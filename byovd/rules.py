"""Rules that turn a driver-load event into a finding.

Each rule is a small function with no I/O and no state: it receives one event
and the scan context, and returns a severity plus a human sentence, or ``None``
when the rule does not apply. That is what makes them cheap to test and safe to
extend — adding a rule never touches the parser or the CLI.

The rules look at behaviour and metadata, not at a threat-intel feed: a path a
user can write to, a signature that is missing, a hash someone already flagged.
A perfect feed still needs someone to ask the right question of the telemetry.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .events import DriverLoad

DATA_DIR = Path(__file__).resolve().parent / "data"
BUILTIN_NAMES = DATA_DIR / "known_vulnerable_drivers.txt"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_at_least(severity: Severity, minimum: Severity) -> bool:
    return severity.rank >= minimum.rank


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    technique: str
    detail: str
    event: DriverLoad


@dataclass(frozen=True)
class Context:
    """Everything a rule may need beyond the event itself."""

    blocklist: frozenset[str] = frozenset()
    vulnerable_names: frozenset[str] = frozenset()


# Paths a standard user can write to. A driver loaded from one of these is the
# most common trace of BYOVD: the loader drops the .sys next to its payload.
USER_WRITABLE = (
    "\\users\\",
    "\\temp\\",
    "\\appdata\\",
    "\\downloads\\",
    "\\programdata\\",
    "\\public\\",
    "\\desktop\\",
    "\\documents\\",
    "\\$recycle.bin\\",
    "\\perflogs\\",
)

SYSTEM_DRIVER_DIRS = ("\\windows\\system32\\drivers\\", "\\windows\\syswow64\\drivers\\")

HEX_NAME = re.compile(r"^[0-9a-f]{6,}$")
SHORT_RANDOM = re.compile(r"^[a-z]{1,3}\d{4,}$")


def _signature_is_bad(event: DriverLoad) -> bool:
    status = (event.signature_status or "").strip().lower()
    if event.signed is False:
        return True
    return status in {"unsigned", "invalid", "error", "not signed", "untrusted"}


def _check_unsigned(event: DriverLoad, context: Context) -> tuple[Severity, str] | None:
    status = (event.signature_status or "").strip()
    if _signature_is_bad(event):
        publisher = event.signature or "none"
        return Severity.HIGH, f"signature status: {status or 'unsigned'}; publisher: {publisher}"
    if status.lower() in {"expired", "unknown"}:
        return Severity.MEDIUM, f"signature status: {status}"
    return None


def _check_user_writable(event: DriverLoad, context: Context) -> tuple[Severity, str] | None:
    image = event.image_lower
    if any(directory in image for directory in SYSTEM_DRIVER_DIRS):
        return None
    hit = next((prefix for prefix in USER_WRITABLE if prefix in image), None)
    if hit is None:
        return None
    severity = Severity.HIGH if _signature_is_bad(event) else Severity.MEDIUM
    return severity, f"loaded from {event.directory or 'a user-writable directory'}"


def _check_blocklist(event: DriverLoad, context: Context) -> tuple[Severity, str] | None:
    if not context.blocklist:
        return None
    for algorithm in ("sha256", "sha1", "md5"):
        digest = event.hashes_lower.get(algorithm)
        if digest and digest in context.blocklist:
            return Severity.CRITICAL, f"{algorithm} {digest} is on the blocklist"
    return None


def _check_known_name(event: DriverLoad, context: Context) -> tuple[Severity, str] | None:
    if event.basename_lower in context.vulnerable_names:
        return Severity.HIGH, f"{event.basename} is a documented vulnerable driver"
    return None


def _check_generated_name(event: DriverLoad, context: Context) -> tuple[Severity, str] | None:
    image = event.image_lower
    if any(directory in image for directory in SYSTEM_DRIVER_DIRS):
        return None
    stem = event.basename_lower.rsplit(".", 1)[0]
    if HEX_NAME.match(stem) or SHORT_RANDOM.match(stem):
        return Severity.LOW, f"file name {event.basename} looks generated"
    return None


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    technique: str
    check: Callable[[DriverLoad, Context], tuple[Severity, str] | None]


RULES: tuple[Rule, ...] = (
    Rule(
        "BYOVD-001",
        "Driver is not validly signed",
        "T1553.002",
        _check_unsigned,
    ),
    Rule(
        "BYOVD-002",
        "Driver loaded from a user-writable directory",
        "T1068",
        _check_user_writable,
    ),
    Rule(
        "BYOVD-003",
        "Driver hash is on the blocklist",
        "T1068",
        _check_blocklist,
    ),
    Rule(
        "BYOVD-004",
        "Driver name is a documented vulnerable driver",
        "T1068",
        _check_known_name,
    ),
    Rule(
        "BYOVD-005",
        "Driver file name looks generated",
        "T1036",
        _check_generated_name,
    ),
)


def evaluate(event: DriverLoad, context: Context, rules: Iterable[Rule] = RULES) -> list[Finding]:
    """Run every rule against one event and return the findings, worst first."""
    findings: list[Finding] = []
    for rule in rules:
        result = rule.check(event, context)
        if result is None:
            continue
        severity, detail = result
        findings.append(Finding(rule.id, rule.title, severity, rule.technique, detail, event))
    findings.sort(key=lambda finding: finding.severity.rank, reverse=True)
    return findings


def scan(
    events: Iterable[DriverLoad],
    context: Context,
    minimum: Severity = Severity.LOW,
    rules: Iterable[Rule] = RULES,
) -> Iterator[Finding]:
    for event in events:
        for finding in evaluate(event, context, rules):
            if severity_at_least(finding.severity, minimum):
                yield finding


def load_vulnerable_names(path: Path | str | None = None) -> frozenset[str]:
    """Read a one-name-per-line file; ``#`` starts a comment."""
    target = Path(path) if path is not None else BUILTIN_NAMES
    if not target.is_file():
        return frozenset()
    names = set()
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            names.add(line)
    return frozenset(names)


def load_blocklist(path: Path | str) -> frozenset[str]:
    """Read SHA-256 hashes, one per line; ``#`` starts a comment."""
    target = Path(path)
    hashes = set()
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            hashes.add(line)
    return frozenset(hashes)
