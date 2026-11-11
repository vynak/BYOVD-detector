"""Text and JSON output. Kept away from the rules so both stay simple."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import timezone
from typing import TextIO

from . import __version__
from .rules import Finding, Severity

SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


def _when(finding: Finding) -> str:
    stamp = finding.event.timestamp
    if stamp is None:
        return "unknown"
    return stamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _digest(finding: Finding) -> str:
    hashes = finding.event.hashes_lower
    for algorithm in ("sha256", "sha1", "md5"):
        if hashes.get(algorithm):
            return f"{algorithm} {hashes[algorithm]}"
    return "not provided"


def _summary_line(counts: Counter[Severity]) -> str:
    parts = [
        f"{counts[severity]} {severity.value}"
        for severity in SEVERITY_ORDER
        if counts[severity]
    ]
    return ", ".join(parts) if parts else "none"


def _signature_line(finding: Finding) -> str:
    event = finding.event
    status = event.signature_status or "unknown"
    if event.signed is False:
        return f"no ({status})"
    publisher = event.company or event.signature
    if event.signed is True:
        return f"yes, {publisher or 'unknown publisher'} ({status})"
    return f"unknown ({status})"


def render_text(
    findings: Sequence[Finding],
    events: int,
    files: Sequence[str],
    minimum: Severity,
    stream: TextIO,
) -> None:
    stream.write(f"byovd-detector {__version__}\n")
    stream.write(f"scanned {events} driver-load events from {len(files)} file(s)\n")

    if not findings:
        stream.write(f"no findings at or above '{minimum.value}'\n")
        return

    counts = Counter(finding.severity for finding in findings)
    stream.write(f"{len(findings)} finding(s): {_summary_line(counts)}\n")

    for finding in findings:
        stream.write("\n")
        stream.write(
            f"[{finding.severity.value}] {finding.rule_id}  {finding.title}  "
            f"({finding.technique})\n"
        )
        stream.write(f"  time    {_when(finding)}\n")
        stream.write(f"  image   {finding.event.image}\n")
        stream.write(f"  hash    {_digest(finding)}\n")
        stream.write(f"  signed  {_signature_line(finding)}\n")
        stream.write(f"  detail  {finding.detail}\n")

    stream.write(f"\nsummary: {_summary_line(counts)}\n")


def render_json(
    findings: Iterable[Finding],
    events: int,
    files: Sequence[str],
    stream: TextIO,
) -> None:
    payload = {
        "tool": "byovd-detector",
        "version": __version__,
        "events": events,
        "files": list(files),
        "findings": [
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "technique": finding.technique,
                "detail": finding.detail,
                "event": {
                    "image": finding.event.image,
                    "timestamp": finding.event.timestamp.isoformat()
                    if finding.event.timestamp
                    else None,
                    "hashes": finding.event.hashes_lower,
                    "company": finding.event.company,
                    "signature_status": finding.event.signature_status,
                    "source": finding.event.source,
                },
            }
            for finding in findings
        ],
    }
    json.dump(payload, stream, indent=2)
    stream.write("\n")
