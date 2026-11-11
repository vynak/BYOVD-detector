"""Command line interface.

    byovd scan sysmon-drivers.jsonl
    byovd scan logs/ --json --blocklist hashes.txt
    byovd rules
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .events import iter_events
from .report import render_json, render_text
from .rules import RULES, Context, Severity, load_blocklist, load_vulnerable_names, scan

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="byovd",
        description="Find vulnerable-driver abuse in Sysmon driver-load telemetry.",
    )
    parser.add_argument("--version", action="version", version=f"byovd-detector {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan_parser = subcommands.add_parser("scan", help="scan exported Sysmon events")
    scan_parser.add_argument("paths", nargs="+", type=Path, help="JSON or JSON Lines export")
    scan_parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    scan_parser.add_argument(
        "--min-severity",
        choices=[severity.value for severity in Severity],
        default=Severity.LOW.value,
        help="only report findings at or above this severity (default: low)",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["none", *(severity.value for severity in Severity)],
        default=Severity.HIGH.value,
        help="exit 1 when a finding reaches this severity (default: high)",
    )
    scan_parser.add_argument(
        "--blocklist",
        type=Path,
        help="file with SHA-256 hashes, one per line",
    )
    scan_parser.add_argument(
        "--names",
        type=Path,
        help="file with vulnerable driver names, one per line (replaces the built-in list)",
    )
    scan_parser.add_argument(
        "--no-names",
        action="store_true",
        help="disable the built-in vulnerable driver name list",
    )
    scan_parser.set_defaults(handler=_scan)

    rules_parser = subcommands.add_parser("rules", help="describe the detection rules")
    rules_parser.set_defaults(handler=_rules)

    return parser


def _collect(paths: Sequence[Path]) -> tuple[list, list[str]]:
    events = []
    for path in paths:
        if path.is_dir():
            files = sorted(path.rglob("*.jsonl")) + sorted(path.rglob("*.json"))
        else:
            files = [path]
        for file in files:
            if not file.is_file():
                raise FileNotFoundError(file)
            events.extend(iter_events(file))
    return events, [str(path) for path in paths]


def _scan(args: argparse.Namespace) -> int:
    try:
        events, files = _collect(args.paths)
    except FileNotFoundError as exc:
        print(f"byovd: no such file: {exc.args[0]}", file=sys.stderr)
        return EXIT_ERROR

    names = frozenset()
    if not args.no_names:
        try:
            names = load_vulnerable_names(args.names)
        except OSError as exc:
            print(f"byovd: cannot read names file: {exc}", file=sys.stderr)
            return EXIT_ERROR

    blocklist = frozenset()
    if args.blocklist:
        try:
            blocklist = load_blocklist(args.blocklist)
        except OSError as exc:
            print(f"byovd: cannot read blocklist: {exc}", file=sys.stderr)
            return EXIT_ERROR

    context = Context(blocklist=blocklist, vulnerable_names=names)
    minimum = Severity(args.min_severity)
    findings = list(scan(events, context, minimum))
    # Worst first, then newest first: the top of the output is what to look at.
    findings.sort(
        key=lambda finding: (
            finding.severity.rank,
            finding.event.timestamp.timestamp() if finding.event.timestamp else 0,
        ),
        reverse=True,
    )

    if args.json:
        render_json(findings, len(events), files, sys.stdout)
    else:
        render_text(findings, len(events), files, minimum, sys.stdout)

    if args.fail_on == "none":
        return EXIT_OK
    threshold = Severity(args.fail_on)
    return EXIT_FINDINGS if any(f.severity.rank >= threshold.rank for f in findings) else EXIT_OK


def _rules(args: argparse.Namespace) -> int:
    width = max(len(rule.id) for rule in RULES)
    for rule in RULES:
        print(f"{rule.id:<{width}}  {rule.technique:<10}  {rule.title}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
