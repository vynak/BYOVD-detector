import json
from pathlib import Path

from byovd.cli import main

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "sample-events.jsonl"
BLOCKLIST = ROOT / "examples" / "blocklist.txt"


def test_scan_reports_high_issues_and_exits_1(capsys):
    code = main(["scan", str(SAMPLE)])
    out = capsys.readouterr().out

    assert code == 1
    assert "BYOVD-002" in out
    assert "RTCore64.sys" in out


def test_scan_json_output(capsys):
    main(["scan", str(SAMPLE), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["tool"] == "byovd-detector"
    assert payload["events"] == 6
    assert any(finding["severity"] == "high" for finding in payload["findings"])


def test_min_severity_critical_without_blocklist_is_clean(capsys):
    code = main(["scan", str(SAMPLE), "--min-severity", "critical"])
    out = capsys.readouterr().out

    assert code == 0
    assert "no findings" in out


def test_blocklist_produces_a_critical_finding(capsys):
    code = main(["scan", str(SAMPLE), "--blocklist", str(BLOCKLIST), "--fail-on", "critical"])
    out = capsys.readouterr().out

    assert code == 1
    assert "BYOVD-003" in out


def test_fail_on_none_always_exits_zero(capsys):
    assert main(["scan", str(SAMPLE), "--fail-on", "none"]) == 0


def test_no_names_disables_the_name_rule(capsys):
    main(["scan", str(SAMPLE), "--no-names", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert all(finding["rule_id"] != "BYOVD-004" for finding in payload["findings"])


def test_missing_file_exits_2(capsys):
    code = main(["scan", "does-not-exist.jsonl"])

    assert code == 2
    assert "no such file" in capsys.readouterr().err


def test_rules_command_lists_every_rule(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out

    assert "BYOVD-001" in out
    assert "BYOVD-005" in out


def test_directory_is_scanned_recursively(capsys, tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "events.jsonl").write_text(
        '{"EventID": 6, "ImageLoaded": "C:\\\\Users\\\\sab\\\\Temp\\\\x.sys", '
        '"Signed": false, "SignatureStatus": "Unsigned"}\n',
        encoding="utf-8",
    )

    code = main(["scan", str(tmp_path)])

    assert code == 1
    assert "x.sys" in capsys.readouterr().out
