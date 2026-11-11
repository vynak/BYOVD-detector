from byovd.events import DriverLoad
from byovd.rules import (
    RULES,
    Context,
    Severity,
    evaluate,
    load_blocklist,
    load_vulnerable_names,
    scan,
)

CLEAN = "C:\\Windows\\System32\\drivers\\disk.sys"


def make(**overrides) -> DriverLoad:
    defaults = {
        "image": CLEAN,
        "hashes": {},
        "signed": True,
        "signature": "Microsoft Windows",
        "signature_status": "Valid",
        "company": "Microsoft Corporation",
    }
    defaults.update(overrides)
    return DriverLoad(**defaults)


def rules_hit(event: DriverLoad, context: Context | None = None) -> set[str]:
    return {finding.rule_id for finding in evaluate(event, context or Context())}


def test_unsigned_driver_is_high():
    findings = evaluate(make(signed=False, signature_status="Unsigned"), Context())

    assert findings[0].rule_id == "BYOVD-001"
    assert findings[0].severity is Severity.HIGH


def test_valid_signature_is_not_flagged_for_signature():
    assert "BYOVD-001" not in rules_hit(make())


def test_expired_signature_is_medium():
    findings = evaluate(make(signature_status="Expired"), Context())

    assert findings[0].severity is Severity.MEDIUM


def test_unknown_signature_data_is_not_a_finding():
    assert "BYOVD-001" not in rules_hit(make(signed=None, signature_status=""))


def test_temp_path_is_medium_when_signed():
    findings = evaluate(make(image="C:\\Users\\sab\\AppData\\Local\\Temp\\x.sys"), Context())

    rule = next(finding for finding in findings if finding.rule_id == "BYOVD-002")
    assert rule.severity is Severity.MEDIUM


def test_temp_path_escalates_when_unsigned():
    findings = evaluate(
        make(image="C:\\Users\\sab\\AppData\\Local\\Temp\\x.sys", signed=False), Context()
    )

    rule = next(finding for finding in findings if finding.rule_id == "BYOVD-002")
    assert rule.severity is Severity.HIGH


def test_system_driver_directory_is_not_user_writable():
    assert "BYOVD-002" not in rules_hit(make())


def test_blocklist_match_is_critical():
    context = Context(blocklist=frozenset({"abc123"}))
    findings = evaluate(make(hashes={"sha256": "abc123"}), context)

    rule = next(finding for finding in findings if finding.rule_id == "BYOVD-003")
    assert rule.severity is Severity.CRITICAL


def test_empty_blocklist_matches_nothing():
    assert "BYOVD-003" not in rules_hit(make(hashes={"sha256": "abc123"}))


def test_known_name_is_high():
    context = Context(vulnerable_names=frozenset({"rtcore64.sys"}))
    findings = evaluate(make(image="C:\\Windows\\System32\\drivers\\RTCore64.sys"), context)

    rule = next(finding for finding in findings if finding.rule_id == "BYOVD-004")
    assert rule.severity is Severity.HIGH


def test_generated_hex_name_is_low():
    findings = evaluate(make(image="C:\\ProgramData\\1a2b3c4d.sys"), Context())

    rule = next(finding for finding in findings if finding.rule_id == "BYOVD-005")
    assert rule.severity is Severity.LOW


def test_generated_name_ignored_inside_system_drivers():
    assert "BYOVD-005" not in rules_hit(make(image="C:\\Windows\\System32\\drivers\\1a2b3c4d.sys"))


def test_clean_event_has_no_findings():
    assert evaluate(make(), Context()) == []


def test_findings_are_sorted_worst_first():
    context = Context(blocklist=frozenset({"abc"}))
    findings = evaluate(
        make(image="C:\\Users\\sab\\Temp\\x.sys", signed=False, hashes={"sha256": "abc"}),
        context,
    )

    severities = [finding.severity.rank for finding in findings]
    assert severities == sorted(severities, reverse=True)


def test_scan_filters_by_minimum_severity():
    event = make(image="C:\\ProgramData\\1a2b3c4d.sys")

    everything = list(scan([event], Context(), Severity.LOW))
    only_high = list(scan([event], Context(), Severity.HIGH))

    assert everything and not only_high


def test_load_names_skips_comments_and_blanks(tmp_path):
    path = tmp_path / "names.txt"
    path.write_text("# comment\n\nfoo.sys\n  bar.sys  # trailing\n", encoding="utf-8")

    assert load_vulnerable_names(path) == frozenset({"foo.sys", "bar.sys"})


def test_load_blocklist_skips_comments(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_text("# header\nABC\n", encoding="utf-8")

    assert load_blocklist(path) == frozenset({"abc"})


def test_builtin_names_are_shipped():
    names = load_vulnerable_names()

    assert "rtcore64.sys" in names
    assert len(RULES) == 5
