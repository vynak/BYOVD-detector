from datetime import timezone

from byovd.events import DriverLoad, iter_events, parse_event, parse_hashes


def test_parse_hashes_lowercases_keys_and_values():
    assert parse_hashes("SHA1=AA,SHA256=BB") == {"sha1": "aa", "sha256": "bb"}


def test_parse_hashes_ignores_empty_chunks():
    assert parse_hashes("") == {}
    assert parse_hashes("SHA256=") == {}


def test_parse_flat_event():
    event = parse_event(
        {
            "EventID": 6,
            "UtcTime": "2026-11-11T12:00:00.000Z",
            "ImageLoaded": "C:\\Windows\\System32\\drivers\\disk.sys",
            "Hashes": "SHA256=abc",
            "Signed": True,
            "SignatureStatus": "Valid",
        }
    )

    assert event is not None
    assert event.basename == "disk.sys"
    assert event.directory == "C:\\Windows\\System32\\drivers"
    assert event.hashes == {"sha256": "abc"}
    assert event.signed is True
    assert event.timestamp is not None
    assert event.timestamp.tzinfo == timezone.utc


def test_parse_winlogbeat_event():
    event = parse_event(
        {
            "winlog": {
                "event_id": "6",
                "event_data": {"ImageLoaded": "C:\\Temp\\a.sys", "SignatureStatus": "Unsigned"},
            },
            "@timestamp": "2026-11-11T12:00:00Z",
        }
    )

    assert event is not None
    assert event.image == "C:\\Temp\\a.sys"
    assert event.signature_status == "Unsigned"


def test_ignores_other_event_ids():
    record = {"EventID": 1, "ImageLoaded": "C:\\Windows\\System32\\drivers\\disk.sys"}

    assert parse_event(record) is None


def test_ignores_records_without_an_image():
    assert parse_event({"EventID": 6}) is None


def test_keeps_records_without_an_event_id():
    event = parse_event({"ImageLoaded": "C:\\Windows\\System32\\drivers\\disk.sys"})

    assert event is not None


def test_path_separators_are_normalized_for_lookup():
    event = DriverLoad(image="C:/Users/sab/AppData/Local/Temp/x.sys")

    assert event.basename == "x.sys"
    assert event.image_lower.startswith("c:/users/")


def test_iter_events_reads_json_lines(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"EventID": 6, "ImageLoaded": "C:\\\\a.sys"}\n'
        "not json\n"
        "\n"
        '{"EventID": 1, "ImageLoaded": "C:\\\\b.sys"}\n',
        encoding="utf-8",
    )

    events = list(iter_events(path))

    assert len(events) == 1
    assert events[0].basename == "a.sys"


def test_iter_events_reads_a_json_array(tmp_path):
    path = tmp_path / "events.json"
    path.write_text('[{"EventID": 6, "ImageLoaded": "C:\\\\a.sys"}]', encoding="utf-8")

    events = list(iter_events(path))

    assert [event.basename for event in events] == ["a.sys"]


def test_iter_events_accepts_a_utf8_bom(tmp_path):
    # Windows PowerShell writes a BOM with `Set-Content -Encoding utf8`.
    path = tmp_path / "events.jsonl"
    path.write_text('{"EventID": 6, "ImageLoaded": "C:\\\\a.sys"}\n', encoding="utf-8-sig")

    events = list(iter_events(path))

    assert len(events) == 1
