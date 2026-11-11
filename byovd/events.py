"""Turn exported Sysmon events into a single, predictable shape.

The detector does not talk to Windows: it reads what a sensor already wrote.
Two exports are supported out of the box, because they cover most real setups:

* flat JSON objects, one per line (``Get-WinEvent`` piped through
  ``ConvertTo-Json -Compress``, or a small script of your own);
* Winlogbeat / Elastic JSON, where the event lives under ``winlog``.

Nothing here imports a third-party package: a SOC laptop with Python can run it.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DRIVER_LOADED_EVENT_ID = 6


@dataclass(frozen=True)
class DriverLoad:
    """One driver-load event, normalized."""

    image: str
    timestamp: datetime | None = None
    hashes: dict[str, str] | None = None
    signed: bool | None = None
    signature: str = ""
    signature_status: str = ""
    company: str = ""
    description: str = ""
    original_name: str = ""
    source: str = ""

    @property
    def basename(self) -> str:
        return self.image.replace("/", "\\").rsplit("\\", 1)[-1]

    @property
    def basename_lower(self) -> str:
        return self.basename.lower()

    @property
    def directory(self) -> str:
        normalized = self.image.replace("/", "\\")
        return normalized.rsplit("\\", 1)[0] if "\\" in normalized else ""

    @property
    def image_lower(self) -> str:
        return self.image.lower()

    @property
    def hashes_lower(self) -> dict[str, str]:
        return self.hashes or {}


def parse_hashes(raw: str) -> dict[str, str]:
    """``"SHA1=aa,SHA256=bb"`` -> ``{"sha1": "aa", "sha256": "bb"}``."""
    result: dict[str, str] = {}
    for chunk in (raw or "").split(","):
        algo, _, value = chunk.partition("=")
        algo, value = algo.strip().lower(), value.strip().lower()
        if algo and value:
            result[algo] = value
    return result


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    return None


def _as_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _lookup(data: dict[str, Any], *names: str) -> Any:
    """Case-insensitive lookup across the aliases a sensor may use."""
    lowered = {str(key).lower(): value for key, value in data.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _event_data(obj: dict[str, Any]) -> tuple[dict[str, Any], Any]:
    """Return ``(fields, event_id)`` for the export shapes we accept."""
    winlog = obj.get("winlog")
    if isinstance(winlog, dict):
        data = winlog.get("event_data") or {}
        if isinstance(data, dict):
            return data, winlog.get("event_id")

    event = obj.get("Event")
    if isinstance(event, dict):
        system = event.get("System") or {}
        data = event.get("EventData") or {}
        return (data if isinstance(data, dict) else {}), system.get("EventID")

    event_data = obj.get("EventData")
    if isinstance(event_data, dict):
        return event_data, obj.get("EventID", obj.get("event_id"))

    return obj, obj.get("EventID", obj.get("event_id", obj.get("Id")))


def parse_event(obj: Any, source: str = "") -> DriverLoad | None:
    """Build a :class:`DriverLoad`, or ``None`` if this is not a driver load."""
    if not isinstance(obj, dict):
        return None

    fields, event_id = _event_data(obj)
    if event_id is not None:
        try:
            if int(event_id) != DRIVER_LOADED_EVENT_ID:
                return None
        except (TypeError, ValueError):
            pass  # an unknown id format is not a reason to drop the record

    image = _lookup(fields, "ImageLoaded", "Image", "image_loaded", "FilePath")
    if not isinstance(image, str) or not image.strip():
        return None

    hashes = parse_hashes(str(_lookup(fields, "Hashes", "hashes") or ""))

    return DriverLoad(
        image=image.strip(),
        timestamp=_as_time(_lookup(obj, "TimeCreated", "UtcTime", "timestamp", "@timestamp")),
        hashes=hashes,
        signed=_as_bool(_lookup(fields, "Signed", "signed")),
        signature=str(_lookup(fields, "Signature", "signature") or ""),
        signature_status=str(_lookup(fields, "SignatureStatus", "signature_status") or ""),
        company=str(_lookup(fields, "Company", "company") or ""),
        description=str(_lookup(fields, "Description", "description") or ""),
        original_name=str(_lookup(fields, "OriginalFileName", "original_file_name") or ""),
        source=source,
    )


def _iter_objects(path: Path) -> Iterator[Any]:
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        yield from payload if isinstance(payload, list) else [payload]
        return

    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue  # a truncated line should not abort the whole scan


def iter_events(path: Path) -> Iterator[DriverLoad]:
    """Yield driver-load events from ``path`` (``.json`` array or JSON Lines)."""
    for obj in _iter_objects(path):
        event = parse_event(obj, source=str(path))
        if event is not None:
            yield event
