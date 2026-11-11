# byovd-detector

Reads the driver-load events of a Sysmon export and tells you which ones look like a **BYOVD** attack.

BYOVD means *bring your own vulnerable driver*: instead of exploiting Windows, the attacker loads a driver that is properly signed but has a flaw, uses it to get kernel-level access, and from there disables the antivirus or reads memory. Signature checks do not stop it, because the driver is signed.

The kernel already logs every driver it loads. This tool asks the right questions of that log.

## What it does

- Reads Sysmon event ID 6 (`DriverLoad`) from a JSON or JSON Lines export.
- Applies five rules that look at behaviour and metadata, not at a threat feed.
- Prints findings worst first, or JSON for a pipeline.
- Exits with a code you can use in CI.

No runtime dependencies: standard library only. Python 3.10 or newer.

## Rules

| Rule | What it looks for | Severity | ATT&CK |
|---|---|---|---|
| BYOVD-001 | Driver is not validly signed (unsigned, invalid, expired) | high | T1553.002 |
| BYOVD-002 | Driver loaded from a directory a normal user can write to | medium, high if unsigned | T1068 |
| BYOVD-003 | SHA-256 of the driver is on your blocklist | critical | T1068 |
| BYOVD-004 | File name matches a documented vulnerable driver | high | T1068 |
| BYOVD-005 | File name looks generated (`1a2b3c4d.sys`, `x9182736.sys`) outside the system directory | low | T1036 |

## Quick start

```bash
python -m byovd scan drivers.jsonl
```

Or install the `byovd` command:

```bash
pip install -e .
byovd scan drivers.jsonl
```

With a blocklist and JSON output:

```bash
byovd scan drivers.jsonl --blocklist hashes.txt --json
```

## Example

Running the sample in [`examples/`](examples) with the example blocklist:

```
byovd-detector 0.1.0
scanned 6 driver-load events from 1 file(s)
8 finding(s): 1 critical, 5 high, 1 medium, 1 low

[critical] BYOVD-003  Driver hash is on the blocklist  (T1068)
  time    2026-11-11 12:00:03Z
  image   C:\Windows\System32\drivers\evil.sys
  hash    sha256 4444...4444
  signed  yes, Example Vendor (Valid)
  detail  sha256 4444...4444 is on the blocklist

[high] BYOVD-001  Driver is not validly signed  (T1553.002)
  time    2026-11-11 12:00:05Z
  image   C:\Users\sab\Desktop\driver.tmp
  hash    sha256 6666...6666
  signed  no (Unsigned)
  detail  signature status: Unsigned; publisher: none

...
summary: 1 critical, 5 high, 1 medium, 1 low
```

The sample is synthetic; the events are made up so the tool has something to chew on.

## Getting the telemetry

Sysmon has to be installed and logging event ID 6. Then export it to JSON Lines from PowerShell:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=6]]" |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = $item.'#text' }
    [pscustomobject]@{
      EventID          = 6
      UtcTime          = $data['UtcTime']
      ImageLoaded      = $data['ImageLoaded']
      Hashes           = $data['Hashes']
      Signed           = $data['Signed']
      Signature        = $data['Signature']
      SignatureStatus  = $data['SignatureStatus']
      Company          = $data['Company']
      Description      = $data['Description']
      OriginalFileName = $data['OriginalFileName']
    } | ConvertTo-Json -Compress
  } | Set-Content -Encoding utf8 drivers.jsonl
```

The reader also accepts Winlogbeat/Elastic documents (fields under `winlog.event_data`) and a plain JSON array.

## Blocklist

`--blocklist` takes one SHA-256 per line, `#` for comments. Use it with the Microsoft vulnerable driver blocklist or [LOLDrivers](https://github.com/magicsword-io/LOLDrivers). A hash is the strongest signal you can have, and the one that ages slowest.

`--names` replaces the built-in list of driver names with your own file. `--no-names` disables that rule completely.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing found at or above `--fail-on` |
| 1 | At least one finding reached `--fail-on` (default: high) |
| 2 | Bad arguments or an unreadable file |

That makes it usable as a step in CI or in a triage script:

```bash
byovd scan drivers.jsonl --min-severity medium --fail-on high
```

## What it does not catch

This is worth being clear about, because the gaps are where attacks live:

- **Hand-mapped drivers.** A loader can map a driver into kernel memory without going through the normal load path; Windows may never raise event 6. The absence of a finding is not proof of a clean machine.
- **Live telemetry.** It reads an export, not a live ETW session. If you need real time, run it on a schedule over fresh exports.
- **Correlation.** It does not yet join a driver load with the service that created it, or with the process that dropped the file.
- **A name list ages.** BYOVD-004 is a starting point, not threat intelligence. The hash rule is the durable one.

## Tests

```bash
pip install pytest ruff
pytest
ruff check .
```

38 tests, no Windows and no sample drivers needed: every rule and parser path is covered with synthetic events. CI runs the suite on Python 3.10 and 3.12.

## Layout

```
byovd/
  events.py    reads JSON/JSONL, normalizes a driver-load event
  rules.py     the five rules, the severity model, list loaders
  report.py    text and JSON output
  cli.py       scan and rules commands
  data/        built-in driver name list
examples/      synthetic events and a sample blocklist
tests/         parser, rules and CLI tests
```

## License

MIT. See [LICENSE](LICENSE).
