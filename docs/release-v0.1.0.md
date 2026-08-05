# SHELLHOUND 0.1.0

First public release.

Local DFIR workbench for compromised web servers (WordPress, Joomla). A copy
of the webroot, the access logs and a database export are indexed once;
after that every analysis is a database query. Runs entirely offline on the
analysis machine.

## Features

- **Analysis** — access log index (~55,000 lines/s), 33 detection rules
  across webroot, database export and logs, CMS inventory with version
  detection, comparison against a clean reference copy
- **Triage** at artifact level rather than per finding, with propagation onto
  clients that loaded a confirmed file according to the log
- **Chronology** of the confirmed artifacts from measured times, with the
  source named per line and gaps stated
- **Trace** of any number of clients with filter, sorting and a timeline
- **Pattern hunt** with a pattern library shared across cases
- **IOC box** with relationships between indicators, export as CSV, JSON and
  STIX 2.1
- **Country attribution** for IP addresses from a local GeoIP database

Detection rules are documented in [`docs/rules.md`](rules.md) with their
trigger, statement and limits.

## Installation

```bash
git clone https://github.com/Mateodevv/shellhound.git
cd shellhound
pip install -r requirements.txt
cd web && npm ci && npm run build && cd ..
python -m server.main
```

Requirements: Python ≥ 3.10, Node ≥ 20. A sample case to try things out is
available via `python tools/sample_case.py`.

## Notes

- A single-seat tool without user accounts and without TLS. For access from
  another machine an SSH tunnel is the intended route. See
  [SECURITY.md](../SECURITY.md).
- The only outbound network access is the optional download of the GeoIP
  country database after an explicit confirmation; no case data is
  transmitted.
- Interface and documentation are in German in this release.

## Known limitations

- Tailored to WordPress and Joomla. Other CMS are read, but without an
  inventory and without CMS-specific rules.
- No report generator; the chronology, IOCs and reasoning are there, the
  writing up is manual.
- Indicators are bound to a case. Comparison across several cases is not
  included.
- CI covers Linux and Windows. macOS is untested.

## License

[Apache-2.0](../LICENSE). Third-party components: [NOTICE](../NOTICE).
