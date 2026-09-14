# Report and cross-case IOC design

## Requirements

- Export one printable, self-contained HTML file without network requests.
- Carry measured facts, analyst decisions, chronology, IOC relationships and
  explicit gaps. Selected log observations may include a bounded, escaped and
  credential-redacted excerpt; full source files are never embedded.
- Compare indicators across open cases without weakening case isolation or
  creating another database that can become stale.

## Data flow

```text
case.db + derived log index ──read──> case_report.py ──> HTML download

current case IOC box ─┐
other case IOC boxes ─┴─read-only──> correlation.py ──> API + report section
```

The English report passes the current time reading to the same
chronology and coverage functions used by the dashboard. The report therefore
cannot silently describe a different timeline from the one on screen.

## API contracts

- `GET /api/cases/{slug}/report.html` returns an attachment and its SHA-256 in
  `X-Content-SHA256`.
- `GET /api/cases/{slug}/iocs/cross-case` returns only matching IOC-box rows,
  case names/references and aggregate scan counts. It returns no case paths,
  findings, raw logs, accounts or evidence.

## Storage and scale

There is no new storage. Cross-case comparison opens each small `case.db` in
SQLite read-only mode and performs conservative equality matching in memory.
This is O(cases × IOCs), which is preferable to synchronisation and retention
problems while workspaces contain tens of cases. Revisit with measurements if
the endpoint becomes slow; a cache must remain derivable and disposable.

## Security boundaries

- Known evidence-root paths are redacted from every report field.
- File artifacts and path IOCs are rendered relative to their evidence root.
- HTML escaping is applied at the final render boundary and a restrictive CSP
  permits only the embedded stylesheet.
- Cross-case reads only explicit IOC-box membership. A raw finding never
  becomes a workspace-wide assertion merely because a rule fired.

## Trade-offs and later work

Evidence-source hashes are not stored by the current schema, so the report
states that limitation instead of inventing one or re-reading terabytes during
a click. If acquisition hashes are added later, store them when evidence is
registered or scanned and include the algorithm and acquisition time.

## Additional log evidence

Confirmed log observations appear with their source name and original line
location. Their saved excerpts survive source removal and case archiving.
Current, reliably dated confirmed observations can contribute to chronology;
undated or stale evidence cannot become an automatic first-sign anchor. A
scanner detection date describes discovery, not the start of an infection.

See [log evidence](log-evidence.md) for format and timestamp limitations.
