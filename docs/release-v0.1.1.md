# SHELLHOUND 0.1.1

Patch release. **Recommended for everyone running 0.1.0.**

## Fixed — `database is locked` during a running analysis

Opening a database connection performed a write before the caller had asked
for anything: `connect()` created the schema unconditionally and applied two
data corrections. Since `connect()` runs on every request, even a read-only
request — such as the job list the interface polls once per second while an
analysis runs — began with a write transaction.

Meeting the write lock held by the working engine, that transaction failed
with `sqlite3.OperationalError: database is locked`, surfacing as a
traceback in the server console and a failed request in the interface.

Aggravating factor: the transaction stayed open, because the corrections
ran without a commit. Every read request therefore held a write lock for
its whole lifetime, so two concurrent reads could block each other even
with no job running.

**No data was lost or corrupted by this** — SQLite aborts the transaction
cleanly. The impact was on usability: views failing to load, and a tool
throwing stack traces in the middle of evidence work. Longer analyses were
affected more, because the window in which it could occur was longer.

### What changed

- The case schema now carries a version number (`schema_version` in
  `meta`). A write happens only when it differs: **once per case instead of
  once per request**. The normal path is read-only and collides with
  nothing.
- `PRAGMA busy_timeout` is set explicitly, so a held lock is waited for
  rather than given up on immediately.
- The journal mode is only switched when the file is not already in WAL —
  the switch briefly requires exclusive access, reading the mode does not.
- If the upgrade does hit a lock, it counts as **maintenance** and is
  deferred; the running read request is not dragged down with it. On a
  still-empty file it must succeed, and the error is propagated.

Existing cases need nothing: they sit at version 0, get upgraded once on
the next open, and are stamped afterwards.

## Upgrading

```bash
git pull
pip install -r requirements.txt
cd web && npm ci && npm run build && cd ..
python -m server.main
```

No case migration is required, and cases created with 0.1.0 open unchanged.

## Licence

[Apache-2.0](../LICENSE). Third-party components: [NOTICE](../NOTICE).
