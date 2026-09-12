"""Read historical provider results. External enrichment now belongs to OpenCTI."""
import json

from server import db


class EnrichError(Exception):
    pass


def lookup(workspace, case_dir, service, value, refresh=False):
    """A compatibility refusal for callers of the retired direct lookup API."""
    raise EnrichError("Direct provider lookup is retired. Use OpenCTI enrichment.")


def all_for(conn, values):
    """Historical cache only; no outgoing requests, key access or triage changes."""
    values = [str(v).strip() for v in values if str(v or "").strip()]
    out = {}
    for i in range(0, len(values), 400):
        chunk = values[i:i + 400]
        marks = ",".join("?" * len(chunk))
        for row in db.rows(conn, f"SELECT service,value,fetched,payload FROM enrichment "
                                f"WHERE value IN ({marks})", chunk):
            try:
                result = json.loads(row["payload"] or "{}")
            except ValueError:
                result = {}
            out.setdefault(row["value"], {})[row["service"]] = {
                "fetched": row["fetched"], "result": result}
    return out
