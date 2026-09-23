"""Explicit public CVE record lookup. No case data is sent to the provider."""
import json
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_record(value):
    cve = value.strip().upper()
    if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", cve):
        raise ValueError("Invalid CVE identifier.")
    url = "https://cveawg.mitre.org/api/cve/" + cve
    try:
        request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Shellhound"})
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("CVE response is too large.")
        record = json.loads(raw)
        if record.get("cveMetadata", {}).get("cveId") != cve:
            raise ValueError("CVE source returned a different record.")
        return {"record": record, "source": url, "fetched_at": datetime.now(timezone.utc).isoformat()}
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ValueError("No public record is available for this CVE.") from None
        raise ValueError("Public CVE source is currently unavailable.") from None
    except (OSError, json.JSONDecodeError, AttributeError):
        raise ValueError("Could not load a valid public CVE record.") from None
