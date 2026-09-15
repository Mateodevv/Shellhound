"""Explicit, report-only reputation lookups when OpenCTI is not configured."""
import base64
import ipaddress
import json
import math
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from server import db, settings, diagnostics


class EnrichError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _get(url, headers):
    """Fixed HTTPS providers, no credential-forwarding redirects, bounded JSON."""
    request = urllib.request.Request(url, headers={**headers, "Accept": "application/json"}, method="GET")
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=25) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise EnrichError("Provider response is too large", 502)
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code == 404:
            return None
        if exc.code in (401, 403):
            raise EnrichError("Provider rejected the API key or this account cannot access the report. Check Settings.", 403) from None
        if exc.code == 429:
            raise EnrichError("Provider rate limit reached. Wait before trying again.", 429) from None
        raise EnrichError("Provider request failed. Please try again later.", 502) from None
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError):
        raise EnrichError("Provider could not be reached. Check the connection and try again.", 502) from None
    except (ValueError, UnicodeError):
        raise EnrichError("Provider returned an invalid report.", 502) from None


def _identity(value, kind):
    if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 32 for c in value):
        raise EnrichError("Invalid observable value")
    value = value.strip()
    if kind == 'file':
        kind = 'hash'
    if not kind:
        if re.fullmatch(r'[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', value):
            kind = 'hash'
        else:
            try:
                ipaddress.ip_address(value)
                kind = 'ip'
            except ValueError:
                kind = 'url' if '://' in value else 'domain'
    if kind == 'hash' and re.fullmatch(r'[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', value):
        return value.lower(), kind
    if kind == 'ip':
        try:
            return str(ipaddress.ip_address(value)), kind
        except ValueError:
            pass
    if kind == 'domain':
        try:
            name = value.rstrip('.').encode('idna').decode('ascii').lower()
            if len(name) <= 253 and '.' in name and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in name.split('.')):
                return name, kind
        except UnicodeError:
            pass
    if kind == 'url':
        try:
            parsed = urllib.parse.urlsplit(value)
            if parsed.scheme in ('https', 'http') and parsed.hostname and not parsed.username and not parsed.password and not any(c.isspace() for c in value):
                _ = parsed.port
                return value, kind
        except ValueError:
            pass
    raise EnrichError("This value is not a supported hash, IP, domain or URL")


def _number(value):
    return value if type(value) in (int, float) and math.isfinite(value) else None


def _text(value):
    return value[:2000] if isinstance(value, str) else None


def _timestamp(value):
    value = _number(value)
    return value if value is not None and 0 <= value <= 253402300799 else None


def _vt(value, kind, key):
    identifier = base64.urlsafe_b64encode(value.encode()).decode().rstrip('=') if kind == 'url' else value
    endpoint = {'hash': 'files', 'ip': 'ip_addresses', 'domain': 'domains', 'url': 'urls'}[kind]
    body = _get('https://www.virustotal.com/api/v3/' + endpoint + '/' + urllib.parse.quote(identifier, safe=''), {'x-apikey': key})
    public_kind = {'hash': 'file', 'ip': 'ip-address', 'domain': 'domain', 'url': 'url'}[kind]
    permalink = 'https://www.virustotal.com/gui/' + public_kind + '/' + urllib.parse.quote(identifier, safe='')
    if body is None:
        return {'known': False, **({'permalink': permalink} if kind != 'url' else {})}
    data = body.get('data')
    attributes = data.get('attributes') if isinstance(data, dict) else None
    if not isinstance(attributes, dict):
        raise EnrichError('VirusTotal returned an incomplete report.', 502)
    if kind == 'url':
        report_id = str(data.get('id') or '')
        permalink = 'https://www.virustotal.com/gui/url/' + report_id if re.fullmatch(r'[a-fA-F0-9]{64}', report_id) else ''
    stats = attributes.get('last_analysis_stats') or {}
    if not isinstance(stats, dict):
        stats = {}
    stats = {k: v for k, v in stats.items() if type(v) is int and v >= 0}
    results = attributes.get('last_analysis_results') or {}
    engines = [{'name': str(name), 'category': str(item.get('category') or ''), 'result': str(item.get('result') or '')}
               for name, item in results.items() if isinstance(item, dict)][:200] if isinstance(results, dict) else []
    tags = attributes.get('tags') or []
    names = attributes.get('names') or []
    return {'known': True, 'score': stats.get('malicious'), 'of': sum(stats.values()) if stats else None,
            'suspicious': stats.get('suspicious'), 'stats': stats, 'engines': engines,
            'reputation': _number(attributes.get('reputation')), 'last_analysis': _timestamp(attributes.get('last_analysis_date')),
            'names': [v for v in names[:20] if isinstance(v, str)] if isinstance(names, list) else [],
            'tags': [v for v in tags[:50] if isinstance(v, str)] if isinstance(tags, list) else [],
            'country': _text(attributes.get('country')), 'isp': _text(attributes.get('as_owner')), 'permalink': permalink}


def _abuse(value, key):
    body = _get('https://api.abuseipdb.com/api/v2/check?' + urllib.parse.urlencode({'ipAddress': value, 'maxAgeInDays': 90}), {'Key': key})
    data = body.get('data') if isinstance(body, dict) else None
    if not isinstance(data, dict):
        raise EnrichError('AbuseIPDB returned an incomplete report.', 502)
    return {'known': True, 'score': _number(data.get('abuseConfidenceScore')), 'of': 100,
            'reports': _number(data.get('totalReports')), 'distinct_reporters': _number(data.get('numDistinctUsers')),
            'country': _text(data.get('countryCode')), 'isp': _text(data.get('isp')), 'usage': _text(data.get('usageType')),
            'tor': data.get('isTor') is True, 'last_reported': _text(data.get('lastReportedAt')), 'window_days': 90,
            'permalink': 'https://www.abuseipdb.com/check/' + urllib.parse.quote(value, safe='')}


def lookup(workspace, case_dir, service, value, refresh=False, *, kind=''):
    if settings.opencti_public(workspace)['configured']:
        raise EnrichError('OpenCTI is configured. Use OpenCTI enrichment.', 409)
    if service not in settings.SERVICES:
        raise EnrichError('Unknown enrichment provider')
    value, kind = _identity(value, kind)
    if service == 'abuseipdb' and kind != 'ip':
        raise EnrichError('AbuseIPDB supports IP addresses only')
    key = settings.for_service(workspace, service)
    if not key:
        raise EnrichError('Configure this provider API key in Settings first')
    conn = db.connect(case_dir)
    try:
        row = conn.execute('SELECT fetched,payload FROM enrichment WHERE service=? AND value=?', (service, value)).fetchone()
        if row and not refresh:
            try:
                return {'service': service, 'value': value, 'kind': kind, 'fetched': row['fetched'], 'result': json.loads(row['payload']), 'cached': True}
            except ValueError:
                pass
    finally:
        conn.close()
    try:
        result = _vt(value, kind, key) if service == 'virustotal' else _abuse(value, key)
    except EnrichError as exc:
        diagnostics.record(workspace, 'warning', 'enrichment', str(exc), service=service, kind=kind, target=diagnostics.fingerprint(value), status=exc.status)
        raise
    diagnostics.record(workspace, 'info', 'enrichment', 'Provider report retrieved', service=service, kind=kind, target=diagnostics.fingerprint(value))
    fetched = datetime.now(timezone.utc).isoformat(timespec='seconds')
    conn = db.connect(case_dir)
    try:
        conn.execute('INSERT INTO enrichment(service,value,kind,fetched,payload) VALUES(?,?,?,?,?) ON CONFLICT(service,value) DO UPDATE SET kind=excluded.kind,fetched=excluded.fetched,payload=excluded.payload', (service,value,kind,fetched,json.dumps(result)))
        conn.commit()
    finally:
        conn.close()
    return {'service': service, 'value': value, 'kind': kind, 'fetched': fetched, 'result': result, 'cached': False}


def all_for(conn, values):
    """Stored results only; never triggers a provider request."""
    values = [str(v).strip() for v in values if str(v or '').strip()]
    out = {}
    for i in range(0, len(values), 400):
        chunk = values[i:i + 400]
        marks = ','.join('?' * len(chunk))
        for row in db.rows(conn, f'SELECT service,value,fetched,payload FROM enrichment WHERE value IN ({marks})', chunk):
            try:
                result = json.loads(row['payload'] or '{}')
            except ValueError:
                result = {}
            out.setdefault(row['value'], {})[row['service']] = {'fetched': row['fetched'], 'result': result}
    return out
