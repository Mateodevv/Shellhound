# server/engines/accesslog.py
"""Access-log line parsing (ported from legacy core/accesslog.py).

The Combined/Common patterns carry years of real-webhost quirks: vhost
tokens, Plesk trailer fields, escaped quotes in UA/referrer, empty 400/408
requests. They are ported verbatim -- every quirk removed here would silently
drop exactly the attacker lines the index exists to answer about.
"""
import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus

_QF = r'(?:[^"\\]|\\.)*'   # content of one quoted log field
# Apache's vhost_combined format and hosting panels such as Plesk may put the
# virtual-host name before the client address. It used to be discarded; the
# Pattern Hunt rule builder can now deliberately constrain a host, so retain
# it when the log format actually carries it. Absence stays absence -- a file
# name is not evidence of the HTTP Host header.
_VHOST_PREFIX = r'(?:(?P<host>\S+) )?'

LOG_PATTERN = re.compile(
    r'^' + _VHOST_PREFIX + r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?:(?P<method>[A-Z]+) (?P<uri>.*?)(?: HTTP/[\d\.]+)??|(?P<badreq>' + _QF + r'))" '
    r'(?P<status>\d{3}) (?P<size>\d+|-) '
    r'(?:[^"\s]\S* )?'
    r'"(?P<referrer>' + _QF + r')" "(?P<user_agent>' + _QF + r')"'
    r'(?:\s.*)?$'
)

LOG_PATTERN_COMMON = re.compile(
    r'^' + _VHOST_PREFIX + r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<uri>.*?)(?: HTTP/[\d\.]+)??" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)\s*$'
)

ERROR_LOG_SIGNATURES = re.compile(
    r'^(?:'
    r'\[\w{3} \w{3} [ \d]?\d \d{2}:\d{2}:\d{2}'   # Apache: [Fri Jun 26 05:19:59...
    r'|\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \['    # Nginx:  2026/06/30 11:52:26 [error]
    r')')

ERROR_LOG_SKIP_REASON = "Apache/Nginx error log (not an access-log format)"

_W3C_FIELDS_PREFIX = "#fields:"


def is_metadata_line(line):
    """Return whether *line* is an IIS W3C directive/comment.

    W3C metadata is evidence about the file format rather than a request.  It
    must therefore neither be indexed nor inflate the unparsed-line count.
    """
    return line.lstrip("\ufeff").startswith("#")


def _decode_w3c_text(value):
    """Decode W3C's URL-encoded free-text fields without touching request URIs."""
    if not value or value == "-":
        return value or "-"
    return unquote_plus(value)


def parse_w3c_line(line, fields):
    """Parse one IIS W3C data row using its preceding ``#Fields`` schema.

    IIS lets administrators choose and reorder fields, so parsing a row
    without that schema would silently assign the wrong forensic meaning to
    columns.  Request paths and queries intentionally remain encoded exactly
    as logged; only human-readable User-Agent and Referer fields are decoded.
    """
    values = line.strip().split()
    if not fields or len(values) != len(fields):
        return None
    row = dict(zip((field.lower() for field in fields), values))
    required = ("date", "time", "c-ip", "cs-method", "cs-uri-stem",
                "sc-status")
    if any(not row.get(field) or row[field] == "-" for field in required):
        return None

    uri = row["cs-uri-stem"]
    query = row.get("cs-uri-query")
    if query and query != "-":
        uri = f"{uri}?{query}"

    return {
        "ip": row["c-ip"],
        "time": f'{row["date"]} {row["time"]}',
        "method": row["cs-method"],
        "uri": uri,
        "status": row["sc-status"],
        "size": row.get("sc-bytes", "-"),
        "referrer": _decode_w3c_text(row.get("cs(referer)", "-")),
        "user_agent": _decode_w3c_text(row.get("cs(user-agent)", "-")),
        "host": _decode_w3c_text(row.get("cs-host", "-")),
    }


class AccessLogParser:
    """Per-file parser for Apache/Common and stateful IIS W3C logs."""

    def __init__(self):
        self._w3c_fields = None

    def parse(self, line):
        clean = line.lstrip("\ufeff")
        if clean.startswith("#"):
            if clean.lower().startswith(_W3C_FIELDS_PREFIX):
                self._w3c_fields = tuple(
                    clean.split(":", 1)[1].strip().split())
            return None
        if self._w3c_fields is not None:
            return parse_w3c_line(clean, self._w3c_fields)
        return parse_line(clean)


def parse_line(line):
    """Combined-then-Common matcher; None if neither. Malformed requests are
    normalized to method/uri '-' so they never feed the detections."""
    match = LOG_PATTERN.match(line) or LOG_PATTERN_COMMON.match(line)
    if match is None:
        return None
    data = match.groupdict()
    if data.get("method") is None:
        data["method"] = "-"
        data["uri"] = data.pop("badreq", None) or "-"
    else:
        data.pop("badreq", None)
    return data


def sniff_error_log(file_path, open_text):
    """True if the file's first non-empty line looks like an error log."""
    try:
        with open_text(file_path) as f:
            for line in f:
                if line.strip():
                    return bool(ERROR_LOG_SIGNATURES.match(line))
    except (OSError, EOFError):
        pass
    return False


# The Apache timestamp is fixed-width (dd/Mon/yyyy:HH:MM:SS +zzzz). strptime
# per line is far too slow for multi-million-line logs, so the (day, tz) part
# is strptime'd ONCE per distinct pair and the time of day is pure integer
# arithmetic. Returns (epoch_utc, tz_offset_seconds) -- the offset lets every
# consumer show the log's own local time again.
_DATE_CACHE = {}


def fast_epoch(ts):
    try:
        # IIS W3C timestamps are always UTC and use separate ISO date/time
        # fields.  Keep the same cached day + integer time-of-day fast path as
        # the Apache parser instead of invoking strptime for every request.
        if len(ts) >= 19 and ts[4:5] == "-" and ts[10:11] in (" ", "T"):
            key = ("w3c", ts[:10])
            cached = _DATE_CACHE.get(key)
            if cached is None:
                dt = datetime.strptime(ts[:10], "%Y-%m-%d").replace(
                    tzinfo=timezone.utc)
                cached = _DATE_CACHE[key] = (dt.timestamp(), 0)
            base, offset = cached
            return (base + int(ts[11:13]) * 3600 + int(ts[14:16]) * 60
                    + int(ts[17:19]), offset)

        key = (ts[:11], ts[21:])
        cached = _DATE_CACHE.get(key)
        if cached is None:
            dt = datetime.strptime(f"{key[0]} {key[1]}", "%d/%b/%Y %z")
            offset = int(dt.utcoffset().total_seconds())
            cached = _DATE_CACHE[key] = (dt.timestamp(), offset)
        base, offset = cached
        return (base + int(ts[12:14]) * 3600 + int(ts[15:17]) * 60 + int(ts[18:20]),
                offset)
    except (ValueError, TypeError, IndexError, KeyError):
        return None
