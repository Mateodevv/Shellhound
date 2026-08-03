# server/engines/accesslog.py
"""Access-log line parsing (ported from legacy core/accesslog.py).

The Combined/Common patterns carry years of real-webhost quirks: vhost
tokens, Plesk trailer fields, escaped quotes in UA/referrer, empty 400/408
requests. They are ported verbatim -- every quirk removed here would silently
drop exactly the attacker lines the index exists to answer about.
"""
import re
from datetime import datetime

_QF = r'(?:[^"\\]|\\.)*'   # content of one quoted log field

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?:(?P<method>[A-Z]+) (?P<uri>.*?)(?: HTTP/[\d\.]+)??|(?P<badreq>' + _QF + r'))" '
    r'(?P<status>\d{3}) (?P<size>\d+|-) '
    r'(?:[^"\s]\S* )?'
    r'"(?P<referrer>' + _QF + r')" "(?P<user_agent>' + _QF + r')"'
    r'(?:\s.*)?$'
)

LOG_PATTERN_COMMON = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<uri>.*?)(?: HTTP/[\d\.]+)??" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)\s*$'
)

ERROR_LOG_SIGNATURES = re.compile(
    r'^(?:'
    r'\[\w{3} \w{3} [ \d]?\d \d{2}:\d{2}:\d{2}'   # Apache: [Fri Jun 26 05:19:59...
    r'|\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \['    # Nginx:  2026/06/30 11:52:26 [error]
    r')')

ERROR_LOG_SKIP_REASON = "Apache/Nginx error log (not an access-log format)"


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
