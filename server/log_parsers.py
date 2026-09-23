"""Bounded, observation-only adapters for locally supplied log evidence."""
import bz2
import gzip
import io
import ipaddress
import lzma
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from server.engines import accesslog, errorlog
from server.paths import io_path

VERSION = "1"
FORMATS = {"auto": "Detect automatically", "access": "Access log",
           "apache_error": "Apache error log", "nginx_error": "Nginx error log",
           "xferlog": "FTP transfer log (xferlog)", "vsftpd": "vsftpd log",
           "clamav": "ClamAV scan report", "text": "Other text (manual review)"}
FAMILIES = {"access": "access", "apache_error": "error", "nginx_error": "error",
            "xferlog": "ftp", "vsftpd": "ftp", "clamav": "malware", "text": "text"}
MAX_LINE = 128 * 1024
MAX_BYTES = 2 * 1024 ** 3
MAX_LINES = 5_000_000
MONTHS = {name: i for i, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_CLOCK = r"\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\d{4}"
_XFER = re.compile(r"^(?P<time>" + _CLOCK + r")\s+(?P<duration>\d+)\s+(?P<host>\S+)\s+"
                   r"(?P<bytes>\d+)\s+(?P<path>.+?)\s+[ab]\s+\S+\s+(?P<direction>[iod])\s+"
                   r"[agr]\s+(?P<account>\S+)\s+\S+\s+\d+\s+\S+\s+(?P<done>[ci])\s*$")
_VSFTP = re.compile(r"^(?P<time>" + _CLOCK + r")\s+\[pid \d+\]\s+"
                    r"(?:\[(?P<account>[^\]]+)\]\s+)?(?P<result>OK|FAIL)\s+"
                    r"(?P<op>LOGIN|UPLOAD|DOWNLOAD|DELETE|MKDIR|RMDIR|RENAME):\s*(?P<detail>.*)$")
_SCAN = re.compile(r"^(?P<path>.+):\s+(?P<signature>.+) FOUND\s*$")


class LogReadError(ValueError):
    pass


def text_lines(path, *, preview=False):
    """Read compressed or plain text without allocating an unbounded line."""
    opener = {".gz": gzip.open, ".bz2": bz2.open, ".xz": lzma.open}.get(Path(path).suffix.lower(), open)
    with opener(io_path(path), "rb") as raw:
        buffered = io.BufferedReader(raw)
        head = buffered.peek(4)[:4]
        encoding = "utf-16" if head.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        with io.TextIOWrapper(buffered, encoding=encoding, errors="replace") as stream:
            size = 0
            for ordinal in range(1, MAX_LINES + 2):
                line = stream.readline(MAX_LINE + 1)
                if not line:
                    return
                if len(line) > MAX_LINE:
                    raise LogReadError("A log record exceeds the 128 KiB safety limit")
                if "\x00" in line:
                    raise LogReadError("Binary content is not a supported text log")
                size += len(line.encode("utf-8"))
                if size > MAX_BYTES or ordinal > MAX_LINES:
                    raise LogReadError("The decompressed log exceeds the processing limit")
                yield ordinal, line.rstrip("\r\n").lstrip("\ufeff")
                if preview and (ordinal >= 100 or size >= 128 * 1024):
                    return


def zone(value):
    if not value or value in ('auto', 'unknown'):
        return None
    if value in ("UTC", "Z"):
        return timezone.utc
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", value)
    if match:
        hours, minutes = int(match[2]), int(match[3])
        if hours > 14 or minutes > 59 or (hours == 14 and minutes):
            raise ValueError("Timezone offset must be between -14:00 and +14:00")
        return timezone(timedelta(minutes=(hours * 60 + minutes) * (-1 if match[1] == "-" else 1)))
    try:
        return ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError("Unknown timezone. Use UTC, an installed timezone name, or an offset such as +02:00") from None


def timestamp(raw, source_zone=""):
    """Return UTC only for a known, unambiguous clock; never use this computer's zone."""
    if not raw:
        return None
    try:
        if re.match(r"^\w{3}\s+\w{3}\s+", raw):
            parts = raw.split()
            clock = parts[3].split(".")[0].split(":")
            value = datetime(int(parts[4]), MONTHS[parts[1]], int(parts[2]), *map(int, clock))
        else:
            normalized = re.sub(r"^(\d{4}):(\d{2}):(\d{2})", r"\1-\2-\3", raw)
            value = datetime.fromisoformat(normalized.replace("/", "-").replace("Z", "+00:00"))
        if value.tzinfo is None:
            tz = zone(source_zone)
            if tz is None:
                return None
            candidates = {int(value.replace(tzinfo=tz, fold=fold).timestamp()) for fold in (0, 1)
                          if datetime.fromtimestamp(value.replace(tzinfo=tz, fold=fold).timestamp(), tz)
                          .replace(tzinfo=None) == value}
            return next(iter(candidates)) if len(candidates) == 1 else None
        return int(value.timestamp())
    except (ValueError, KeyError, IndexError, OverflowError, OSError):
        return None


def client(value):
    value = (value or "").strip().strip('"')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        try:
            host = value[1:value.index("]")] if value.startswith("[") else value.rsplit(":", 1)[0]
            return str(ipaddress.ip_address(host))
        except (ValueError, IndexError):
            return ""


def redact(text):
    """Credentials remain in the original evidence, not summaries or diagnostics."""
    text = re.sub(r"(?i)(\b(?:password|passwd|authorization|token|secret)\s*[:=]\s*)[^\s,;]+", r"\1[redacted]", text)
    return re.sub(r"(?i)(\bPASS\s+)[^\r\n]+", r"\1[redacted]", text)


def parse_line(fmt, line):
    base = {"raw_time": "", "ip": "", "remote_host": "", "account": "", "path": "",
            "operation": "observation", "outcome": "", "signature": "", "bytes": None,
            "time_meaning": "event", "detection": False, "parsed": True}
    if fmt in ("apache_error", "nginx_error"):
        value = errorlog.parse_line(line)
        if not value:
            return None
        paths = errorlog.paths_in(value["message"])
        nginx_ip = re.search(r"\bclient:\s*([^,\s]+)", value["message"])
        return {**base, "raw_time": value["time"], "ip": client(value["client"] or (nginx_ip[1] if nginx_ip else "")),
                "path": paths[0][0] if paths else "", "file_line": paths[0][1] if paths else None,
                "operation": "web_error", "outcome": "error"}
    if fmt == "xferlog":
        m = _XFER.match(line)
        if not m:
            return None
        return {**base, "raw_time": m["time"], "ip": client(m["host"]), "remote_host": m["host"],
                "account": m["account"], "path": m["path"], "bytes": int(m["bytes"]),
                "operation": {"i": "upload", "o": "download", "d": "delete"}[m["direction"]],
                "outcome": "success" if m["done"] == "c" else "incomplete"}
    if fmt == "vsftpd":
        m = _VSFTP.match(line)
        if not m:
            return None
        host = re.search(r'Client "([^"]+)"', m["detail"])
        path = re.search(r'Client "[^"]+", "([^"]+)"', m["detail"])
        size = re.search(r"\b(\d+) bytes\b", m["detail"])
        return {**base, "raw_time": m["time"], "ip": client(host[1]) if host else "",
                "remote_host": host[1] if host else "", "account": m["account"] or "",
                "path": path[1] if path else "", "bytes": int(size[1]) if size else None,
                "operation": m["op"].lower(), "outcome": "success" if m["result"] == "OK" else "failed"}
    if fmt == "clamav":
        m = _SCAN.match(line)
        if m:
            warning = m["signature"].startswith(("Heuristics.Limits.", "Heuristics.Encrypted.", "Heuristics.Broken."))
            return {**base, "path": m["path"], "signature": m["signature"], "time_meaning": "detection",
                    "operation": "scan_warning" if warning else "malware_detection",
                    "outcome": "warning" if warning else "reported_detection", "detection": not warning}
        m = re.match(r"^(.+?):\s+(OK|.* ERROR|Removed\.?|(?:moved|copied) to .+)\s*$", line, re.I)
        if m:
            return {**base, "path": m[1], "operation": "scan_result", "time_meaning": "scan",
                    "outcome": "reported_ok" if m[2].upper() == "OK" else "error" if m[2].upper().endswith("ERROR") else "reported_action"}
        if line.startswith(("ERROR:", "WARNING:")):
            return {**base, "operation": "scan_result", "time_meaning": "scan",
                    "outcome": "error" if line.startswith("ERROR:") else "warning"}
        if re.match(r"^-+ SCAN SUMMARY -+$|^(?:Known viruses|Engine version|Scanned directories|Scanned files|Infected files|Total errors|Data scanned|Data read|Time|Start Date|End Date):", line):
            dated = re.match(r"^(?:Start Date|End Date):\s*(.+)$", line)
            return {**base, "operation": "scan_summary", "time_meaning": "scan", "outcome": "summary",
                    "raw_time": dated[1] if dated else ""}
    if fmt == "text":
        return {**base, "parsed": False}
    return None


def detect(lines):
    scores = {}
    parser = accesslog.AccessLogParser()
    for _, line in lines:
        if not line.strip():
            continue
        found = []
        for fmt in ("xferlog", "vsftpd", "clamav", "apache_error", "nginx_error"):
            if (fmt == "apache_error" and not line.startswith("[")) or (fmt == "nginx_error" and not re.match(r"^\d{4}/", line)):
                continue
            if parse_line(fmt, line):
                found.append(fmt)
        if not found and parser.parse(line):
            found.append("access")
        for fmt in found:
            scores[fmt] = scores.get(fmt, 0) + 1
    ordered = sorted(scores, key=lambda fmt: (-scores[fmt], fmt))
    ambiguous = len(ordered) > 1
    return {"format": ordered[0] if len(ordered) == 1 else "text", "ambiguous": ambiguous,
            "candidates": ordered, "recognized": bool(ordered) and not ambiguous}


def records(path, fmt, source_zone=""):
    pending = None
    for number, line in text_lines(path):
        if not line.strip():
            continue
        parsed = parse_line(fmt, line)
        if not parsed and pending and fmt in ("apache_error", "nginx_error") and (line[:1].isspace() or re.match(r"^#\d+\s", line)):
            if len(pending["raw"]) + len(line) > MAX_LINE:
                raise LogReadError("A multiline log record exceeds the 128 KiB safety limit")
            pending["raw"] += "\n" + line
            pending["line_end"] = number
            continue
        if pending:
            yield pending
        parsed = parsed or parse_line("text", line)
        pending = {**parsed, "epoch": timestamp(parsed["raw_time"], source_zone),
                   "line": number, "line_end": number, "raw": line}
    if pending:
        yield pending
