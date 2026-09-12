"""Local rotating log for application activity, requests and exceptions."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re
import sys
import threading
import time
import traceback
from urllib.parse import parse_qs
import uuid


_LOCK = threading.RLock()
_MAX_BYTES = 10 * 1024 * 1024
_MAX_ENTRIES = 10000
_HANDLERS = {}
_KNOWN_SECRETS = set()
_SECRET = re.compile(r'''(?ix)(["']?\b(?:token|password|authorization|api[_ -]?key|x-token)\b["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|(?:bearer\s+)?[^\s,;}]+)''')
_BEARER = re.compile(r"(?i)\bbearer\s+[^\s,;\"']+")
_WINDOWS_PATH = re.compile(r"(?i)(?:[A-Z]:\\|\\\\)[^\s\"']+")
_UNIX_PATH = re.compile(r"(?<![\w/])/(?:home|tmp|var|users|private)/[^\s\"']+")
_URL_QUERY = re.compile(r"(https?://[^\s?]+)\?[^\s]+", re.I)


def _file(workspace: Path) -> Path:
    return Path(workspace) / "logs" / "shellhound.log"


def sanitize(value: object, *, limit: int = 16000) -> str:
    """Keep a useful operational message while excluding sensitive material."""
    text = str(value if value is not None else "")
    with _LOCK:
        for secret in sorted(_KNOWN_SECRETS, key=len, reverse=True):
            text = text.replace(secret, "[redacted]")
    text = _SECRET.sub(lambda match: match.group(1) + "[redacted]", text)
    text = _BEARER.sub("Bearer [redacted]", text)
    text = _URL_QUERY.sub(r"\1?[redacted]", text)
    text = _WINDOWS_PATH.sub("[local path]", text)
    text = _UNIX_PATH.sub("[local path]", text)
    return text[:limit] or "No additional error detail was available."


def protect_secret(value):
    if isinstance(value, str) and len(value) >= 6:
        with _LOCK:
            _KNOWN_SECRETS.add(value)


def _clean(value):
    if isinstance(value, dict):
        return {str(k): "[redacted]" if re.search(r"token|password|authorization|api.?key", str(k), re.I)
                else _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return sanitize(value)


def _handler(workspace):
    target = _file(workspace).resolve()
    with _LOCK:
        if target not in _HANDLERS:
            target.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(target, maxBytes=_MAX_BYTES, backupCount=5,
                                          encoding="utf-8", delay=True)
            handler.setFormatter(logging.Formatter("%(message)s"))
            handler.handleError = lambda record: sys.stderr.write("Shellhound could not write its log file.\n")
            _HANDLERS[target] = handler
        return _HANDLERS[target]


def record(workspace: Path, level: str, component: str, message: object, **context: object) -> dict:
    """Append one safe event. Diagnostics must never make the product fail."""
    event = {
        "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "level": level.lower(),
        "component": sanitize(component, limit=60),
        "message": sanitize(message),
        "thread": threading.current_thread().name,
    }
    for key, value in context.items():
        if value not in (None, ""):
            event[key] = _clean(value)
    try:
        entry = logging.LogRecord("shellhound.file", logging.INFO, "", 0,
                                  json.dumps(event, ensure_ascii=False), (), None)
        handler = _handler(workspace)
        with handler.lock:
            handler.handle(entry)
            # Flush immediately and release the file on Windows so workspace
            # backup/removal is never blocked by an idle logging handle.
            handler.close()
    except (OSError, ValueError):
        sys.stderr.write("Shellhound could not write its log file.\n")
    return event


def read(workspace: Path, limit: int = 100) -> list[dict]:
    """Return newest valid events first; a damaged line never hides the rest."""
    try:
        lines = _file(workspace).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    events = []
    for line in reversed(lines[-max(1, min(int(limit), _MAX_ENTRIES)):]):
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def fingerprint(value: object) -> str:
    """Correlate a local target across events without recording its path."""
    return hashlib.sha256(str(value or "").encode("utf-8", "replace")).hexdigest()[:12]


def exception(workspace, component, exc, **context):
    # Keep all stack frames without locals or source lines containing evidence.
    chain, seen, current = [], set(), exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append({"type": type(current).__name__, "message": str(current),
                      "frames": [{"file": Path(f.filename).name, "line": f.lineno, "function": f.name}
                                 for f in traceback.extract_tb(current.__traceback__)]})
        current = current.__cause__ or (None if current.__suppress_context__ else current.__context__)
    return record(workspace, "error", component, f"{type(exc).__name__}: {exc}", exceptions=chain, **context)


def close(workspace):
    with _LOCK:
        handler = _HANDLERS.pop(_file(workspace).resolve(), None)
        if handler:
            handler.close()


class ApplicationLogHandler(logging.Handler):
    def __init__(self, workspace):
        super().__init__(logging.DEBUG)
        self.workspace = workspace

    def emit(self, entry):
        if entry.exc_info and entry.exc_info[1]:
            exception(self.workspace, entry.name, entry.exc_info[1])
        else:
            record(self.workspace, entry.levelname, entry.name, entry.getMessage())


def configure(workspace, token=""):
    protect_secret(token)
    handler = ApplicationLogHandler(workspace)
    root = logging.getLogger()
    previous = root.level
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)

    def cleanup():
        root.removeHandler(handler)
        root.setLevel(previous)
        close(workspace)
    return cleanup


class RequestLogMiddleware:
    def __init__(self, app, workspace):
        self.app, self.workspace = app, workspace

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        request_id = uuid.uuid4().hex[:16]
        scope["diagnostic_id"] = request_id
        started, status = time.monotonic(), 500
        query = parse_qs(scope.get("query_string", b"")[:16384].decode("utf-8", "replace"))
        target = (query.get("path") or [""])[0]
        context = {"request_id": request_id, "method": scope.get("method", "WS")}
        if target:
            context["target"] = fingerprint(target)
        record(self.workspace, "debug", "http", "Request received", **context)

        async def logged_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message = {**message, "headers": [*message.get("headers", []),
                                                   (b"x-request-id", request_id.encode())]}
            elif message["type"] == "websocket.accept":
                status = 101
            elif message["type"] == "websocket.close":
                context["close_code"] = message.get("code")
            await send(message)
        try:
            await self.app(scope, receive, logged_send)
        except Exception as exc:
            exception(self.workspace, "http", exc, **context)
            raise
        finally:
            record(self.workspace, "error" if status >= 500 else "warning" if status >= 400 else "info",
                   "http", "Request completed", **context,
                   route=getattr(scope.get("route"), "path", "<unmatched>"), status=status,
                   duration_ms=round((time.monotonic() - started) * 1000, 2))
