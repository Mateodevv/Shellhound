"""Small, non-executing decoder for PHP serialized values.

WordPress stores lists, cron jobs, roles and session metadata in PHP's
serialization format.  Pulling PHP into the evidence pipeline (or invoking
``unserialize``) would turn a passive parser into code execution.  This
module understands only the data grammar and applies hard limits before it
allocates nested structures.
"""

from __future__ import annotations

import math


class DecodeError(ValueError):
    pass


class _Parser:
    def __init__(self, data: bytes, *, max_depth: int, max_items: int):
        self.data = data
        self.pos = 0
        self.max_depth = max_depth
        self.max_items = max_items
        self.items = 0

    def _take(self, token: bytes):
        if not self.data.startswith(token, self.pos):
            raise DecodeError("invalid PHP serialization delimiter")
        self.pos += len(token)

    def _until(self, token: bytes) -> bytes:
        end = self.data.find(token, self.pos)
        if end < 0:
            raise DecodeError("unterminated PHP serialization value")
        out = self.data[self.pos:end]
        self.pos = end + len(token)
        return out

    def parse(self, depth: int = 0):
        if depth > self.max_depth:
            raise DecodeError("PHP serialization is nested too deeply")
        self.items += 1
        if self.items > self.max_items:
            raise DecodeError("PHP serialization contains too many values")
        if self.pos >= len(self.data):
            raise DecodeError("truncated PHP serialization")
        kind = chr(self.data[self.pos])
        self.pos += 1

        if kind == "N":
            self._take(b";")
            return None
        self._take(b":")
        if kind == "b":
            raw = self._until(b";")
            if raw not in (b"0", b"1"):
                raise DecodeError("invalid serialized boolean")
            return raw == b"1"
        if kind == "i":
            try:
                return int(self._until(b";"))
            except ValueError as exc:
                raise DecodeError("invalid serialized integer") from exc
        if kind == "d":
            try:
                value = float(self._until(b";"))
            except ValueError as exc:
                raise DecodeError("invalid serialized float") from exc
            if not math.isfinite(value):
                raise DecodeError("non-finite serialized float")
            return value
        if kind == "s":
            try:
                length = int(self._until(b":"))
            except ValueError as exc:
                raise DecodeError("invalid serialized string length") from exc
            if length < 0 or self.pos + length > len(self.data):
                raise DecodeError("serialized string exceeds input")
            self._take(b'"')
            raw = self.data[self.pos:self.pos + length]
            self.pos += length
            self._take(b'";')
            return raw.decode("utf-8", errors="replace")
        if kind in ("r", "R"):
            # References are irrelevant to forensic extraction.  Preserve
            # their presence without resolving object graphs.
            self._until(b";")
            return None
        if kind == "a":
            try:
                count = int(self._until(b":"))
            except ValueError as exc:
                raise DecodeError("invalid serialized array length") from exc
            if count < 0 or count > self.max_items:
                raise DecodeError("serialized array is too large")
            self._take(b"{")
            pairs = []
            for _ in range(count):
                key = self.parse(depth + 1)
                value = self.parse(depth + 1)
                if not isinstance(key, (str, int)):
                    raise DecodeError("unsupported serialized array key")
                pairs.append((key, value))
            self._take(b"}")
            if [key for key, _ in pairs] == list(range(count)):
                return [value for _, value in pairs]
            return dict(pairs)
        if kind == "O":
            try:
                name_length = int(self._until(b":"))
            except ValueError as exc:
                raise DecodeError("invalid serialized object name") from exc
            self._take(b'"')
            if name_length < 0 or self.pos + name_length > len(self.data):
                raise DecodeError("serialized object name exceeds input")
            class_name = self.data[self.pos:self.pos + name_length].decode(
                "utf-8", errors="replace")
            self.pos += name_length
            self._take(b'":')
            try:
                count = int(self._until(b":"))
            except ValueError as exc:
                raise DecodeError("invalid serialized object size") from exc
            if count < 0 or count > self.max_items:
                raise DecodeError("serialized object is too large")
            self._take(b"{")
            obj = {"__class__": class_name}
            for _ in range(count):
                key = self.parse(depth + 1)
                value = self.parse(depth + 1)
                if isinstance(key, (str, int)):
                    obj[str(key).replace("\x00", "")] = value
            self._take(b"}")
            return obj
        raise DecodeError(f"unsupported PHP serialization type: {kind}")


def loads(value: str | bytes, *, max_bytes: int = 1_048_576,
          max_depth: int = 16, max_items: int = 5_000):
    """Decode a bounded PHP data value without executing PHP code."""
    data = value if isinstance(value, bytes) else str(value).encode("utf-8")
    if len(data) > max_bytes:
        raise DecodeError("PHP serialization exceeds the byte limit")
    parser = _Parser(data.strip(), max_depth=max_depth, max_items=max_items)
    result = parser.parse()
    if parser.data[parser.pos:].strip():
        raise DecodeError("trailing data after PHP serialization")
    return result


def safe_loads(value: str | bytes, **limits):
    """Return ``None`` for malformed or unsupported serialized data."""
    try:
        return loads(value, **limits)
    except (DecodeError, UnicodeError, ValueError, TypeError):
        return None
