"""Explicit large-file retries stay bounded without changing normal scans."""

MAX_OVERRIDE_SCAN_BYTES = 256 * 1024 * 1024


def scan_byte_limit(default, max_bytes=None):
    """Use the selected file's approved ceiling, never an unbounded read."""
    if max_bytes is None:
        return default
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_OVERRIDE_SCAN_BYTES:
        raise ValueError("A selected-file scan limit must be between 1 byte and 256 MiB")
    return max_bytes


def size_skip_reason(kind, size, limit):
    scanner = "a YARA scan" if kind == "yara" else "content scan"
    return f"too large for {scanner} ({size} bytes; limit {limit} bytes)"
