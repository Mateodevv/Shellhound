"""Bounded raw-file pages with source line numbers and optional line lookup."""
import codecs
from dataclasses import dataclass
from typing import BinaryIO


_SCAN_BYTES = 64 * 1024


@dataclass(frozen=True)
class RawFilePage:
    offset: int
    chunk: bytes
    from_line: int
    starts_mid_line: bool
    focus_found: bool | None = None


def _line_offset(stream: BinaryIO, line: int, size: int) -> int | None:
    """Find a line start without retaining earlier lines, even very long ones."""
    if not size:
        return None
    if line == 1:
        return 0
    stream.seek(0)
    remaining = line - 1
    position = 0
    while position < size:
        chunk = stream.read(min(_SCAN_BYTES, size - position))
        if not chunk:
            break
        count = chunk.count(b"\n")
        if count >= remaining:
            boundary = -1
            for _ in range(remaining):
                boundary = chunk.find(b"\n", boundary + 1)
            start = position + boundary + 1
            # A trailing newline terminates the previous line; it does not
            # create another source line for scanners to refer to.
            return start if start < size else None
        remaining -= count
        position += len(chunk)
    return None


def _line_number(stream: BinaryIO, offset: int) -> int:
    stream.seek(0)
    remaining = offset
    line = 1
    while remaining:
        chunk = stream.read(min(remaining, _SCAN_BYTES))
        if not chunk:
            break
        line += chunk.count(b"\n")
        remaining -= len(chunk)
    return line


def _character_start(stream: BinaryIO, offset: int, size: int) -> int:
    """Rewind an offset only when it splits a valid UTF-8 character."""
    if not 0 < offset < size:
        return offset
    start = max(0, offset - 3)
    stream.seek(start)
    nearby = stream.read(7)
    relative = offset - start
    for candidate in range(min(relative, len(nearby)) - 1, -1, -1):
        lead = nearby[candidate]
        width = (2 if 0xC2 <= lead <= 0xDF else
                 3 if 0xE0 <= lead <= 0xEF else
                 4 if 0xF0 <= lead <= 0xF4 else 0)
        if not candidate < relative < candidate + width:
            continue
        try:
            nearby[candidate:candidate + width].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        return start + candidate
    return offset


def read_raw_page(stream: BinaryIO, *, size: int, window: int,
                  offset: int = 0, line: int | None = None) -> RawFilePage:
    """Return at most ``window`` bytes, aligned to complete UTF-8 characters.

    Requested source lines start the page. A missing line returns the first
    page with ``focus_found=False`` so callers can explain the missing anchor.
    Byte-based pages retain their real line number and flag partial first
    lines. Prefix scans use fixed-size reads rather than loading the file or
    a potentially enormous individual line into memory.
    """
    if window < 4:
        raise ValueError("The raw file window must be at least four bytes")
    if line is not None and line < 1:
        raise ValueError("Line must be a positive integer")
    offset = max(0, min(offset, size))
    focus_found = None
    if line is not None:
        found = _line_offset(stream, line, size)
        focus_found = found is not None
        offset = found if found is not None else 0
        from_line = line if focus_found else 1
    else:
        # Backward paging can land inside a multi-byte character. Rewind only
        # a valid sequence; malformed bytes must not cause overlapping pages.
        offset = _character_start(stream, offset, size)
        from_line = _line_number(stream, offset)

    starts_mid_line = False
    if offset:
        stream.seek(offset - 1)
        starts_mid_line = stream.read(1) != b"\n"
    stream.seek(offset)
    chunk = stream.read(window)
    if offset + len(chunk) < size:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        decoder.decode(chunk, final=False)
        buffered, _ = decoder.getstate()
        if buffered:
            chunk = chunk[:-len(buffered)]
    return RawFilePage(offset, chunk, from_line, starts_mid_line, focus_found)
