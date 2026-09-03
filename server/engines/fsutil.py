# server/engines/fsutil.py
"""Shared filesystem helpers (ported from legacy core/utils.py)."""
import bz2
import gzip
import lzma
import hashlib
import os
from pathlib import Path

# `.xz` is listed in DUMP_SUFFIXES, so a dump named that way was offered to
# the detector and then read as raw compressed bytes: it found no SQL and
# the file was silently never proposed, while a .sql.gz beside it was.
COMPRESSED_OPENERS = {".gz": gzip.open, ".bz2": bz2.open, ".xz": lzma.open}
_CHUNK = 65536


def get_files_recursive(directory):
    for file_path in Path(directory).rglob("*"):
        if file_path.is_file():
            yield str(file_path)


def iter_target_files(target):
    if os.path.isfile(target):
        yield str(target)
    else:
        yield from get_files_recursive(target)


def path_within_any(path, targets):
    """True when ``path`` is one of ``targets`` or lives below one.

    Both sides are resolved first so a symlink cannot make a partial cleanup
    reach outside the evidence that job was actually given.  ``commonpath``
    also handles path-component boundaries (``site`` never matches
    ``site-old``) and different Windows drives without string-prefix tricks.
    """
    candidate = os.path.normcase(os.path.realpath(os.path.abspath(str(path))))
    for target in targets:
        root = os.path.normcase(os.path.realpath(os.path.abspath(str(target))))
        try:
            if os.path.commonpath((candidate, root)) == root:
                return True
        except ValueError:
            continue
    return False


def is_compressed(file_path):
    return Path(file_path).suffix.lower() in COMPRESSED_OPENERS


def open_text_auto(file_path, encoding="utf-8-sig", errors="replace"):
    """Every text file the engines read comes through here.

    `utf-8-sig`, NOT `utf-8`. A byte-order mark is what a file gets from being
    opened and saved in a Windows editor, which is an ordinary thing to happen
    to evidence between the server and the analysis machine. Decoded as plain
    utf-8 the mark survives as U+FEFF at the head of the first line, and it is
    not whitespace -- so `^(?P<ip>\\S+)` ate it into the client address and the
    actor list gained a client that never existed, while a real visitor lost
    its earliest request.

    That was the visible half. The quiet half was worse: an error log carrying
    a mark stopped being recognised as one, so every finding it would have
    produced was lost without a word, and it then entered the access-log index
    instead -- where coverage reported it as truncated, which is a statement
    about a file that is not true of the file.

    `utf-8-sig` is a superset: it strips a mark if present and behaves exactly
    as `utf-8` otherwise. A mark in the MIDDLE of a stream -- what `cat`-ing
    rotated logs together produces -- is NOT covered here and still invents a
    client; closing that means stripping U+FEFF in the line parsers."""
    opener = COMPRESSED_OPENERS.get(Path(file_path).suffix.lower(), open)
    return opener(file_path, mode="rt", encoding=encoding, errors=errors)


def looks_binary(file_path, sniff_bytes=8192):
    try:
        with open(file_path, "rb") as f:
            return b"\x00" in f.read(sniff_bytes)
    except OSError:
        return True


def is_scannable_text(file_path):
    return is_compressed(file_path) or not looks_binary(file_path)


def sha256_of(file_path):
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(_CHUNK), b""):
                h.update(block)
        return h.hexdigest()
    except OSError:
        return ""


def format_size(size_bytes):
    if not size_bytes:
        return "0 B"
    names = ("B", "KB", "MB", "GB", "TB")
    i = 0
    size = float(size_bytes)
    while size >= 1024 and i < len(names) - 1:
        size /= 1024.0
        i += 1
    return f"{size:.2f} {names[i]}"
