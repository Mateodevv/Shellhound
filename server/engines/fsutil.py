# server/engines/fsutil.py
"""Shared filesystem helpers (ported from legacy core/utils.py)."""
import bz2
import gzip
import hashlib
import os
from pathlib import Path

COMPRESSED_OPENERS = {".gz": gzip.open, ".bz2": bz2.open}
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


def is_compressed(file_path):
    return Path(file_path).suffix.lower() in COMPRESSED_OPENERS


def open_text_auto(file_path, encoding="utf-8", errors="replace"):
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
