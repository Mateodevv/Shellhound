# server/engines/fsutil.py
"""Shared filesystem helpers (ported from legacy core/utils.py)."""
import bz2
import gzip
import lzma
import hashlib
import os
import stat
import time
from pathlib import Path
from server.paths import display_path, io_path

# `.xz` is listed in DUMP_SUFFIXES, so a dump named that way was offered to
# the detector and then read as raw compressed bytes: it found no SQL and
# the file was silently never proposed, while a .sql.gz beside it was.
COMPRESSED_OPENERS = {".gz": gzip.open, ".bz2": bz2.open, ".xz": lzma.open}
_CHUNK = 65536


def record_skip(ctx, path, reason, category="file", root=""):
    """Retain per-job details when running with a job context."""
    callback = getattr(ctx, "detailed_skip", None)
    if callback is not None:
        callback(path, reason, category=category, root=root)
        return
    callback = getattr(ctx, "skip", None)
    if callback is not None:
        callback(path, reason)


def canonical_file(path):
    """One identity for long-path prefixes, aliases and platform casing."""
    return os.path.normcase(os.path.realpath(io_path(path)))


class ScanProgress:
    """File scans publish phases without flooding the job event stream."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.last_update = float("-inf")

    def cancelled(self):
        return self.ctx is not None and self.ctx.cancelled()

    def update(self, fraction, message, phase, completed=None, total=None,
               force=False):
        if self.ctx is None:
            return
        now = time.monotonic()
        if not force and now - self.last_update < 0.2:
            return
        self.last_update = now
        callback = getattr(self.ctx, "phase_progress", None)
        if callback is not None:
            callback(fraction, message, phase, completed=completed, total=total)
        else:
            self.ctx.progress(fraction, message)


def discover_scan_files(targets, progress, stats, file_targets=None):
    """Discover once, reporting unknown totals and explicit traversal errors.

    Retry entries already identify individual files and their original root;
    they must never turn into a recursive scan if the file became a directory.
    Links inside an evidence root are supported, but cannot escape that root
    or cause a directory cycle. Failures to enumerate are incomplete coverage,
    not ordinary file warnings.
    """
    files, seen_files = [], set()
    progress.update(0, "Finding files… 0 found", "discovering", 0, None, force=True)

    def discovery_error(path, root, error):
        stats["partial"] = True
        stats["discovery_errors"] = stats.get("discovery_errors", 0) + 1
        record_skip(progress.ctx, display_path(path), str(error), "discovery", root)

    def add(path, root):
        path = os.path.abspath(display_path(path))
        root = os.path.abspath(display_path(root))
        # Names and paths relative to the evidence root affect scanner rules.
        # Only repeated logical contexts are duplicates; resolving aliases here
        # could hide an executable extension or a file's upload-directory role.
        key = (os.path.normcase(path), os.path.normcase(root))
        if key not in seen_files:
            seen_files.add(key)
            files.append((path, root))
        progress.update(0, f"Finding files… {len(files):,} found", "discovering",
                        len(files), None)

    if file_targets is not None:
        for entry in file_targets:
            if progress.cancelled():
                break
            path, root = entry["path"], entry["root"]
            if not path_within_any(path, [root]):
                discovery_error(path, root, "file is outside its original evidence root")
                continue
            add(path, root)
    else:
        for target in targets:
            if progress.cancelled():
                break
            target = os.path.abspath(display_path(target))
            try:
                mode = os.stat(io_path(target)).st_mode
            except OSError as exc:
                discovery_error(target, target, f"cannot inspect evidence root: {exc}")
                continue
            if stat.S_ISREG(mode):
                add(target, os.path.dirname(target))
                continue
            if not stat.S_ISDIR(mode):
                discovery_error(target, target, "evidence root is not a file or directory")
                continue
            pending = [(target, frozenset())]
            while pending and not progress.cancelled():
                directory, ancestors = pending.pop()
                identity = canonical_file(directory)
                # Stop cycles on this traversal branch, while preserving other
                # logical paths to the same directory for location-based rules.
                if identity in ancestors:
                    continue
                ancestors = ancestors | {identity}
                try:
                    with os.scandir(io_path(directory)) as entries:
                        for entry in entries:
                            if progress.cancelled():
                                break
                            path = display_path(entry.path)
                            try:
                                if not path_within_any(path, [target]):
                                    discovery_error(path, target,
                                                    "link points outside the evidence root")
                                elif entry.is_file():
                                    add(path, target)
                                elif entry.is_dir():
                                    pending.append((path, ancestors))
                                elif entry.is_symlink():
                                    discovery_error(path, target, "cannot resolve evidence link")
                            except OSError as exc:
                                discovery_error(path, target, f"cannot inspect entry: {exc}")
                            progress.update(0, f"Finding files… {len(files):,} found",
                                            "discovering", len(files), None)
                except OSError as exc:
                    discovery_error(directory, target, f"cannot read directory: {exc}")
                progress.update(0, f"Finding files… {len(files):,} found", "discovering",
                                len(files), None)
    progress.update(0, f"Finding files… {len(files):,} found", "discovering",
                    len(files), None, force=True)
    return files


def get_files_recursive(directory):
    for file_path in Path(io_path(directory)).rglob("*"):
        if file_path.is_file():
            yield display_path(file_path)


def iter_target_files(target):
    if os.path.isfile(io_path(target)):
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
    candidate = os.path.normcase(os.path.realpath(io_path(path)))
    for target in targets:
        root = os.path.normcase(os.path.realpath(io_path(target)))
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
    return opener(io_path(file_path), mode="rt", encoding=encoding, errors=errors)


def looks_binary(file_path, sniff_bytes=8192):
    try:
        with open(io_path(file_path), "rb") as f:
            return b"\x00" in f.read(sniff_bytes)
    except OSError:
        return True


def is_scannable_text(file_path):
    return is_compressed(file_path) or not looks_binary(file_path)


def sha256_of(file_path):
    h = hashlib.sha256()
    try:
        with open(io_path(file_path), "rb") as f:
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
