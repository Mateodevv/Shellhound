"""Bind file analysis and its content index to the exact bytes examined."""
import hashlib
import os
import stat

from server import backups, db
from server.paths import io_path


class ScanResult(tuple):
    """Keep the public three-item scanner result while carrying its identity."""
    def __new__(cls, findings, skip_reason, inert, identity=None):
        result = super().__new__(cls, (findings, skip_reason, inert))
        result.identity = identity
        return result


def read_file(path, *, limit=None, keep_content=True, cancelled=None):
    """Read and hash once, rejecting replacement, growth and concurrent edits."""
    before = os.stat(io_path(path))
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('file is no longer a regular file')
    digest = hashlib.sha256()
    chunks = []
    size = 0
    with open(io_path(path), 'rb') as handle:
        opened = os.fstat(handle.fileno())
        while True:
            if cancelled and cancelled():
                raise ValueError('analysis cancelled')
            count = min(1024 * 1024, limit + 1 - size) if limit is not None else 1024 * 1024
            block = handle.read(count)
            if not block:
                break
            size += len(block)
            if limit is not None and size > limit:
                raise ValueError('file grew beyond the content scan size limit')
            digest.update(block)
            if keep_content:
                chunks.append(block)
        after = os.fstat(handle.fileno())
    final = os.stat(io_path(path))
    content = lambda st: (st.st_size, st.st_mtime_ns, st.st_ino)
    if (backups.marker(before) != backups.marker(final)
            or backups.marker(opened) != backups.marker(after)
            or content(final) != content(after) or size != final.st_size):
        raise ValueError('file changed while being read; retry analysis')
    return b''.join(chunks), {'sha256': digest.hexdigest(), 'size': size,
                            'marker': backups.marker(final)}


def unchanged(path, identity):
    try:
        return backups.marker(os.stat(io_path(path))) == identity['marker']
    except OSError:
        return False


def record(conn, engine, path, run, identity, ctx=None):
    """Caller commits this together with findings and file completion."""
    backups.remember(conn, path, identity)
    conn.execute('INSERT OR REPLACE INTO file_scan_receipts '
                 '(engine,artifact,sha256,marker,run,scanned_at,job_id) VALUES (?,?,?,?,?,?,?)',
                 (engine, path, identity['sha256'], identity['marker'], run, db.now(),
                  getattr(ctx, 'job_id', 0)))


def invalidate(conn, engine, path):
    conn.execute('DELETE FROM file_scan_receipts WHERE engine=? AND artifact=?',
                 (engine, path))
