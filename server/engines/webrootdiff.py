# server/engines/webrootdiff.py
"""Compare a webroot against a reference copy.

The classic manual work after every web server incident: put the compromised
webroot next to a clean release of the same CMS version and ask what DEVIATES.
Three answers are possible, and each means something different:

    extra     -- only in the webroot. Uploaded, generated, or part of the
                 installation the reference does not cover. This is where the
                 dropped shells live.
    modified  -- in both, but different. This is where injected code in
                 legitimate files lives.
    missing   -- only in the reference. Deleted core files are rarely an
                 attack, but often the trace of a cleanup attempt.

WHAT THE COMPARISON DOES NOT SAY: an `extra` is not a find but a candidate --
every upload directory is full of legitimate extras. The comparison shrinks
the haystack, the assessment stays with the analyst.

Comparison is by SHA-256, but only where needed: a different size IS a
difference, nobody needs a hash for that. Files above the hashing limit with
the SAME size are reported as `too_big` rather than silently waved through as
identical -- "not checked" is a different statement from "identical"."""
import hashlib
import os

from server import db

# Files up to this size are hashed. Above it the size alone decides -- and a
# tie is reported, not claimed.
HASH_CAP = 32 * 1024 * 1024

# A run stores no more deviations than this. Whoever has 100,000 differences
# is comparing the wrong trees (different CMS version, wrong folder) -- and
# the summary says so.
ROW_CAP = 20000


def _walk(root):
    """rel_path (with /) -> size. Symlinks are not followed: a forensic copy
    should contain no loops, and if it does, their target does not belong to
    the tree."""
    out = {}
    base = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames.sort()
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            try:
                size = os.stat(full).st_size
            except OSError:
                continue
            rel = os.path.relpath(full, base).replace("\\", "/")
            out[rel] = size
    return out


def _sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None


def run(ctx, webroot_id, webroot_path, reference_id, reference_path):
    """The comparison as a job. The result lands in webroot_diff (replacing
    the previous run) and as a summary in the job stats."""
    ctx.progress(0.02, "Reading webroot…")
    left = _walk(webroot_path)
    if ctx.cancelled():
        return {"cancelled": True}
    ctx.progress(0.15, "Reading reference…")
    right = _walk(reference_path)
    if ctx.cancelled():
        return {"cancelled": True}

    rows = []          # (status, path, size, ref_size)
    counts = {"extra": 0, "missing": 0, "modified": 0, "too_big": 0,
              # Of the modified ones, how many came out of the
              # same-size set -- the only ones `identical` may
              # be reduced by.
              "modified_same_size": 0}
    truncated = False

    def keep(status, path, size, ref_size):
        nonlocal truncated
        counts[status] += 1
        if len(rows) < ROW_CAP:
            rows.append((status, path, size, ref_size))
        else:
            truncated = True

    for rel in sorted(set(left) - set(right)):
        keep("extra", rel, left[rel], 0)
    for rel in sorted(set(right) - set(left)):
        keep("missing", rel, 0, right[rel])

    # Same path, both present: first the size (free), then the hash
    # (expensive, hence with progress -- this is the long part).
    both = sorted(set(left) & set(right))
    same_size = [rel for rel in both if left[rel] == right[rel]]
    for rel in both:
        if left[rel] != right[rel]:
            keep("modified", rel, left[rel], right[rel])
    for i, rel in enumerate(same_size):
        if ctx.cancelled():
            return {"cancelled": True}
        if i % 200 == 0:
            ctx.progress(0.2 + 0.75 * i / max(1, len(same_size)),
                         f"Inhalte vergleichen… {i}/{len(same_size)}")
        if left[rel] > HASH_CAP:
            keep("too_big", rel, left[rel], right[rel])
            continue
        a = _sha256(os.path.join(webroot_path, rel))
        b = _sha256(os.path.join(reference_path, rel))
        if a is None or b is None or a != b:
            keep("modified", rel, left[rel], right[rel])
            counts["modified_same_size"] += 1

    ctx.progress(0.97, "Storing result…")
    conn = db.connect(ctx.case_dir)
    try:
        # A run replaces the previous one: the result is a DERIVATION from
        # two trees, not a history -- whoever needs the old state has it in
        # the case archive.
        conn.execute("DELETE FROM webroot_diff")
        conn.executemany(
            "INSERT INTO webroot_diff (webroot_id, reference_id, status,"
            " path, size, ref_size, ran_at) VALUES (?,?,?,?,?,?,?)",
            [(webroot_id, reference_id, status, path, size, ref_size, db.now())
             for status, path, size, ref_size in rows])
        conn.commit()
    finally:
        conn.close()

    # COUNTED, NOT SUBTRACTED. `modified` is produced in two places -- once
    # for files whose SIZE differs, which were never in `same_size`, and once
    # after hashing files that were. Subtracting all of them from
    # len(same_size) therefore took off rows that had never been added, and
    # with more size-differing files than same-size ones the count went
    # negative. It also read from `rows`, which is capped, while len(same_size)
    # is not.
    identical = len(same_size) - counts["modified_same_size"] - counts["too_big"]
    return {"files_webroot": len(left), "files_reference": len(right),
            "identical": max(0, identical),
            **{k: v for k, v in counts.items() if k != "modified_same_size"},
            "truncated": truncated}
