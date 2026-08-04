# server/engines/webrootdiff.py
"""Webroot gegen eine Referenzkopie vergleichen.

Die klassische Handarbeit nach jedem Webserver-Vorfall: das kompromittierte
Webroot neben ein sauberes Release derselben CMS-Version legen und fragen,
was ABWEICHT. Drei Antworten sind möglich, und jede bedeutet etwas anderes:

    extra     -- liegt nur im Webroot. Hochgeladen, generiert oder Teil der
                 Installation, die die Referenz nicht abdeckt. Hier wohnen
                 die abgelegten Shells.
    modified  -- in beiden, aber verschieden. Hier wohnt der eingeschleuste
                 Code in legitimen Dateien.
    missing   -- liegt nur in der Referenz. Gelöschte Kern-Dateien sind
                 selten Angriff, aber oft Spur eines Aufräumversuchs.

WAS DER VERGLEICH NICHT SAGT: Ein `extra` ist kein Fund, sondern ein
Kandidat -- jedes Upload-Verzeichnis ist voller legitimer Extras. Der
Vergleich verkleinert den Heuhaufen, die Bewertung bleibt beim Analysten.

Verglichen wird über SHA-256, aber nur wo nötig: unterschiedliche Größe IST
Verschiedenheit, da braucht niemand einen Hash. Dateien über der Hash-Grenze
mit GLEICHER Größe werden als `too_big` gemeldet statt still als gleich
durchgewunken -- »nicht geprüft« ist eine andere Aussage als »gleich«."""
import hashlib
import os

from server import db

# Bis zu dieser Größe wird gehasht. Darüber entscheidet die Größe allein --
# und Gleichstand wird gemeldet, nicht behauptet.
HASH_CAP = 32 * 1024 * 1024

# Mehr Abweichungen speichert ein Lauf nicht. Wer 100.000 Unterschiede hat,
# vergleicht die falschen Bäume (andere CMS-Version, falscher Ordner) -- das
# sagt die Zusammenfassung dann auch.
ROW_CAP = 20000


def _walk(root):
    """rel_path (mit /) -> Größe. Symlinks werden nicht verfolgt: eine
    Kopie aus der Forensik soll keine Schleifen enthalten, und wenn doch,
    gehört ihr Ziel nicht zum Baum."""
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
    """Der Vergleich als Job. Ergebnis landet in webroot_diff (ersetzt den
    vorherigen Lauf) und als Zusammenfassung in den Job-Stats."""
    ctx.progress(0.02, "Webroot einlesen…")
    left = _walk(webroot_path)
    if ctx.cancelled():
        return {"cancelled": True}
    ctx.progress(0.15, "Referenz einlesen…")
    right = _walk(reference_path)
    if ctx.cancelled():
        return {"cancelled": True}

    rows = []          # (status, path, size, ref_size)
    counts = {"extra": 0, "missing": 0, "modified": 0, "too_big": 0}
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

    # Gleicher Pfad, beide vorhanden: erst die Größe (kostenlos), dann der
    # Hash (teuer, deshalb mit Fortschritt -- das hier ist der lange Teil).
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

    ctx.progress(0.97, "Ergebnis speichern…")
    conn = db.connect(ctx.case_dir)
    try:
        # Ein Lauf ersetzt den vorherigen: das Ergebnis ist eine ABLEITUNG
        # aus zwei Bäumen, keine Historie -- wer den alten Stand braucht,
        # hat ihn im Fall-Archiv.
        conn.execute("DELETE FROM webroot_diff")
        conn.executemany(
            "INSERT INTO webroot_diff (webroot_id, reference_id, status,"
            " path, size, ref_size, ran_at) VALUES (?,?,?,?,?,?,?)",
            [(webroot_id, reference_id, status, path, size, ref_size, db.now())
             for status, path, size, ref_size in rows])
        conn.commit()
    finally:
        conn.close()

    return {"files_webroot": len(left), "files_reference": len(right),
            "identical": len(same_size) - sum(
                1 for s, *_ in rows if s in ("modified", "too_big")),
            **counts, "truncated": truncated}
