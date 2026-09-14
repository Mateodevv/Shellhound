"""Harmless, repeatable CMS workflow evidence; never contains executable attacks."""
from pathlib import Path

IP = "198.51.100.42"
CVE = "CVE-2026-12345"


def create(root):
    root = Path(root)
    site = root / "evidence" / "CMS with spaces"
    site.mkdir(parents=True)
    files = {}
    for name, marker in (("review.txt", "QA_REVIEW_MARKER"),
                         ("dropper.txt", "QA_DROPPER_MARKER"),
                         ("ordinary.txt", "Ordinary reference document")):
        path = site / name
        path.write_text(marker + "\nInert acceptance evidence only.\n", encoding="utf-8")
        files[name] = path
    logs = root / "evidence" / "access.log"
    logs.write_text(
        f'{IP} - - [12/Sep/2026:10:00:00 +0000] "GET /review.txt HTTP/1.1" 200 42 "-" "QA"\n'
        '203.0.113.10 - - [12/Sep/2026:10:01:00 +0000] "GET /ordinary.txt HTTP/1.1" 200 42 "-" "QA"\n',
        encoding="utf-8")
    dump = root / "evidence" / "database.sql"
    dump.write_text("CREATE TABLE cms_users (id int, username varchar(50), email varchar(100));\n"
                    "INSERT INTO cms_users VALUES (1,'qa-user','qa@example.test');\n", encoding="utf-8")
    ws = root / "workspace"
    rules = ws / "yara"
    rules.mkdir(parents=True)
    (rules / "acceptance.yar").write_text('''
rule QA_Review { strings: $marker = "QA_REVIEW_MARKER" condition: $marker }
rule QA_Review_Second_Observation { strings: $marker = "QA_REVIEW_MARKER" condition: $marker }
rule QA_Dropper { strings: $marker = "QA_DROPPER_MARKER" condition: $marker }
''', encoding="utf-8")
    return {"workspace": ws, "site": site, "logs": logs, "dump": dump, "files": files}
