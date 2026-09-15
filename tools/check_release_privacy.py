"""Bounded, offline release privacy checks. Never print matched values or paths.

This structural check complements Gitleaks and human review; it does not prove
that prose, screenshots or arbitrary encoded text contain no personal data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath

MAX_ENTRY_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 20000
CATALOG = "tools/reviewed_assets.json"
PRIVATE_DIRS = {".git", ".shellhound", ".venv", "venv", "node_modules",
                ".codex", ".claude", "workspace", "workspaces", "cases",
                "shellhoundcases", "evidence", "test_case_data", "testdata",
                "real-world-data", "archive", "remediation"}
PRIVATE_PREFIXES = ("privacy-audit", "private-audit", "shellhoundcases-")
DATA_SUFFIXES = (".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3", ".sql",
                 ".dump", ".log", ".log.gz", ".log.bz2", ".sql.gz", ".sql.bz2")
ARCHIVE_SUFFIXES = (".zip", ".whl", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar")
REVIEW_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif",
                   ".tiff", ".ico", ".avif", ".woff", ".woff2", ".ttf", ".otf"}
GITHUB_NOREPLY = re.compile(r"(?:[0-9]+\+)?[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?@users\.noreply\.github\.com\Z")
TECHNICAL_IDENTITIES = {("Codex", "codex@openai.com"),
                        ("Codi", "codi@localhost"), ("GitHub", "noreply@github.com")}


@dataclass
class Violation:
    kind: str
    index: int
    path: str = ""  # Private details only; never emitted to standard output.
    container: str = ""


@dataclass
class Result:
    entries: int = 0
    skipped_sparse: int = 0
    violations: list[Violation] = field(default_factory=list)

    def reject(self, kind: str, index: int, path: str = "", container: str = ""):
        self.violations.append(Violation(kind, index, path, container))


def safe_parts(name: str) -> tuple[str, ...] | None:
    if (not name or any(ord(char) < 32 for char in name)
            or name.startswith(("/", "\\")) or PureWindowsPath(name).drive):
        return None
    parts = name.replace("\\", "/").split("/")
    if any(part == ".." or ":" in part or (part not in ("", ".") and part.rstrip(" .") != part)
           for part in parts):
        return None
    return tuple(part for part in parts if part not in ("", ".")) or None


def path_violation(name: str, *, archive: bool = False) -> str | None:
    parts = safe_parts(name)
    if parts is None:
        return "unsafe-path"
    lower = tuple(part.casefold() for part in parts)
    # Last part may be a directory entry too: private directories are forbidden anywhere.
    if any(part in PRIVATE_DIRS or part.startswith(PRIVATE_PREFIXES) for part in lower):
        return "private-directory"
    base = lower[-1]
    if (base == "settings.json" or base.startswith("settings.json.")
            or base in {"case.json", "case_summary.json", "secrets.json", "token.txt"}
            or (base.startswith(".env") and base != ".env.example")
            or base.endswith((".pem", ".key", ".p12", ".pfx"))):
        return "runtime-or-secret-file"
    if (base.endswith(DATA_SUFFIXES) or re.search(r"\.log\.\d+(?:\.gz|\.bz2)?$", base)):
        return "case-or-log-data"
    if base.endswith(ARCHIVE_SUFFIXES):
        return "nested-archive"
    if not archive and (lower[0] in {"build", "dist"}
                        or lower[:2] in {("web", "dist"), ("server", "static")}):
        return "generated-source-output"
    return None


def load_catalog(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("assets"), list):
        raise ValueError("invalid catalog")
    result = {}
    for asset in data["assets"]:
        name, digest = asset["path"], asset["sha256"]
        if (not isinstance(name, str) or safe_parts(name) is None
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or name in result or not asset.get("review")):
            raise ValueError("invalid catalog asset")
        result[name] = digest
    return result


def asset_name(name: str, *, archive: bool) -> str:
    parts = safe_parts(name)
    if parts is None:
        return name
    if archive and parts[0].startswith("shellhound-"):
        parts = parts[1:]  # Standard sdist root; wheel paths have no extra root.
    if archive and parts[:2] == ("server", "static"):
        parts = ("web", "public", *parts[2:])
    return "/".join(parts)


def content_violation(name: str, data: bytes, catalog: dict[str, str], *, archive: bool = False) -> str | None:
    if data.startswith(b"SQLite format 3\x00"):
        return "sqlite-content"
    if (data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b",
                         b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07"))
            or data[257:262] == b"ustar"):
        return "archive-content"
    try:
        data.decode("utf-8")
        binary = b"\x00" in data
    except UnicodeDecodeError:
        binary = True
    if binary or PurePosixPath(name).suffix.casefold() in REVIEW_SUFFIXES:
        key = asset_name(name, archive=archive)
        if catalog.get(key) != hashlib.sha256(data).hexdigest():
            return "unreviewed-binary-asset"
    return None


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ValueError("git query failed")
    return result.stdout


def check_source(root: Path, catalog: dict[str, str]) -> Result:
    root = root.resolve()
    result = Result()
    total = 0
    for raw in _git(root, "ls-files", "-v", "--stage", "-z").split(b"\x00"):
        if not raw:
            continue
        result.entries += 1
        index = result.entries
        if index > MAX_ENTRIES:
            result.reject("entry-limit", index)
            break
        try:
            meta, name = raw.decode("utf-8").split("\t", 1)
            tag, mode, _oid, stage = meta.split()
        except (ValueError, UnicodeError):
            result.reject("invalid-git-entry", index)
            continue
        issue = path_violation(name)
        if issue:
            result.reject(issue, index, name)
            continue
        if mode in {"120000", "160000"}:
            result.reject("linked-source-entry", index, name)
            continue
        if stage != "0":
            result.reject("unmerged-source-entry", index, name)
            continue
        file = root / name
        if not file.exists() and tag.upper() == "S":
            result.skipped_sparse += 1
            continue  # Do not materialize intentionally excluded payload fixtures.
        try:
            if file.is_symlink() or not file.resolve().is_relative_to(root):
                result.reject("linked-source-entry", index, name)
                continue
            size = file.stat().st_size
            total += size
            if size > MAX_ENTRY_BYTES or total > MAX_TOTAL_BYTES:
                result.reject("size-limit", index, name)
                continue
            data = file.read_bytes()
        except OSError:
            result.reject("unreadable-source-entry", index, name)
            continue
        issue = content_violation(name, data, catalog)
        if issue:
            result.reject(issue, index, name)
    return result


def check_archive(path: Path, catalog: dict[str, str]) -> Result:
    result = Result()
    total = 0
    seen = set()

    def inspect(name, size, directory, linked, reader):
        nonlocal total
        result.entries += 1
        index = result.entries
        if index > MAX_ENTRIES:
            raise ValueError("entry limit")
        issue = path_violation(name, archive=True)
        normalized = "/".join(safe_parts(name) or ()).casefold()
        if issue:
            result.reject(issue, index, name, str(path))
            return
        if normalized in seen:
            result.reject("duplicate-archive-entry", index, name, str(path))
            return
        seen.add(normalized)
        if linked:
            result.reject("linked-or-special-entry", index, name, str(path))
            return
        if directory:
            return
        total += size
        if size < 0 or size > MAX_ENTRY_BYTES or total > MAX_TOTAL_BYTES:
            result.reject("size-limit", index, name, str(path))
            return
        with reader() as handle:
            data = handle.read(MAX_ENTRY_BYTES + 1)
        if len(data) != size or len(data) > MAX_ENTRY_BYTES:
            result.reject("invalid-entry-size", index, name, str(path))
            return
        issue = content_violation(name, data, catalog, archive=True)
        if issue:
            result.reject(issue, index, name, str(path))

    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as package:
                for entry in package.infolist():
                    mode = stat.S_IFMT(entry.external_attr >> 16)
                    inspect(entry.filename, entry.file_size, entry.is_dir(),
                            mode not in (0, stat.S_IFREG, stat.S_IFDIR),
                            lambda entry=entry: package.open(entry))
        else:
            with tarfile.open(path, "r:*") as package:
                for entry in package:
                    inspect(entry.name, entry.size, entry.isdir(),
                            not (entry.isfile() or entry.isdir()),
                            lambda entry=entry: package.extractfile(entry))
    except Exception:
        # Corrupt compression formats must fail closed without a path-bearing traceback.
        result.reject("invalid-or-oversized-archive", result.entries + 1, container=str(path))
    return result


def identity_allowed(name: str, email: str) -> bool:
    return bool(GITHUB_NOREPLY.fullmatch(email)) or (name, email) in TECHNICAL_IDENTITIES


def check_history(root: Path) -> Result:
    result = Result()
    fields = _git(root, "log", "--all", "-z", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce").decode("utf-8").split("\x00")
    if fields and fields[-1] == "":
        fields.pop()
    if len(fields) % 5:
        raise ValueError("invalid history record")
    for offset in range(0, len(fields), 5):
        oid, author, author_email, committer, committer_email = fields[offset:offset + 5]
        result.entries += 1
        for kind, name, email in (("author-email", author, author_email),
                                  ("committer-email", committer, committer_email)):
            if not identity_allowed(name, email):
                result.reject(kind, result.entries, oid)
    tags = _git(root, "for-each-ref", "refs/tags", "--format=%(objectname)%00%(objecttype)%00%(taggername)%00%(taggeremail)")
    for raw in tags.decode("utf-8").splitlines():
        oid, kind, name, email = raw.split("\x00")
        if kind != "tag":
            continue
        result.entries += 1
        if not identity_allowed(name, email.removeprefix("<").removesuffix(">")):
            result.reject("tagger-email", result.entries, oid)
    return result


class QuietParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "Privacy check: invalid-arguments (entry 0)\n")


def main(argv=None) -> int:
    parser = QuietParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    source = sub.add_parser("source", help="Check tracked working-tree entries without materializing sparse files")
    source.add_argument("--root", type=Path, default=Path("."))
    source.add_argument("--history", action="store_true", help="Also require publishable Git identity emails")
    archives = sub.add_parser("archives", help="Check built wheels/sdists in place without extraction")
    archives.add_argument("paths", nargs="+", type=Path)
    for part in (source, archives):
        part.add_argument("--catalog", type=Path, help="Reviewed asset catalog (defaults to tools/reviewed_assets.json)")
        part.add_argument("--details", type=Path, help="Write private local JSON details; never upload this file")
    args = parser.parse_args(argv)
    results = []
    try:
        root = args.root if args.command == "source" else Path(".")
        catalog = load_catalog(args.catalog or root / CATALOG)
        if args.command == "source":
            results.append(check_source(root, catalog))
            if args.history:
                results.append(check_history(root))
        else:
            results.extend(check_archive(path, catalog) for path in args.paths)
    except Exception:
        # No exception text: it can contain a private path or Git identity.
        results.append(Result(violations=[Violation("input-or-catalog-error", 0)]))
    violations = [item for result in results for item in result.violations]
    if args.details:
        try:
            args.details.parent.mkdir(parents=True, exist_ok=True)
            args.details.write_text(json.dumps({"results": [asdict(result) for result in results]}, indent=2), encoding="utf-8")
        except OSError:
            violations.append(Violation("private-report-write-error", 0))
    for item in violations:
        print(f"Privacy check: {item.kind} (entry {item.index})")
    print(f"Privacy check: {sum(result.entries for result in results)} entries; {len(violations)} violations; "
          f"{sum(result.skipped_sparse for result in results)} sparse entries not read.")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
