"""Read one recorded table row from an SQL export without executing SQL.

The scanner records a table's one-based INSERT row ordinal, not a physical
line number. Reuse its tokenizer and value decoder so opening a finding uses
the same row identity, including rows spread over multiple INSERT statements.
"""

import json
import lzma
import re
import time
import hashlib

from server.engines.fsutil import open_text_auto
from server.engines.sqldump import (
    INSERT_RE, insert_columns, iter_statements, parse_create, split_rows,
    evaluate_row, row_digest, validate_insert_values,
)


MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_STATEMENT_BYTES = 16 * 1024 * 1024
MAX_READ_SECONDS = 10
MAX_ROW_BYTES = 64 * 1024
MAX_CELL_BYTES = 8 * 1024
FIELD_PAGE_CHARACTERS = 8192
MAX_MATCH_CONTEXT = 1024
MAX_MATCHES = 64
_CHUNK_SIZE = 64 * 1024
_TABLE_NAME = re.compile(r"[A-Za-z0-9_$#]{1,256}\Z")


class RowReadError(ValueError):
    """A safe, user-facing explanation for an unavailable row preview."""


class _BoundedReader:
    """Guard the existing tokenizer before it can accumulate a huge statement.

    Quote handling deliberately follows ``iter_statements``. Limits apply to
    decoded UTF-8 bytes, including compressed exports, not the archive's size.
    The time limit is checked between bounded reads and parser operations.
    """

    def __init__(self, stream):
        self.stream = stream
        self.deadline = time.monotonic() + MAX_READ_SECONDS
        self.total = 0
        self.statement_bytes = 0
        self.in_string = False
        self.escape = False

    def check_time(self):
        if time.monotonic() > self.deadline:
            raise RowReadError(
                "This row takes too long to locate in the export. "
                "Open the original export in a database viewer to inspect it.")

    def _count_statement(self, part):
        self.statement_bytes += len(part.encode("utf-8"))
        if self.statement_bytes > MAX_STATEMENT_BYTES:
            raise RowReadError(
                "An SQL statement is too large for the row preview. "
                "Open the original export in a database viewer to inspect it.")

    def read(self, size):
        self.check_time()
        chunk = self.stream.read(min(size, _CHUNK_SIZE))
        self.check_time()
        self.total += len(chunk.encode("utf-8"))
        if self.total > MAX_INPUT_BYTES:
            raise RowReadError(
                "The row was not reached within the export preview read limit. "
                "Open the original export in a database viewer to inspect it.")
        start = 0
        for i, char in enumerate(chunk):
            if self.escape:
                self.escape = False
            elif self.in_string:
                if char == "\\":
                    self.escape = True
                elif char == "'":
                    self.in_string = False
            elif char == "'":
                self.in_string = True
            elif char == ";":
                self._count_statement(chunk[start:i + 1])
                self.statement_bytes = 0
                start = i + 1
        self._count_statement(chunk[start:])
        return chunk


def _check_complete_values(values):
    """Do not present a partial row from a damaged INSERT as complete."""
    try:
        validate_insert_values(values)
    except ValueError as error:
        raise RowReadError(str(error)) from error


def _clip(text, limit):
    encoded = text.encode("utf-8")
    return encoded[:max(0, limit)].decode("utf-8", errors="ignore")


def _json_size(value):
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8"))


def _preview(table, row_number, names, values, indexed=False):
    result = {"table": table, "row": row_number, "columns": [], "truncated": False}
    size = _json_size(result)
    for i, value in enumerate(values):
        original_name = names[i] if i < len(names) else f"col{i + 1}"
        name = _clip(original_name, 256)
        clipped = _clip(value, MAX_CELL_BYTES) if value is not None else None
        column = {"name": name, "value": clipped,
                  "truncated": clipped != value or name != original_name}
        if indexed:
            column["index"] = i
        available = MAX_ROW_BYTES - size - (2 if result["columns"] else 0)
        if _json_size(column) > available:
            column["truncated"] = True
            if clipped is not None:
                # JSON escaping may cost more than the displayed text. Fit the
                # serialized value as well as limiting each decoded cell.
                low, high = 0, len(clipped)
                while low < high:
                    middle = (low + high + 1) // 2
                    column["value"] = clipped[:middle]
                    if _json_size(column) <= available:
                        low = middle
                    else:
                        high = middle - 1
                column["value"] = clipped[:low]
            if _json_size(column) > available:
                result["truncated"] = True
                break
        result["columns"].append(column)
        size += _json_size(column) + (2 if len(result["columns"]) > 1 else 0)
        result["truncated"] |= column["truncated"]
    if len(result["columns"]) < len(values):
        result["truncated"] = True
    return result


def read_database_record(path, table, row):
    """Read the full decoded record under the existing input/time limits.

    The caller must resolve the export from case-owned metadata and enforce
    evidence scope before calling this helper. No statements are executed.
    """
    if not isinstance(table, str) or not _TABLE_NAME.fullmatch(table):
        raise RowReadError("The requested database table name is invalid.")
    if not isinstance(row, int) or isinstance(row, bool) or row < 1:
        raise RowReadError("The requested database row must be a positive whole number.")
    names = []
    rows_seen = 0
    try:
        with open_text_auto(path) as stream:
            reader = _BoundedReader(stream)
            for statement in iter_statements(reader, chunk_size=_CHUNK_SIZE):
                reader.check_time()
                created = parse_create(statement)
                if created:
                    if created[0] == table:
                        names = [name for name, _kind in created[1]]
                    continue
                match = INSERT_RE.search(statement)
                if match is None or match.group("table") != table:
                    continue
                values_text = statement[match.end():]
                _check_complete_values(values_text)
                rows = split_rows(values_text)
                reader.check_time()
                if not rows:
                    raise RowReadError(
                        "The requested table contains an unreadable INSERT. "
                        "Check the original database export.")
                # An explicit list belongs to this INSERT, and may reorder or
                # omit columns compared with the table's CREATE statement.
                row_names = insert_columns(match) or names
                if not names:
                    names = row_names or [f"col{i + 1}" for i in range(len(rows[0]))]
                    row_names = names
                if rows_seen + len(rows) >= row:
                    values = rows[row - rows_seen - 1]
                    result = ([row_names[i] if i < len(row_names) else f"col{i + 1}"
                               for i in range(len(values))], values)
                    reader.check_time()
                    return result
                rows_seen += len(rows)
    except (OSError, EOFError, lzma.LZMAError, UnicodeError) as exc:
        raise RowReadError(
            "The database export could not be read. Check that its evidence "
            "file is available and, if compressed, that the archive is intact.") from exc
    raise RowReadError(
        "The recorded row was not found in this table's INSERT data. "
        "The export may have changed since analysis; check the original evidence.")


def read_database_row(path, table, row):
    """Backward-compatible bounded preview for existing local callers."""
    names, values = read_database_record(path, table, row)
    return _preview(table, row, names, values)


def record_version(dump_path, table_id, table, row, names, values):
    identity = [str(dump_path), table_id, table, row, row_digest(names, values)]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def _match_context(index, names, values, start, end):
    value = values[index]
    lo = max(0, start - 160)
    hi = min(len(value), end + 160, lo + MAX_MATCH_CONTEXT)
    return {"column_index": index, "column_name": _clip(names[index], 256),
            "start": start, "end": end, "before": value[lo:start],
            "text": value[start:min(end, hi)], "after": value[min(end, hi):hi]}


def finding_match(conn, finding, dump_path, names, values):
    """Historical spans require the same decoded row; legacy checks write nothing."""
    from server import db
    from server.engines import sqldump

    observations = db.rows(conn,
        "SELECT * FROM sql_finding_observations WHERE finding_fingerprint=? "
        "ORDER BY dump_path,column_index", (finding["fingerprint"],))
    sources = db.rows(conn,
        "SELECT DISTINCT o.dump_path,d.id AS dump_id,t.id AS table_id "
        "FROM sql_finding_observations o LEFT JOIN db_dumps d ON d.path=o.dump_path "
        "LEFT JOIN db_tables t ON t.dump_id=d.id AND t.name=? "
        "WHERE o.finding_fingerprint=? ORDER BY o.dump_path LIMIT 64",
        (finding["artifact"], finding["fingerprint"]))
    result = {"state": "not_observed", "matches": [], "sources": sources}
    if observations:
        selected = [item for item in observations if item["dump_path"] == str(dump_path)]
        if not selected:
            return result
        digest = row_digest(names, values)
        if any(item["row_sha256"] != digest for item in selected):
            result["state"] = "changed"
            return result
        result["state"] = "recorded"
        spans = [(item["column_index"], item["match_start"], item["match_end"])
                 for item in selected]
    else:
        rules = [rule for rule in sqldump.RULES if
                 (rule[0] == finding["rule_id"] if finding["rule_id"] else
                  rule[2] == finding["rule"])]
        if not rules:
            result["state"] = "rule_unavailable"
            return result
        spans = [(index, start, end) for index, _rid, _severity, _rule, start, end
                 in evaluate_row(values, rules)]
        result["state"] = "current" if spans else "not_found"
    valid = [(index, start, end) for index, start, end in spans
             if 0 <= index < len(values) and isinstance(values[index], str)
             and 0 <= start <= end <= len(values[index])]
    if len(valid) != len(spans):
        result["state"] = "changed"
        return result
    result["matches"] = [_match_context(index, names, values, start, end)
                         for index, start, end in valid[:MAX_MATCHES]]
    result["matches_truncated"] = len(valid) > MAX_MATCHES
    return result


def database_record_preview(table, row, names, values):
    return _preview(table, row, names, values, indexed=True)


def field_page(names, values, column_index, offset, matches=None):
    if (not isinstance(column_index, int) or isinstance(column_index, bool)
            or not 0 <= column_index < len(values)):
        raise RowReadError("The requested database column is invalid.")
    value = values[column_index]
    length = len(value) if value is not None else 0
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= length:
        raise RowReadError("The requested field offset is outside this value.")
    end = min(length, offset + FIELD_PAGE_CHARACTERS)
    page = value[offset:end] if value is not None else None
    result = {"column_index": column_index, "column_name": _clip(names[column_index], 256),
              "value": page, "offset": offset, "next_offset": end if end < length else None,
              "total_characters": length}
    for match in matches or []:
        if (match["column_index"] == column_index and match["start"] < end
                and match["end"] > offset):
            start, stop = max(offset, match["start"]) - offset, min(end, match["end"]) - offset
            result["highlight"] = {"before": page[:start], "text": page[start:stop],
                                   "after": page[stop:]}
            break
    return result
