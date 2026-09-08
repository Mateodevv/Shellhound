"""Normalize scanner reasons, including the exact formats in older case history.

Only known size-limit messages qualify for acceptance or a size override. A
permission error that happens to mention 'size' must remain an ordinary failure.
"""
import re


_SIZE_REASON = re.compile(
    r"(?:scan error: )?too large for (?:content scan|a YARA scan)"
    r"(?: \((\d+) bytes(?:; limit (\d+) bytes)?\))?")
_GROWTH_REASONS = {
    "file grew beyond the content scan size limit",
    "file grew beyond the YARA scan size limit",
    "scan error: file grew beyond the YARA scan size limit",
}


def classify_skip(reason, category="file"):
    if category not in ("file", "other"):
        return {"group": "other"}
    match = _SIZE_REASON.fullmatch(reason or "")
    if match:
        return {"group": "size_limit",
                "size_bytes": int(match[1]) if match[1] else None,
                "limit_bytes": int(match[2]) if match[2] else 5 * 1024 * 1024}
    if reason in _GROWTH_REASONS:
        return {"group": "size_limit", "size_bytes": None, "limit_bytes": None}
    return {"group": "other"}
