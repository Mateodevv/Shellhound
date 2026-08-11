"""Merge Cosmic Ray shard reports into one prioritized Markdown worklist."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path


_TOTAL = re.compile(r"^total jobs:\s*(\d+)", re.M)
_COMPLETE = re.compile(r"^complete:\s*(\d+)", re.M)
_SURVIVING = re.compile(r"^surviving mutants:\s*(\d+)", re.M)

P0 = {"server/app.py", "server/engines/logindex.py",
      "server/engines/sqldump.py", "server/db.py", "server/iocs.py",
      "server/workspace.py", "server/case_report.py", "server/correlation.py"}
P1_PREFIXES = ("server/chain.py", "server/coverage.py", "server/engines/",
               "server/patterns.py", "server/sigma.py")


def priority(module: str) -> str:
    if module in P0:
        return "P0"
    if module.startswith(P1_PREFIXES):
        return "P1"
    return "P2"


def parse_report(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    total_match = _TOTAL.search(text)
    complete_match = _COMPLETE.search(text)
    surviving_match = _SURVIVING.search(text)
    total = int(total_match.group(1)) if total_match else 0
    complete = int(complete_match.group(1)) if complete_match else 0
    surviving = int(surviving_match.group(1)) if surviving_match else 0
    modules = Counter()
    lines = iter(text.splitlines())
    for line in lines:
        if not line.startswith("[job-id]"):
            continue
        mutation = next(lines, "").strip()
        if mutation.startswith("server/"):
            modules[mutation.split()[0]] += 1
    shard = path.stem.removeprefix("survivors-")
    pri = min((priority(module) for module in modules), default="P2")
    return {"shard": shard, "total": total, "complete": complete,
            "surviving": surviving, "modules": modules, "priority": pri}


def summarize(folder: Path) -> str:
    reports = [parse_report(path)
               for path in sorted(folder.rglob("survivors-*.txt"))]
    if not reports:
        raise FileNotFoundError("no survivors-*.txt reports found")
    reports.sort(key=lambda row: (
        row["priority"], -row["surviving"], row["shard"]))
    out = [
        "# Mutation triage", "",
        "Survivors are leads, not an automatic failure. Classify each as a "
        "real test gap, an equivalent mutant, or an invalid mutation.", "",
        "| Priority | Shard | Complete | Survivors | State |",
        "|---|---|---:|---:|---|",
    ]
    all_modules = Counter()
    for row in reports:
        state = ("complete" if row["complete"] == row["total"]
                 and row["total"] else "PARTIAL")
        out.append(
            f"| {row['priority']} | {row['shard']} | "
            f"{row['complete']}/{row['total']} | {row['surviving']} | {state} |")
        all_modules.update(row["modules"])
    out.extend(["", "## Worklist", "",
                "| Priority | Module | Survivors |", "|---|---|---:|"])
    for module, count in sorted(
            all_modules.items(),
            key=lambda item: (priority(item[0]), -item[1], item[0])):
        out.append(f"| {priority(module)} | `{module}` | {count} |")
    partial = [row["shard"] for row in reports
               if row["complete"] != row["total"]]
    if partial:
        out.extend([
            "", "> Incomplete shards: " + ", ".join(partial) +
            ". Their survivor counts are lower bounds, not scores."])
    out.append("")
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("folder", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    text = summarize(args.folder)
    args.output.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
