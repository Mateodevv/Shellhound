"""Completion receipts for all engines scheduled against an evidence source."""
import threading


def stats_complete(stats):
    """A returned job is not necessarily a complete scan."""
    return (not any(stats.get(key) for key in ("partial", "skipped", "broken_rules"))
            and stats.get("available") is not False)


class AnalysisReceipts:
    """Non-blocking join: the last successful engine writes the receipt.

    The entire plan is registered before any worker starts. Failed, cancelled
    or partial engines never contribute a success, so incremental retries can
    still select the evidence. No worker waits for a queued sibling.
    """

    def __init__(self, tasks, evidence, mark_scanned):
        self.required = {}
        for engine, _fn, kinds in tasks:
            for kind in kinds:
                self.required.setdefault(kind, set()).add(engine)
        self.evidence = evidence
        self.mark_scanned = mark_scanned
        self.finished = {}
        self.marked = set()
        self.lock = threading.Lock()

    def wrap(self, engine, fn):
        def run(ctx):
            stats = fn(ctx) or {}
            if ctx.cancelled() or not stats_complete(stats):
                return stats
            with self.lock:
                self.finished[engine] = (stats, ctx)
                for kind, required in self.required.items():
                    if kind in self.marked or not required.issubset(self.finished):
                        continue
                    if any(self.finished[name][1].cancelled() for name in required):
                        continue
                    primary = {"webroot": "webshell", "access_logs": "index_logs",
                               "sql_dump": "sqldb"}[kind]
                    receipt = dict(self.finished[primary][0])
                    receipt["engines"] = {
                        name: self.finished[name][0] for name in sorted(required)}
                    self.mark_scanned([row["id"] for row in self.evidence[kind]], receipt)
                    self.marked.add(kind)
            return stats
        return run
