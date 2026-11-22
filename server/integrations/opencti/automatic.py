"""Coalesce committed finding changes without occupying a local scan worker."""
import threading
from contextlib import contextmanager
from time import monotonic

from server import db, diagnostics, settings, workspace
from server.casework.testcase import is_generated_case
from server.events import hub
from server.jobs import CaseBusy
from server.integrations.opencti import matches, service


def _invalidate(case):
    hub.publish({'type': 'invalidate', 'scope': 'opencti-matches', 'case_slug': case.name})


class _Check:
    def __init__(self, case):
        self.case = case
        self.stop = threading.Event()
        self.last_update = 0

    def cancelled(self):
        return self.stop.is_set()

    def progress(self, _fraction, _message):
        if monotonic() - self.last_update >= 1:
            self.last_update = monotonic()
            _invalidate(self.case)


class AutomaticMatches:
    def __init__(self, root):
        self.root = root
        self.condition = threading.Condition()
        self.destination = None
        self.unsubscribe = None
        self.worker = None
        self.active = None
        self.pending = {}
        self.opened = set()
        self.paused = set()
        self.failures = {}

    def configure(self):
        with self.condition:
            config = settings.opencti_config(self.root)
            destination = (service._destination(config) if config.get('auto_match') is True
                           and config.get('url') and config.get('token') else None)
            if destination == self.destination:
                return
            self._reset()
            self.destination = destination
            if destination:
                self.unsubscribe = db.subscribe_finding_changes(self.changed)

    def _reset(self):
        if self.unsubscribe:
            self.unsubscribe()
            self.unsubscribe = None
        self.destination = None
        self.opened.clear()
        self.pending.clear()
        self.failures.clear()
        if self.active:
            self.active.stop.set()
        self.condition.notify_all()

    def close(self):
        with self.condition:
            self._reset()
            worker = self.worker
        if worker:
            worker.join()

    def opened_case(self, case):
        with self.condition:
            retry_after = self.failures.get(case)
            if case not in self.opened or (retry_after is not None and monotonic() >= retry_after):
                self.changed(case)

    def refresh_open_cases(self):
        with self.condition:
            for case in tuple(self.opened):
                self.changed(case)

    def recheck(self, case, ctx, authority):
        stats = matches.scan(self.root, case, ctx, expected_authority=authority)
        if not stats['cancelled'] and not stats['reason']:
            with self.condition:
                if self.destination == authority:
                    self.failures.pop(case, None)
        _invalidate(case)
        return stats

    def changed(self, case):
        if case.parent != self.root:
            return
        with self.condition:
            if not self.destination or case in self.paused or case in self.pending:
                return
            if case not in self.opened and is_generated_case(case):
                return
            self.opened.add(case)
            # Scanner transactions may publish hundreds of changes in a burst.
            self.pending[case] = max(monotonic() + 0.35, self.failures.get(case, 0))
            if self.worker is None:
                self.worker = threading.Thread(target=self._run, name='opencti-case-matches', daemon=True)
                self.worker.start()
            self.condition.notify_all()

    def status(self, case):
        with self.condition:
            if case in self.failures:
                return 'unavailable'
            if case in self.pending or (self.active and self.active.case == case):
                return 'pending'
            return 'idle'

    @contextmanager
    def suspend(self, case):
        """Keep the worker out of a case while its database is archived or deleted."""
        with self.condition:
            if case in self.paused:
                raise CaseBusy('An operation is already closing this case.')
            self.paused.add(case)
            self.pending.pop(case, None)
            if self.active and self.active.case == case:
                self.active.stop.set()
            if not self.condition.wait_for(lambda: self.active is None or self.active.case != case, timeout=20):
                self.paused.remove(case)
                self.opened.discard(case)
                raise CaseBusy('OpenCTI is finishing its current request. Try again shortly.')
        try:
            yield
        finally:
            with self.condition:
                self.paused.remove(case)
                self.opened.discard(case)
                self.failures.pop(case, None)

    def _run(self):
        while True:
            with self.condition:
                if not self.pending:
                    self.worker = None
                    return
                case = min(self.pending, key=self.pending.get)
                delay = self.pending[case] - monotonic()
                if delay > 0:
                    self.condition.wait(delay)
                    continue
                del self.pending[case]
                destination = self.destination
                check = self.active = _Check(case)
            failed = False
            try:
                if workspace.resolve_case(self.root, case.name) == case and not is_generated_case(case):
                    stats = matches.scan(self.root, case, check, expected_authority=destination, only_new=True)
                    failed = bool(stats.get('failed'))
            except Exception as exc:
                failed = True
                diagnostics.record(self.root, 'warning', 'opencti', 'Automatic matching unavailable', kind=type(exc).__name__)
            finally:
                with self.condition:
                    if not check.cancelled() and destination == self.destination:
                        if failed:
                            self.failures[case] = monotonic() + 30
                            if case in self.pending:
                                self.pending[case] = self.failures[case]
                        else:
                            self.failures.pop(case, None)
                    self.active = None
                    self.condition.notify_all()
                _invalidate(case)
