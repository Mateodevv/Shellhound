# tests/test_jobs.py
"""The live job registry across two open cases.

Regression guard: a job id is a rowid in ONE case database, so two cases both
hand out 1, 2, 3. Keyed by that id alone, the registry let case B evict case
A's entry -- `cancel` then stopped the wrong job and `wait_for` reported "all
quiet" while an engine in the other case was still writing. Closing a case in
that state packs a half-written database.
"""
import tempfile
import threading
import unittest
from pathlib import Path

from server import db
from server.jobs import JobManager


class RegistryTests(unittest.TestCase):

    def setUp(self):
        self.a = Path(tempfile.mkdtemp(prefix="shellhound-job-a-"))
        self.b = Path(tempfile.mkdtemp(prefix="shellhound-job-b-"))
        for case in (self.a, self.b):
            db.connect(case).close()
        self.manager = JobManager()
        # Every job blocks here until the test releases it, so both are live
        # at the same time -- which is the whole point.
        self.release = threading.Event()
        self.running = threading.Event()

    def tearDown(self):
        self.release.set()
        self.manager.pool.shutdown(wait=True)

    def _blocking_job(self, ctx):
        self.running.set()
        self.release.wait(timeout=10)
        return {}

    def test_two_cases_get_the_same_job_id(self):
        """The premise of the bug -- if this ever stops holding, the guard
        below stops guarding anything."""
        first = self.manager.submit(self.a, "test", self._blocking_job)
        second = self.manager.submit(self.b, "test", self._blocking_job)
        self.assertEqual(first, second,
                         "job ids are per case; the collision is expected")

    def test_both_cases_stay_in_the_registry(self):
        job_a = self.manager.submit(self.a, "test", self._blocking_job)
        job_b = self.manager.submit(self.b, "test", self._blocking_job)
        self.assertIn((str(self.a), job_a), self.manager.live)
        self.assertIn((str(self.b), job_b), self.manager.live,
                      "the second case must not evict the first")
        self.assertEqual(2, len(self.manager.live))

    def test_cancel_only_touches_its_own_case(self):
        job_a = self.manager.submit(self.a, "test", self._blocking_job)
        job_b = self.manager.submit(self.b, "test", self._blocking_job)
        self.assertTrue(self.manager.cancel(self.a, job_a))
        self.assertTrue(self.manager.live[(str(self.a), job_a)].cancelled())
        self.assertFalse(self.manager.live[(str(self.b), job_b)].cancelled(),
                         "cancelling in one case cancelled the other")

    def test_a_finished_job_does_not_clear_the_other_case(self):
        """The dangerous half, in full.

        `archive` waits for the jobs of ITS case. Case B finishes and removes
        its entry -- under a shared key that took case A's still-running job
        with it, the wait returned "all quiet" and the case was packed while
        an engine was still writing into it."""
        job_a = self.manager.submit(self.a, "test", self._blocking_job)
        done = threading.Event()

        def quick(ctx):
            done.set()
            return {}

        job_b = self.manager.submit(self.b, "test", quick)
        self.assertEqual(job_a, job_b, "the ids have to collide for this test")
        self.assertTrue(done.wait(timeout=5))
        self.manager.wait_for(self.b, [job_b], timeout=5)

        still = self.manager.wait_for(self.a, [job_a], timeout=0.5)
        self.assertEqual([job_a], still,
                         "case A is still running and must be reported")

    def test_a_finished_job_leaves_the_registry(self):
        self.release.set()
        job = self.manager.submit(self.a, "test", self._blocking_job)
        self.assertEqual([], self.manager.wait_for(self.a, [job], timeout=5))
        self.assertNotIn((str(self.a), job), self.manager.live)


if __name__ == "__main__":
    unittest.main()
