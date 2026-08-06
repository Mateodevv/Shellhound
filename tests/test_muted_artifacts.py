# tests/test_muted_artifacts.py
"""What switching a rule off does to the work list.

The point of the switch is that noise goes away, so an artifact whose
findings ALL came from muted rules has to leave the list. Two boundaries make
that safe rather than destructive, and both are what this file guards:

  * A DECIDED ARTIFACT STAYS. Confirmed or reviewed means somebody looked at
    it, and that decision is the analyst's. A muted rule is not a retraction
    -- otherwise switching a rule off could quietly remove a confirmed shell
    from the case.
  * NOTHING IS DELETED. The findings are still in the database with their
    triage; switch the rule back on and everything is where it was.

And the third thing: the list says how many it dropped. A list that shrinks
without saying so is a list nobody can trust.
"""
import tempfile
import unittest
from pathlib import Path

from server import db
from server.artifacts import art_sql


def add(conn, artifact, rule_id, rule="Some rule", severity=db.SEV_HIGH):
    db.upsert_finding(conn, "webshell", severity, rule, "file", artifact,
                      rule_id=rule_id)


def artifacts(conn, muted=(), only_visible=True):
    sql = art_sql(muted)
    clause = "WHERE active > 0 OR triage != 'new'" if only_visible else ""
    return {r["artifact"]: r for r in db.rows(
        conn, f"WITH art AS ({sql}) SELECT * FROM art {clause}")}


class MutedArtifactTests(unittest.TestCase):

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="shellhound-muted-"))
        db.connect(self.case).close()
        self.conn = db.connect(self.case)
        # only a noisy rule
        add(self.conn, "/w/only_noise.php", "webshell.goto")
        # a noisy rule AND a real one
        add(self.conn, "/w/both.php", "webshell.goto")
        add(self.conn, "/w/both.php", "webshell.eval_input", rule="Eval")
        # nothing noisy at all
        add(self.conn, "/w/clean_rule.php", "webshell.eval_input", rule="Eval")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_nothing_is_hidden_while_every_rule_runs(self):
        self.assertEqual(3, len(artifacts(self.conn)))

    def test_an_artifact_with_only_muted_findings_leaves_the_list(self):
        shown = artifacts(self.conn, {"webshell.goto"})
        self.assertNotIn("/w/only_noise.php", shown)

    def test_an_artifact_with_one_live_rule_stays(self):
        """The switch removes noise, not evidence: a file another rule still
        names is still on the list."""
        shown = artifacts(self.conn, {"webshell.goto"})
        self.assertIn("/w/both.php", shown)
        self.assertIn("/w/clean_rule.php", shown)

    def test_it_still_shows_every_finding_of_an_artifact_it_shows(self):
        """Filtering must never hide part of what a decision is based on."""
        shown = artifacts(self.conn, {"webshell.goto"})
        self.assertEqual(2, shown["/w/both.php"]["findings"])
        self.assertEqual(1, shown["/w/both.php"]["active"])

    def test_a_confirmed_artifact_survives_muting_its_only_rule(self):
        """A decision outranks the rule that prompted it. Otherwise
        switching a rule off could quietly drop a confirmed shell."""
        self.conn.execute("UPDATE findings SET triage = 'confirmed' "
                          "WHERE artifact = ?", ("/w/only_noise.php",))
        self.conn.commit()
        self.assertIn("/w/only_noise.php", artifacts(self.conn, {"webshell.goto"}))

    def test_a_reviewed_artifact_survives_too(self):
        self.conn.execute("UPDATE findings SET triage = 'reviewed' "
                          "WHERE artifact = ?", ("/w/only_noise.php",))
        self.conn.commit()
        self.assertIn("/w/only_noise.php", artifacts(self.conn, {"webshell.goto"}))

    def test_nothing_is_deleted(self):
        """Switch the rule back on and the world is as it was."""
        before = artifacts(self.conn)
        artifacts(self.conn, {"webshell.goto"})
        self.assertEqual(set(before), set(artifacts(self.conn)))
        rows = db.rows(self.conn, "SELECT count(*) n FROM findings")
        self.assertEqual(4, rows[0]["n"])

    def test_a_finding_without_a_rule_id_always_counts(self):
        """Findings older than the column, and the analyst's own YARA rules,
        which are switched off as FILES rather than through this."""
        add(self.conn, "/w/legacy.php", "", rule="From before the column")
        self.conn.commit()
        shown = artifacts(self.conn, {"webshell.goto", ""})
        self.assertIn("/w/legacy.php", shown)

    def test_a_rule_id_with_an_odd_shape_cannot_reach_the_sql(self):
        """Ids from analyst-authored SIGMA files end up in this query. One
        that is not a plain identifier is dropped rather than quoted --
        visibly ineffective beats silently injected."""
        sql = art_sql({"webshell.goto", "'); DROP TABLE findings; --"})
        self.assertIn("webshell.goto", sql)
        self.assertNotIn("DROP TABLE", sql)
        self.assertTrue(db.rows(self.conn, f"WITH art AS ({sql}) SELECT * FROM art"))

    def test_the_plain_view_knows_nothing_about_muting(self):
        """The chronology, the exports and the IOC box use it: what a case
        FOUND does not change because a rule was later switched off."""
        from server.artifacts import ART_SQL
        rows = db.rows(self.conn, f"WITH art AS ({ART_SQL}) SELECT * FROM art")
        self.assertEqual(3, len(rows))
        for row in rows:
            self.assertEqual(row["findings"], row["active"])


if __name__ == "__main__":
    unittest.main()
