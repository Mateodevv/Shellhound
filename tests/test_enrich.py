# tests/test_enrich.py
"""The door to the outside: settings and enrichment.

Every test here is about something NOT happening. This is the one part of
the toolkit that sends data to a third party, and the guards that keep it to
one indicator per explicit click are exactly the kind that rot quietly -- a
refactor that "simplifies" the gate leaves a tool that phones home.

No test in this file touches the network. The lookup functions are replaced;
what is asserted is that the request never gets that far.
"""
import json
import tempfile
import unittest
from pathlib import Path

from server import db, enrich, settings


class SettingsTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-set-"))

    def test_defaults_are_closed(self):
        conf = settings.load(self.ws)
        self.assertFalse(conf["enrichment_ack"], "lookups start unaccepted")
        self.assertTrue(all(not v for v in conf["keys"].values()),
                        "no service starts configured")

    def test_a_key_never_reaches_the_interface_in_full(self):
        secret = "vt-0123456789-SECRET-abcd"
        settings.set_key(self.ws, "virustotal", secret)
        pub = settings.public(self.ws)
        blob = json.dumps(pub)
        self.assertNotIn(secret, blob)
        self.assertNotIn("SECRET", blob)
        self.assertEqual("…abcd", pub["services"]["virustotal"]["hint"],
                         "the last four identify the key")
        self.assertTrue(pub["services"]["virustotal"]["configured"])

    def test_the_real_key_is_available_to_the_lookup_only(self):
        settings.set_key(self.ws, "abuseipdb", "abc123")
        self.assertEqual("abc123", settings.for_service(self.ws, "abuseipdb"))

    def test_an_empty_key_switches_the_service_off(self):
        settings.set_key(self.ws, "virustotal", "abc")
        settings.set_key(self.ws, "virustotal", "")
        self.assertFalse(settings.public(self.ws)["services"]["virustotal"]["configured"])

    def test_an_unknown_service_is_refused(self):
        with self.assertRaises(ValueError):
            settings.set_key(self.ws, "some-feed", "abc")

    def test_a_broken_settings_file_does_not_raise(self):
        settings.path(self.ws).write_text("{not json", encoding="utf-8")
        conf = settings.load(self.ws)
        self.assertFalse(conf["enrichment_ack"])

    def test_settings_live_in_the_workspace_not_in_a_case(self):
        """A case archive must never carry an API key: handing a colleague a
        case must not hand them the key."""
        self.assertEqual(self.ws, settings.path(self.ws).parent)


class EnrichGateTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-enr-"))
        self.case = Path(tempfile.mkdtemp(prefix="shellhound-enrcase-"))
        db.connect(self.case).close()
        self.calls = []
        self._real = dict(enrich._LOOKUPS)
        for name in enrich._LOOKUPS:
            enrich._LOOKUPS[name] = self._record(name)
        # At the production interval this class would sit in `sleep` for
        # three minutes. The throttle itself is covered separately.
        self._intervals = dict(enrich.MIN_INTERVAL)
        for name in enrich.MIN_INTERVAL:
            enrich.MIN_INTERVAL[name] = 0.0

    def tearDown(self):
        enrich._LOOKUPS.clear()
        enrich._LOOKUPS.update(self._real)
        enrich.MIN_INTERVAL.clear()
        enrich.MIN_INTERVAL.update(self._intervals)

    def _record(self, name):
        def fake(key, value):
            self.calls.append((name, key, value))
            return {"known": True, "score": 1, "of": 70}
        return fake

    def _open(self):
        settings.set_ack(self.ws, True)
        settings.set_key(self.ws, "virustotal", "vt-key")
        settings.set_key(self.ws, "abuseipdb", "ab-key")

    # --- the gate -----------------------------------------------------------

    def test_nothing_goes_out_before_the_analyst_accepted(self):
        settings.set_key(self.ws, "virustotal", "vt-key")
        with self.assertRaises(enrich.EnrichError):
            enrich.lookup(self.ws, self.case, "virustotal", "a" * 64)
        self.assertEqual([], self.calls, "a lookup ran without acceptance")

    def test_nothing_goes_out_without_a_key(self):
        settings.set_ack(self.ws, True)
        with self.assertRaises(enrich.EnrichError):
            enrich.lookup(self.ws, self.case, "abuseipdb", "203.0.113.9")
        self.assertEqual([], self.calls)

    def test_an_unknown_service_is_refused(self):
        self._open()
        with self.assertRaises(enrich.EnrichError):
            enrich.lookup(self.ws, self.case, "some-feed", "203.0.113.9")
        self.assertEqual([], self.calls)

    # --- what is allowed to be sent where -----------------------------------

    def test_an_ip_is_never_sent_to_virustotal(self):
        self._open()
        with self.assertRaises(enrich.EnrichError):
            enrich.lookup(self.ws, self.case, "virustotal", "203.0.113.9")
        self.assertEqual([], self.calls)

    def test_a_hash_is_never_sent_to_abuseipdb(self):
        self._open()
        with self.assertRaises(enrich.EnrichError):
            enrich.lookup(self.ws, self.case, "abuseipdb", "a" * 64)
        self.assertEqual([], self.calls)

    def test_only_the_indicator_is_handed_to_the_service(self):
        """The whole promise in one assertion: the call receives the key and
        the single value -- no case name, no path, no second indicator."""
        self._open()
        digest = "b" * 64
        enrich.lookup(self.ws, self.case, "virustotal", digest)
        self.assertEqual([("virustotal", "vt-key", digest)], self.calls)

    def test_a_hash_is_normalised_before_it_leaves(self):
        self._open()
        enrich.lookup(self.ws, self.case, "virustotal", "  " + "A" * 64 + " ")
        self.assertEqual("a" * 64, self.calls[0][2])

    def test_junk_is_refused_rather_than_sent(self):
        self._open()
        for value in ("", "   ", "not-a-hash", "1.2.3.999"):
            self.calls.clear()
            with self.assertRaises(enrich.EnrichError):
                enrich.lookup(self.ws, self.case, "abuseipdb", value)
            self.assertEqual([], self.calls, f"{value!r} was sent")

    # --- the cache ----------------------------------------------------------

    def test_a_second_click_costs_no_second_request(self):
        self._open()
        digest = "c" * 64
        first = enrich.lookup(self.ws, self.case, "virustotal", digest)
        second = enrich.lookup(self.ws, self.case, "virustotal", digest)
        self.assertEqual(1, len(self.calls), "the cache did not hold")
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(first["result"], second["result"])

    def test_refresh_asks_again(self):
        self._open()
        digest = "d" * 64
        enrich.lookup(self.ws, self.case, "virustotal", digest)
        enrich.lookup(self.ws, self.case, "virustotal", digest, refresh=True)
        self.assertEqual(2, len(self.calls))

    def test_the_answer_carries_when_it_was_fetched(self):
        """A verdict from six weeks ago is a different statement from one
        fetched this morning."""
        self._open()
        out = enrich.lookup(self.ws, self.case, "abuseipdb", "198.51.100.4")
        self.assertTrue(out["fetched"], "no timestamp on the answer")

    def test_the_cache_is_per_case(self):
        self._open()
        other = Path(tempfile.mkdtemp(prefix="shellhound-enrcase2-"))
        db.connect(other).close()
        digest = "e" * 64
        enrich.lookup(self.ws, self.case, "virustotal", digest)
        enrich.lookup(self.ws, other, "virustotal", digest)
        self.assertEqual(2, len(self.calls),
                         "one case answered from another case's cache")

    def test_enrichment_never_becomes_a_finding(self):
        """The epistemic rule: a foreign opinion is not evidence this case
        gathered. It must not appear among the findings."""
        self._open()
        enrich.lookup(self.ws, self.case, "virustotal", "f" * 64)
        conn = db.connect(self.case)
        try:
            findings = conn.execute("SELECT count(*) FROM findings").fetchone()[0]
            stored = conn.execute("SELECT count(*) FROM enrichment").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(0, findings, "a lookup wrote a finding")
        self.assertEqual(1, stored)

    def test_all_for_reads_back_what_was_stored(self):
        self._open()
        enrich.lookup(self.ws, self.case, "virustotal", "1" * 64)
        enrich.lookup(self.ws, self.case, "abuseipdb", "192.0.2.7")
        conn = db.connect(self.case)
        try:
            found = enrich.all_for(conn, ["1" * 64, "192.0.2.7", "192.0.2.8"])
        finally:
            conn.close()
        self.assertIn("virustotal", found["1" * 64])
        self.assertIn("abuseipdb", found["192.0.2.7"])
        self.assertNotIn("192.0.2.8", found)


class ThrottleTests(unittest.TestCase):
    """The rate limit is per KEY, not per case: going over it earns a 429
    and, repeatedly, a blocked key. So it has to hold even when the analyst
    clicks faster than the free tier allows."""

    def test_the_second_call_waits(self):
        import time
        saved = dict(enrich.MIN_INTERVAL)
        enrich._last_call.pop("virustotal", None)
        try:
            enrich.MIN_INTERVAL["virustotal"] = 0.4
            enrich._throttle("virustotal")
            start = time.monotonic()
            enrich._throttle("virustotal")
            self.assertGreaterEqual(time.monotonic() - start, 0.3)
        finally:
            enrich.MIN_INTERVAL.clear()
            enrich.MIN_INTERVAL.update(saved)
            enrich._last_call.pop("virustotal", None)

    def test_the_production_interval_respects_the_free_tier(self):
        # VirusTotal's free tier is four requests per minute.
        self.assertGreaterEqual(enrich.MIN_INTERVAL["virustotal"], 15.0)


if __name__ == "__main__":
    unittest.main()
