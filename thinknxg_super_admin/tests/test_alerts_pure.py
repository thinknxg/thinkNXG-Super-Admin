import unittest
from datetime import date, datetime, timedelta

from thinknxg_super_admin.monitoring import alert_rules as ar
from thinknxg_super_admin.monitoring import summary as sm

NOW = datetime(2026, 11, 21, 12, 0)


def site(name="a", conn="Online", status="Active", checked=None):
	return {"name": name, "organization": "org", "status": status, "connection_status": conn, "last_health_check": checked or NOW - timedelta(minutes=2)}


def keys(snapshot, settings=None):
	return sorted(c["key"] for c in ar.evaluate(snapshot, settings or {}, NOW))


class TestEvaluate(unittest.TestCase):
	def test_healthy_is_quiet(self):
		self.assertEqual(keys({"sites": [site()]}), [])

	def test_offline_degraded_stale(self):
		self.assertEqual(keys({"sites": [site(conn="Offline")]}), ["site_offline|a"])
		self.assertEqual(keys({"sites": [site(conn="Degraded")]}), ["site_degraded|a"])
		self.assertEqual(keys({"sites": [site(checked=NOW - timedelta(minutes=20))]}), ["site_stale|a"])

	def test_only_active_sites_alert(self):
		self.assertEqual(keys({"sites": [site(conn="Offline", status="Draft"), site(conn="Offline", status="Disconnected")]}), [])

	def test_severity(self):
		by = {c["key"]: c["severity"] for c in ar.evaluate({"sites": [site(conn="Offline"), site("b", conn="Degraded")]}, {}, NOW)}
		self.assertEqual(by, {"site_offline|a": "Critical", "site_degraded|b": "Warning"})

	def test_thresholds(self):
		snap = {"failures": [{"site": "a", "organization": "o", "count": 4}], "denials": [{"site": "a", "organization": "o", "count": 9}], "needs_review": [{"site": "a", "organization": "o", "count_overdue": 0}]}
		self.assertEqual(keys(snap), [])
		snap = {"failures": [{"site": "a", "organization": "o", "count": 5}], "denials": [{"site": "a", "organization": "o", "count": 10}], "needs_review": [{"site": "a", "organization": "o", "count_overdue": 2}]}
		self.assertEqual(keys(snap), ["denial_spike|a", "failures|a", "needs_review|a"])
		self.assertEqual(keys({"failures": [{"site": "a", "organization": "o", "count": 2}]}, {"failure_threshold": 2}), ["failures|a"])

	def test_queue_stuck_has_no_site(self):
		out = ar.evaluate({"queue": {"oldest_queued_age_seconds": 16 * 60, "count": 3}}, {}, NOW)
		self.assertEqual([(c["key"], c["site"]) for c in out], [("queue_stuck", None)])
		self.assertEqual(keys({"queue": {"oldest_queued_age_seconds": 14 * 60}}), [])

	def test_none_settings_fall_back_to_defaults(self):
		self.assertEqual(ar.with_defaults({"renotify_hours": None, "failure_threshold": 9})["renotify_hours"], 6)
		self.assertEqual(ar.with_defaults({"failure_threshold": 9})["failure_threshold"], 9)
		self.assertNotIn("junk", ar.with_defaults({"junk": 1}))


def cand(key="site_offline|a", severity="Critical"):
	return {"key": key, "type": "t", "severity": severity, "title": "T", "message": "M", "site": "a", "organization": "o"}


class TestReconcile(unittest.TestCase):
	def rec(self, open_alerts, cands, hours=6):
		return ar.reconcile(open_alerts, cands, NOW, hours)

	def test_new_alert_opens_and_notifies_once(self):
		r = self.rec({}, [cand()])
		self.assertEqual((len(r["open"]), r["notify"]), (1, [("site_offline|a", "opened")]))

	def test_open_alert_is_quiet_until_renotify_window(self):
		prev = {"site_offline|a": {"status": "Open", "severity": "Critical", "last_notified_at": NOW - timedelta(hours=5)}}
		self.assertEqual(self.rec(prev, [cand()])["notify"], [])
		prev["site_offline|a"]["last_notified_at"] = NOW - timedelta(hours=6)
		self.assertEqual(self.rec(prev, [cand()])["notify"], [("site_offline|a", "reminder")])

	def test_acknowledged_is_never_reminded_but_escalates(self):
		prev = {"k": {"status": "Acknowledged", "severity": "Warning", "last_notified_at": NOW - timedelta(days=3)}}
		self.assertEqual(self.rec(prev, [cand("k", "Warning")])["notify"], [])
		self.assertEqual(self.rec(prev, [cand("k", "Critical")])["notify"], [("k", "escalated")])

	def test_deescalation_is_silent(self):
		prev = {"k": {"status": "Open", "severity": "Critical", "last_notified_at": NOW}}
		self.assertEqual(self.rec(prev, [cand("k", "Warning")])["notify"], [])

	def test_cleared_condition_resolves_and_notifies(self):
		prev = {"k": {"status": "Open", "severity": "Critical", "last_notified_at": NOW}}
		r = self.rec(prev, [])
		self.assertEqual((r["resolve"], r["notify"]), (["k"], [("k", "resolved")]))

	def test_never_notified_open_alert_gets_a_reminder(self):
		prev = {"k": {"status": "Open", "severity": "Critical", "last_notified_at": None}}
		self.assertEqual(self.rec(prev, [cand("k")])["notify"], [("k", "reminder")])


class TestDigest(unittest.TestCase):
	def test_escapes_everything(self):
		item = {"event": "opened", "severity": "Critical", "title": "<script>alert(1)</script>", "message": "a & b", "link": "/app/x?a=1&b=\"2\""}
		subject, body, text = ar.render_digest([item], "https://admin.example.com/")
		self.assertNotIn("<script>", body)
		self.assertIn("&lt;script&gt;", body)
		self.assertIn("a &amp; b", body)
		self.assertNotIn('"2"', body.split("href=")[1].split(">")[0].strip('"') + "x")
		self.assertIn("https://admin.example.com/app/x", text)
		self.assertIn("Critical", subject)

	def test_subject_uses_highest_severity(self):
		items = [{"event": "opened", "severity": s, "title": "t", "message": "m", "link": "/a"} for s in ("Warning", "Critical", "Info")]
		self.assertIn("highest severity Critical", ar.render_digest(items, "https://x")[0])

	def test_empty_is_an_error(self):
		with self.assertRaises(ValueError):
			ar.render_digest([], "https://x")

	def test_email_threshold(self):
		self.assertTrue(ar.meets_email_threshold("Critical", "Warning"))
		self.assertFalse(ar.meets_email_threshold("Info", "Warning"))
		self.assertTrue(ar.meets_email_threshold("Warning", "Warning"))


class TestSummary(unittest.TestCase):
	def test_fill_counts(self):
		out = sm.fill_counts([{"s": "Online", "n": 3}, {"s": "Weird", "n": 2}], "s", sm.CONNECTION_ORDER)
		self.assertEqual(out, {"Online": 3, "Degraded": 0, "Offline": 0, "Unknown": 0, "Other": 2})

	def test_daily_buckets_cover_every_day(self):
		rows = [{"day": datetime(2026, 11, 21, 3), "status": "Failed", "n": 2}, {"day": date(2026, 11, 19), "status": "Succeeded", "n": 5}, {"day": date(2026, 10, 1), "status": "Failed", "n": 9}]
		out = sm.daily_buckets(rows, 3, date(2026, 11, 21))
		self.assertEqual([b["day"] for b in out], ["2026-11-19", "2026-11-20", "2026-11-21"])
		self.assertEqual((out[0]["Succeeded"], out[1]["Failed"], out[2]["Failed"]), (5, 0, 2))

	def test_rank_sites(self):
		sites = [site("ok"), site("deg", "Degraded"), site("off", "Offline", checked=NOW), site("off2", "Offline", checked=NOW - timedelta(hours=1)), site("draft", "Offline", status="Draft")]
		self.assertEqual([s["name"] for s in sm.rank_sites_needing_attention(sites)], ["off2", "off", "deg"])

	def test_clip(self):
		self.assertEqual(sm.clip("a\nb"), "a b")
		self.assertEqual(len(sm.clip("x" * 300)), 140)
		self.assertEqual(sm.clip(None), "")


if __name__ == "__main__":
	unittest.main()
