import unittest
from datetime import datetime, timedelta

from thinknxg_super_admin.utils import site_rules as sr
from thinknxg_super_admin.utils.rules import RuleError

NOW = datetime(2026, 11, 21, 12, 0, 0)


def code_of(fn):
	try:
		fn()
	except RuleError as exc:
		return exc.code
	return None


class TestPairing(unittest.TestCase):
	def setUp(self):
		self.code, self.hash = sr.new_pairing_code()
		self.exp = NOW + timedelta(minutes=30)

	def test_code_shape_and_uniqueness(self):
		self.assertTrue(self.code.startswith("TNXG-"))
		self.assertNotEqual(self.code, sr.new_pairing_code()[0])
		self.assertNotIn(self.code, self.hash)
		self.assertEqual(len(self.hash), 64)

	def test_valid_with_formatting_noise(self):
		sr.check_pairing(self.hash, self.exp, 1, self.code.lower(), NOW)
		sr.check_pairing(self.hash, self.exp, 1, "  " + self.code.replace("-", " ") + " ", NOW)

	def test_wrong_expired_locked_closed(self):
		self.assertEqual(code_of(lambda: sr.check_pairing(self.hash, self.exp, 1, "TNXG-WRONG", NOW)), "pairing_invalid")
		self.assertEqual(code_of(lambda: sr.check_pairing(self.hash, self.exp, 1, self.code, NOW + timedelta(minutes=31))), "pairing_expired")
		self.assertEqual(code_of(lambda: sr.check_pairing(self.hash, self.exp, 6, self.code, NOW)), "pairing_locked")
		self.assertEqual(code_of(lambda: sr.check_pairing(None, None, 1, self.code, NOW)), "pairing_invalid")
		self.assertEqual(code_of(lambda: sr.check_pairing(self.hash, self.exp, 1, None, NOW)), "pairing_invalid")

	def test_lockout_applies_even_to_the_right_code(self):
		self.assertEqual(code_of(lambda: sr.check_pairing(self.hash, self.exp, sr.PAIRING_MAX_ATTEMPTS + 1, self.code, NOW)), "pairing_locked")


GOOD = {"agent_version": "0.1.0", "frappe_version": "16.0.0", "erpnext_version": "16.0.0", "queue_backlog": 3, "scheduler_ok": True, "server_time_ms": 1_800_000_000_000}


class TestHealthPayload(unittest.TestCase):
	def test_valid_and_unknown_keys_dropped(self):
		out = sr.parse_health_payload({**GOOD, "evil": "x"})
		self.assertNotIn("evil", out)
		self.assertEqual(out["queue_backlog"], 3)

	def test_rejects_bad_types(self):
		for bad in (None, [], {**GOOD, "queue_backlog": -1}, {**GOOD, "queue_backlog": True}, {**GOOD, "agent_version": "x" * 100},
			{**GOOD, "agent_version": 5}, {**GOOD, "server_time_ms": "now"}):
			self.assertEqual(code_of(lambda b=bad: sr.parse_health_payload(b)), "health_invalid")

	def test_scheduler_must_be_literally_true(self):
		self.assertFalse(sr.parse_health_payload({**GOOD, "scheduler_ok": "yes"})["scheduler_ok"])

	def test_skew_sign(self):
		self.assertEqual(sr.clock_skew_ms(1_000_500, 1_000_000, 1_000_100), 450)
		self.assertLess(sr.clock_skew_ms(900_000, 1_000_000, 1_000_100), 0)


class TestEvaluate(unittest.TestCase):
	ok = {"reachable": True, "scheduler_ok": True, "queue_backlog": 0, "clock_skew_ms": 10, "latency_ms": 50}
	down = {"reachable": False}

	def test_unknown_without_history(self):
		self.assertEqual(sr.evaluate_connection([]), "Unknown")

	def test_online(self):
		self.assertEqual(sr.evaluate_connection([self.ok, self.ok]), "Online")

	def test_one_or_two_failures_degraded_three_offline(self):
		self.assertEqual(sr.evaluate_connection([self.down, self.ok]), "Degraded")
		self.assertEqual(sr.evaluate_connection([self.down, self.down, self.ok]), "Degraded")
		self.assertEqual(sr.evaluate_connection([self.down, self.down, self.down, self.ok]), "Offline")

	def test_recovery_after_failures(self):
		self.assertEqual(sr.evaluate_connection([self.ok, self.down, self.down, self.down]), "Online")

	def test_reachable_but_unhealthy_is_degraded(self):
		for patch in ({"scheduler_ok": False}, {"queue_backlog": 501}, {"clock_skew_ms": -31_000}, {"latency_ms": 6000}):
			self.assertEqual(sr.evaluate_connection([{**self.ok, **patch}]), "Degraded", patch)


class TestCatalogue(unittest.TestCase):
	def test_valid_sorted_unique(self):
		self.assertEqual(sr.parse_catalogue({"roles": ["B", "A", "A"]}), ["A", "B"])

	def test_rejects_bad(self):
		for bad in (None, [], {}, {"roles": "A"}, {"roles": [1]}, {"roles": [""]}, {"roles": ["x" * 141]}, {"roles": ["a"] * 2001}):
			self.assertEqual(code_of(lambda b=bad: sr.parse_catalogue(b)), "catalogue_invalid", bad)


if __name__ == "__main__":
	unittest.main()
