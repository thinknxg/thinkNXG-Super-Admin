import unittest
from datetime import datetime, timedelta

from thinknxg_super_admin.utils.ops_rules import health_verdict

NOW = datetime(2026, 11, 21, 12, 0, 0)


class OpsRulesTest(unittest.TestCase):
	def test_ok(self):
		self.assertEqual(
			health_verdict(db_ok=True, last_evaluated_at=NOW - timedelta(minutes=4), now=NOW), (True, "ok")
		)

	def test_boundary_is_still_ok(self):
		self.assertTrue(health_verdict(db_ok=True, last_evaluated_at=NOW - timedelta(minutes=15), now=NOW)[0])

	def test_stale_scheduler(self):
		self.assertEqual(
			health_verdict(db_ok=True, last_evaluated_at=NOW - timedelta(minutes=16), now=NOW),
			(False, "scheduler_stale"),
		)

	def test_never_ran(self):
		self.assertEqual(
			health_verdict(db_ok=True, last_evaluated_at=None, now=NOW), (False, "scheduler_never_ran")
		)

	def test_database_down_wins(self):
		self.assertEqual(health_verdict(db_ok=False, last_evaluated_at=NOW, now=NOW), (False, "database"))
