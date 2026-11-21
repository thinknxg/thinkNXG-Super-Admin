"""Bench-only tests for pairing and health polling. Run: bench run-tests --app thinknxg_super_admin

Keycloak and the network are mocked. NOT executed in the environment that generated this file.
"""

from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase

from thinknxg_super_admin.api import agent_in, site_admin
from thinknxg_super_admin.monitoring import health
from thinknxg_super_admin.security import signing
from thinknxg_super_admin.tests.test_controllers import make_org
from thinknxg_super_admin.utils import site_rules
from thinknxg_super_admin.utils.rules import RuleError

SITE = "pair-site"


def make_site():
	make_org()
	if frappe.db.exists("ThinkNXG Managed Site", SITE):
		frappe.delete_doc("ThinkNXG Managed Site", SITE, force=True)
	return frappe.get_doc(
		{
			"doctype": "ThinkNXG Managed Site",
			"site_name": SITE,
			"display_name": "Pair",
			"organization": "test-org",
			"site_url": "https://pair-site.example.com",
		}
	).insert()


class TestPairing(IntegrationTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		make_site()
		self.code = site_admin.create_pairing_code(SITE)["code"]
		self.pub = signing.generate_keypair()[1]

	def _pair(self, code=None):
		with patch("thinknxg_super_admin.api.agent_in.site_ops.ensure_client", return_value=("tnxg-site-pair-site", "s3cret")):
			return agent_in._pair(SITE, code or self.code, self.pub, "0.0.1")

	def test_pairing_sets_key_and_is_single_use(self):
		out = self._pair()
		self.assertEqual(out["client_id"], "tnxg-site-pair-site")
		site = frappe.get_doc("ThinkNXG Managed Site", SITE)
		self.assertTrue(site.agent_key_id.startswith("agt-"))
		self.assertEqual(site.agent_public_key, self.pub)
		self.assertFalse(site.pairing_code_hash)
		with self.assertRaises(RuleError):
			self._pair()

	def test_wrong_code_locks_after_five_attempts(self):
		for _ in range(5):
			with self.assertRaises(RuleError):
				self._pair("TNXG-WRONG")
		with self.assertRaises(RuleError) as ctx:
			self._pair()  # even the right code is refused now
		self.assertEqual(ctx.exception.code, "pairing_locked")

	def test_bad_public_key_is_refused(self):
		self.pub = "not a key"
		with self.assertRaises(ValueError):
			self._pair()

	def test_code_is_not_stored_in_clear(self):
		stored = frappe.db.get_value("ThinkNXG Managed Site", SITE, "pairing_code_hash")
		self.assertEqual(stored, site_rules.hash_code(self.code))
		self.assertNotIn(self.code, stored)


class TestHealth(IntegrationTestCase):
	def test_failures_move_status_to_offline(self):
		frappe.set_user("Administrator")
		make_site()
		frappe.db.set_value("ThinkNXG Managed Site", SITE, "agent_key_id", "agt-x")
		with patch.object(health, "_probe", return_value=(None, 0, None, "ConnectTimeout")):
			statuses = [health.check_site(SITE) for _ in range(3)]
		self.assertEqual(statuses, ["Degraded", "Degraded", "Offline"])
		good = {"agent_version": "0.0.1", "frappe_version": "16", "erpnext_version": "", "queue_backlog": 0, "scheduler_ok": True, "server_time_ms": 1}
		with patch.object(health, "_probe", return_value=(good, 40, 5, None)):
			self.assertEqual(health.check_site(SITE), "Online")
