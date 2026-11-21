"""Bench-only: central key rotation with overlap. Run with `bench run-tests`."""

from types import SimpleNamespace
from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase

from thinknxg_super_admin.security import rotation

SSO = "ThinkNXG SSO Configuration"


def _sites(**acked):
	return [
		SimpleNamespace(name=n, site_url=f"https://{n}.example.com", central_key_acked=a)
		for n, a in acked.items()
	]


class TestRotation(IntegrationTestCase):
	def setUp(self):
		rotation.cancel()

	def tearDown(self):
		frappe.db.rollback()

	def test_begin_stages_every_site_and_reports_failures(self):
		def fake_call(url, endpoint, payload):
			if "bad" in url:
				raise rotation.agent_client.AgentCallError("unreachable")
			return 200, {"ok": True}

		with (
			patch.object(rotation, "_paired_sites", return_value=_sites(good=None, bad=None)),
			patch.object(rotation.agent_client, "call", side_effect=fake_call),
		):
			result = rotation.begin()
		self.assertEqual(result["sites"], {"good": "staged", "bad": "unreachable"})
		self.assertTrue(result["next_key_id"])

	def test_complete_refuses_while_a_site_is_pending(self):
		with (
			patch.object(rotation, "_paired_sites", return_value=_sites(a=None)),
			patch.object(
				rotation.agent_client, "call", side_effect=rotation.agent_client.AgentCallError("timeout")
			),
		):
			rotation.begin()
			self.assertRaises(frappe.ValidationError, rotation.complete)

	def test_complete_switches_signing_key_and_clears_next(self):
		before = frappe.db.get_single_value(SSO, "central_key_id")
		with (
			patch.object(rotation, "_paired_sites", return_value=_sites()),
		):
			result = rotation.begin()
			nxt = result["next_key_id"]
			rotation.complete()
		self.assertEqual(frappe.db.get_single_value(SSO, "central_key_id"), nxt)
		self.assertNotEqual(before, nxt)
		self.assertFalse(frappe.db.get_single_value(SSO, "central_next_key_id"))

	def test_accept_pending_allows_cutover_and_is_audited(self):
		with (
			patch.object(rotation, "_paired_sites", return_value=_sites(a=None)),
			patch.object(
				rotation.agent_client, "call", side_effect=rotation.agent_client.AgentCallError("timeout")
			),
		):
			rotation.begin()
			rotation.complete(["a"])
		entry = frappe.get_all(
			"ThinkNXG Audit Log", filters={"action": "sso.central_key_rotated"}, fields=["after"], limit=1
		)
		self.assertIn('"a"', entry[0].after)

	def test_cancel_discards_next_key(self):
		with patch.object(rotation, "_paired_sites", return_value=_sites()):
			rotation.begin()
		rotation.cancel()
		self.assertFalse(frappe.db.get_single_value(SSO, "central_next_key_id"))
