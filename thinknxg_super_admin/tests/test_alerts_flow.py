"""Bench-only: alert lifecycle, notifier fan-out and dashboard scoping. Run with `bench run-tests`."""

from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase

from thinknxg_super_admin.monitoring import alerts, notifier


class TestAlertFlow(IntegrationTestCase):
	def test_alert_name_is_stable(self):
		self.assertEqual(alerts.alert_name("site_offline|S1"), alerts.alert_name("site_offline|S1"))
		self.assertNotEqual(alerts.alert_name("a"), alerts.alert_name("b"))

	def test_email_failure_does_not_block_in_app(self):
		ev = [{"name": "ALT-x", "event": "opened", "severity": "Critical", "title": "t", "message": "m", "organization": None}]
		with (
			patch.object(notifier, "recipients_for", return_value=["Administrator"]),
			patch("frappe.sendmail", side_effect=RuntimeError("smtp down")),
			patch("frappe.get_doc") as get_doc,
		):
			notifier.deliver(ev, {"enable_email": 1, "enable_in_app": 1})
		self.assertTrue(get_doc.called)

	def test_overview_denied_for_plain_user(self):
		from thinknxg_super_admin.api import dashboard

		frappe.set_user("Guest")
		self.assertRaises(frappe.PermissionError, dashboard.overview)
		frappe.set_user("Administrator")

	def test_run_is_idempotent_without_conditions(self):
		now = frappe.utils.now_datetime()
		alerts.run(now)
		self.assertEqual(alerts.run(now), [])
