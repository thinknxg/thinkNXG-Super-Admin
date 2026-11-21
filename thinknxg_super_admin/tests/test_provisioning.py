"""Bench-only executor tests. Run: bench run-tests --app thinknxg_super_admin

Keycloak and the site are mocked. NOT executed in the environment that generated this file.
"""

import json
from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase

from thinknxg_super_admin.provisioning import agent_client, executor
from thinknxg_super_admin.tests.test_controllers import make_org
from thinknxg_super_admin.tests.test_pairing_health import SITE, make_site

UID_EMAIL = "prov-user@example.com"


def make_fixtures(user_status="Active"):
	make_org()
	make_site()
	frappe.db.set_value("ThinkNXG Managed Site", SITE, "status", "Active")
	if frappe.db.exists("ThinkNXG Central User", {"email": UID_EMAIL}):
		user = frappe.get_doc("ThinkNXG Central User", {"email": UID_EMAIL})
	else:
		user = frappe.get_doc({"doctype": "ThinkNXG Central User", "email": UID_EMAIL, "first_name": "P", "organization": "test-org"}).insert()
	frappe.db.set_value("ThinkNXG Central User", user.name, "status", user_status)
	return user


def make_request(user, request_op="Create User", **state):
	body = {"operation": "upsert", "central_uid": user.name, "email": user.email, "first_name": "P", "last_name": "", "roles": [], "approved_privileged": [], "deprovision_policy": "Disable"}
	body.update(state)
	return frappe.get_doc(
		{
			"doctype": "ThinkNXG Provisioning Request",
			"operation": request_op,
			"central_user": user.name,
			"site": SITE,
			"organization": "test-org",
			"idempotency_key": frappe.generate_hash(length=40),
			"desired_state": json.dumps(body),
		}
	).insert()


class FakeAdmin:
	def __init__(self):
		self.calls = []

	def create_user(self, rep):
		self.calls.append("create")
		return "kc-1"

	def update_user(self, kc_id, rep):
		self.calls.append("update")

	def set_user_enabled(self, kc_id, enabled):
		self.calls.append(("enabled", enabled))

	def logout_user(self, kc_id):
		self.calls.append("logout")


class TestExecutor(IntegrationTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		self.user = make_fixtures()
		self.admin = FakeAdmin()
		self.patches = [patch.object(executor.site_ops, "get_admin", return_value=self.admin)]
		for p in self.patches:
			p.start()
		self.addCleanup(lambda: [p.stop() for p in self.patches])

	def run_with(self, req, result=None, error=None):
		target = patch.object(agent_client, "call", side_effect=error, return_value=result)
		with target:
			executor.run_request(req.name)
		req.reload()
		return req

	def test_success_records_user_and_logs_both_steps(self):
		req = self.run_with(make_request(self.user), result=(200, {"ok": True, "site_user": "x@y.com", "link_state": "Linked"}))
		self.assertEqual(req.status, "Succeeded")
		self.assertEqual(frappe.db.get_value("ThinkNXG Central User", self.user.name, "keycloak_user_id"), "kc-1")
		steps = frappe.get_all("ThinkNXG Provisioning Log", filters={"request": req.name}, pluck="step")
		self.assertEqual(sorted(steps), ["idp", "site_apply"])

	def test_timeout_retries_with_backoff(self):
		req = self.run_with(make_request(self.user), error=agent_client.AgentCallError("timeout"))
		self.assertEqual(req.status, "Retrying")
		self.assertTrue(req.next_retry_at)
		self.assertIn("timeout", req.last_error)

	def test_validation_failure_is_final(self):
		req = self.run_with(make_request(self.user), result=(422, {"ok": False, "code": "validation_failed", "message": "bad"}))
		self.assertEqual(req.status, "Failed")

	def test_email_clash_needs_review(self):
		req = self.run_with(make_request(self.user), result=(409, {"ok": False, "code": "link_required", "message": "exists"}))
		self.assertEqual(req.status, "Needs Review")

	def test_finished_request_is_not_rerun(self):
		req = self.run_with(make_request(self.user), result=(200, {"ok": True}))
		with patch.object(agent_client, "call", side_effect=AssertionError("must not be called")):
			executor.run_request(req.name)

	def test_site_not_active_goes_to_review_without_calling_site(self):
		frappe.db.set_value("ThinkNXG Managed Site", SITE, "status", "Inactive")
		with patch.object(agent_client, "call", side_effect=AssertionError("must not be called")):
			req = make_request(self.user)
			executor.run_request(req.name)
		req.reload()
		self.assertEqual(req.status, "Needs Review")


class TestBlockedUser(IntegrationTestCase):
	def test_suspended_user_is_blocked_at_the_idp_and_logged_out(self):
		frappe.set_user("Administrator")
		user = make_fixtures(user_status="Suspended")
		frappe.db.set_value("ThinkNXG Central User", user.name, "keycloak_user_id", "kc-9")
		admin = FakeAdmin()
		with patch.object(executor.site_ops, "get_admin", return_value=admin), patch.object(
			agent_client, "call", return_value=(200, {"ok": True})
		):
			req = make_request(user, "Disable User", operation="disable")
			executor.run_request(req.name)
		self.assertEqual(admin.calls, [("enabled", False), "logout"])
