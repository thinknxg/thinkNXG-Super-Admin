import unittest
from datetime import datetime, timedelta

from thinknxg_super_admin.provisioning import plan
from thinknxg_super_admin.utils.rules import RuleError

NOW = datetime(2026, 11, 21, 12, 0)
UID = "6f1c2a52-3d0b-4c43-9a6b-2f6a1d0e8c11"


def state(**kw):
	args = dict(operation="Create User", central_uid=UID, email="A@B.com", first_name="A", last_name="B",
		roles=["Sales User", "Sales User", "Accounts User"], approved_privileged=[], deprovision_policy="Disable", assignment="ASG-1")
	args.update(kw)
	return plan.build_desired_state(**args)


class TestState(unittest.TestCase):
	def test_normalised_sorted_unique(self):
		s = state()
		self.assertEqual(s["roles"], ["Accounts User", "Sales User"])
		self.assertEqual(s["email"], "a@b.com")
		self.assertEqual(s["operation"], "upsert")

	def test_approval_only_covers_requested_roles(self):
		s = state(roles=["System Manager", "Sales User"], approved_privileged=["System Manager", "Accounts Manager"])
		self.assertEqual(s["approved_privileged"], ["System Manager"])

	def test_unknown_operation(self):
		with self.assertRaises(RuleError):
			state(operation="Delete Everything")

	def test_version_changes_with_roles_but_not_order(self):
		a = plan.desired_version(state(roles=["A", "B"]))
		self.assertEqual(a, plan.desired_version(state(roles=["B", "A"])))
		self.assertNotEqual(a, plan.desired_version(state(roles=["A"])))

	def test_request_key_is_stable_and_op_specific(self):
		s = state()
		self.assertEqual(plan.request_key("Create User", UID, "site", s), plan.request_key("Create User", UID, "site", s))
		self.assertNotEqual(plan.request_key("Create User", UID, "site", s), plan.request_key("Resync User", UID, "site", s))
		self.assertNotEqual(plan.request_key("Create User", UID, "site", s), plan.request_key("Create User", UID, "other", s))


class TestApprovals(unittest.TestCase):
	def test_privileged_only_when_approved_and_never_administrator(self):
		roles = ["System Manager", "Administrator", "Sales User"]
		self.assertEqual(plan.approved_privileged_roles(roles, privileged_approved=False), [])
		self.assertEqual(plan.approved_privileged_roles(roles, privileged_approved=True), ["System Manager"])


class TestClassify(unittest.TestCase):
	def test_needs_review(self):
		self.assertEqual(plan.classify_failure("link_required", 409, 1), ("Needs Review", None))
		self.assertEqual(plan.classify_failure("conflict", 409, 1), ("Needs Review", None))

	def test_non_retryable_fail_fast(self):
		for code in ("validation_failed", "forbidden", "approval_required", "unsupported_version"):
			self.assertEqual(plan.classify_failure(code, 400, 1), ("Failed", None), code)

	def test_client_errors_do_not_retry_but_throttling_does(self):
		self.assertEqual(plan.classify_failure(None, 401, 1), ("Failed", None))
		self.assertEqual(plan.classify_failure(None, 429, 1)[0], "Retrying")
		self.assertEqual(plan.classify_failure(None, 503, 1)[0], "Retrying")
		self.assertEqual(plan.classify_failure("timeout", None, 1), ("Retrying", 60))

	def test_backoff_then_exhaustion(self):
		delays = [plan.classify_failure("timeout", None, n)[1] for n in range(1, 6)]
		self.assertEqual(delays, [60, 300, 1800, 7200, 43200])
		self.assertEqual(plan.classify_failure("timeout", None, 6), ("Failed", None))

	def test_jitter_is_bounded(self):
		self.assertEqual(plan.classify_failure("timeout", None, 1, jitter=5.0)[1], 72)


class TestReconcilerPredicates(unittest.TestCase):
	def test_retry_due(self):
		self.assertTrue(plan.due_for_retry("Retrying", NOW - timedelta(seconds=1), NOW))
		self.assertFalse(plan.due_for_retry("Retrying", NOW + timedelta(seconds=1), NOW))
		self.assertFalse(plan.due_for_retry("Failed", NOW - timedelta(days=1), NOW))
		self.assertFalse(plan.due_for_retry("Retrying", None, NOW))

	def test_stuck_and_stale(self):
		self.assertTrue(plan.stuck_running("Running", NOW - timedelta(minutes=11), NOW))
		self.assertFalse(plan.stuck_running("Running", NOW - timedelta(minutes=9), NOW))
		self.assertTrue(plan.stale_queued("Queued", NOW - timedelta(minutes=3), NOW))
		self.assertFalse(plan.stale_queued("Queued", NOW - timedelta(seconds=30), NOW))


class TestAssignmentEvents(unittest.TestCase):
	def ev(self, b, a):
		return plan.assignment_events(b, a)

	def test_new_requested_creates(self):
		self.assertEqual(self.ev(None, {"status": "Requested", "roles_signature": "x"}), "Create User")
		self.assertIsNone(self.ev(None, {"status": "Active", "roles_signature": "x"}))

	def test_transitions(self):
		cases = {("Requested", "Provisioning"): "Create User", ("Disabled", "Provisioning"): "Enable User",
			("Active", "Disabled"): "Disable User", ("Active", "Removing"): "Deprovision User", ("Failed", "Provisioning"): "Create User"}
		for (b, a), op in cases.items():
			self.assertEqual(self.ev({"status": b, "roles_signature": "x"}, {"status": a, "roles_signature": "x"}), op)

	def test_role_change_on_active_updates_only_then(self):
		self.assertEqual(self.ev({"status": "Active", "roles_signature": "a"}, {"status": "Active", "roles_signature": "b"}), "Update User")
		self.assertIsNone(self.ev({"status": "Active", "roles_signature": "a"}, {"status": "Active", "roles_signature": "a"}))
		self.assertIsNone(self.ev({"status": "Disabled", "roles_signature": "a"}, {"status": "Disabled", "roles_signature": "b"}))

	def test_terminal_and_noops(self):
		self.assertIsNone(self.ev({"status": "Provisioning", "roles_signature": "a"}, {"status": "Active", "roles_signature": "a"}))
		self.assertIsNone(self.ev({"status": "Removing", "roles_signature": "a"}, {"status": "Removed", "roles_signature": "a"}))


if __name__ == "__main__":
	unittest.main()
