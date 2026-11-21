import unittest
from datetime import datetime, timedelta

from thinknxg_super_admin.utils import rules as r


def m(template, roles, site=None, eff=None):
	return {"role_template": template, "site": site, "roles": roles, "effective_from": eff}


class TestIdentifiers(unittest.TestCase):
	def test_slug(self):
		for ok in ("a", "company-a", "a1", "x" * 64):
			self.assertTrue(r.is_valid_slug(ok), ok)
		for bad in ("", "-a", "a-", "A", "a_b", "a b", "x" * 65, None):
			self.assertFalse(r.is_valid_slug(bad), bad)

	def test_email(self):
		self.assertEqual(r.normalize_email("  Ali@Example.COM "), "ali@example.com")
		for bad in ("", "a@b", "a b@c.com", "@c.com"):
			with self.assertRaises(r.RuleError):
				r.normalize_email(bad)

	def test_split_host(self):
		self.assertEqual(r.split_host("company-a.thinknxg.com"), ("thinknxg.com", "company-a"))
		self.assertEqual(r.split_host("a.b.example.com.om"), ("example.com.om", "a.b"))
		self.assertEqual(r.split_host("example.com.om"), ("example.com.om", ""))
		self.assertEqual(r.split_host("example.com"), ("example.com", ""))

	def test_assignment_name_is_deterministic_and_pair_specific(self):
		self.assertEqual(r.assignment_name("u1", "s1"), r.assignment_name("u1", "s1"))
		self.assertNotEqual(r.assignment_name("u1", "s1"), r.assignment_name("u1", "s2"))
		self.assertNotEqual(r.assignment_name("u1s", "1"), r.assignment_name("u1", "s1"))

	def test_idempotency_key(self):
		a = r.idempotency_key("Create User", "u", "s", 3)
		self.assertEqual(a, r.idempotency_key("Create User", "u", "s", "3"))
		self.assertNotEqual(a, r.idempotency_key("Create User", "u", "s", 4))


class TestUrls(unittest.TestCase):
	def test_https_url(self):
		self.assertEqual(r.validate_https_url("https://Auth.Example.com/", allow_path=False, label="x"), "https://auth.example.com")
		self.assertEqual(
			r.validate_https_url("https://a.com/realms/x/", allow_path=True, label="x"), "https://a.com/realms/x"
		)
		for bad in ("http://a.com", "https://u:p@a.com", "https://a.com/?q=1", "https://a.com#f", ""):
			with self.assertRaises(r.RuleError):
				r.validate_https_url(bad, allow_path=True, label="x")
		with self.assertRaises(r.RuleError):
			r.validate_https_url("https://a.com/p", allow_path=False, label="x")

	def test_redirect_uris(self):
		o = "https://company-a.thinknxg.com"
		good = o + r.AGENT_CALLBACK_PATH
		self.assertEqual(r.validate_redirect_uris(o, [good]), [good])
		for bad in (
			"https://evil.com/cb",
			"http://company-a.thinknxg.com/cb",
			"https://*.thinknxg.com/cb",
			o + "/cb#x",
			"https://company-a.thinknxg.com.evil.com/cb",
			"https://company-a.thinknxg.com@evil.com/cb",
		):
			with self.assertRaises(r.RuleError, msg=bad):
				r.validate_redirect_uris(o, [bad])
		with self.assertRaises(r.RuleError):
			r.validate_redirect_uris(o, [good, good])

	def test_launch_path(self):
		self.assertEqual(r.validate_launch_path("/app"), "/app")
		for bad in ("app", "//evil.com", "https://evil.com", "/a\\b", "/a\nb", ""):
			with self.assertRaises(r.RuleError, msg=bad):
				r.validate_launch_path(bad)

	def test_cidrs(self):
		self.assertEqual(r.validate_cidrs(["10.0.0.5/8"]), ["10.0.0.0/8"])
		with self.assertRaises(r.RuleError):
			r.validate_cidrs(["nope"])


class TestPrivilege(unittest.TestCase):
	def kw(self, **o):
		base = dict(privileged=True, requested_by="a", approved_by="b", requester_is_super_admin=True, approver_is_super_admin=True)
		base.update(o)
		return base

	def test_detects_privileged(self):
		self.assertEqual(r.privileged_roles_in(["Sales User", " System Manager ", "Administrator"]), ["Administrator", "System Manager"])
		self.assertEqual(r.privileged_roles_in(["Sales User"]), [])

	def test_approval_rule(self):
		r.validate_privileged_approval(**self.kw())
		r.validate_privileged_approval(**self.kw(privileged=False, approved_by=None))
		for override, code in (
			({"approved_by": None}, "approval_required"),
			({"approved_by": "a"}, "approval_required"),
			({"approver_is_super_admin": False}, "forbidden"),
			({"requester_is_super_admin": False}, "forbidden"),
		):
			with self.assertRaises(r.RuleError) as cm:
				r.validate_privileged_approval(**self.kw(**override))
			self.assertEqual(cm.exception.code, code)

	def test_override_roles_parse(self):
		self.assertEqual(r.parse_override_roles(""), [])
		self.assertEqual(r.parse_override_roles('["A", " A ", "B"]'), ["A", "B"])
		for bad in ("not json", '{"a": 1}', "[1]", '[""]', "[" + ",".join(['"x"'] * 51) + "]"):
			with self.assertRaises(r.RuleError, msg=bad):
				r.parse_override_roles(bad)


class TestRoleResolution(unittest.TestCase):
	def test_site_specific_replaces_default(self):
		ms = [m("T", ["Sales User"]), m("T", ["Sales Manager"], site="B")]
		self.assertEqual(r.resolve_roles("T", "A", ms), ["Sales User"])
		self.assertEqual(r.resolve_roles("T", "B", ms), ["Sales Manager"])

	def test_missing_mapping_raises(self):
		with self.assertRaises(r.RuleError):
			r.resolve_roles("T", "A", [m("Other", ["x"])])

	def test_future_mapping_ignored(self):
		now = datetime(2026, 1, 1)
		ms = [m("T", ["Old"]), m("T", ["New"], site="A", eff=now + timedelta(days=1))]
		self.assertEqual(r.resolve_roles("T", "A", ms, now=now), ["Old"])
		self.assertEqual(r.resolve_roles("T", "A", ms, now=now + timedelta(days=2)), ["New"])

	def test_desired_roles_union_with_overrides(self):
		ms = [m("T1", ["A", "B"]), m("T2", ["B", "C"])]
		self.assertEqual(r.desired_roles(["T1", "T2"], "S", ms, overrides=["D"]), ["A", "B", "C", "D"])

	def test_catalogue_check(self):
		self.assertEqual(r.validate_roles_exist(["A", "Z"], ["A", "B"]), ["Z"])
		self.assertEqual(r.validate_roles_exist(["A", "Z"], []), [])


class TestStateMachines(unittest.TestCase):
	def test_every_target_is_a_known_state(self):
		for table in (r.ASSIGNMENT_TRANSITIONS, r.REQUEST_TRANSITIONS, r.USER_TRANSITIONS, r.SITE_TRANSITIONS):
			for targets in table.values():
				self.assertLessEqual(targets, set(table))

	def test_allowed_and_blocked(self):
		r.check_transition(r.REQUEST_TRANSITIONS, "Queued", "Running", "Request")
		r.check_transition(r.REQUEST_TRANSITIONS, None, "Succeeded", "Request")
		r.check_transition(r.REQUEST_TRANSITIONS, "Failed", "Failed", "Request")
		for table, old, new in (
			(r.REQUEST_TRANSITIONS, "Succeeded", "Queued"),
			(r.SITE_TRANSITIONS, "Disconnected", "Active"),
			(r.USER_TRANSITIONS, "Pending", "Suspended"),
			(r.ASSIGNMENT_TRANSITIONS, "Active", "Requested"),
		):
			with self.assertRaises(r.RuleError):
				r.check_transition(table, old, new, "X")

	def test_initial(self):
		r.check_initial("Draft", "Draft", "site")
		with self.assertRaises(r.RuleError):
			r.check_initial("Draft", "Active", "site")


class TestRetry(unittest.TestCase):
	def test_schedule_and_exhaustion(self):
		self.assertEqual([r.retry_delay_seconds(i) for i in range(1, 6)], [60, 300, 1800, 7200, 43200])
		self.assertIsNone(r.retry_delay_seconds(6))
		self.assertIsNone(r.retry_delay_seconds(0))

	def test_jitter_is_clamped(self):
		self.assertEqual(r.retry_delay_seconds(1, 0.2), 72)
		self.assertEqual(r.retry_delay_seconds(1, 5), 72)
		self.assertEqual(r.retry_delay_seconds(1, -5), 48)

	def test_retryable(self):
		self.assertTrue(r.is_retryable("site_unreachable"))
		self.assertTrue(r.is_retryable(None))
		self.assertFalse(r.is_retryable("link_required"))


class TestRedact(unittest.TestCase):
	def test_redacts_nested_secrets(self):
		data = {"a": 1, "client_secret": "x", "nested": {"api_token": "t", "ok": 2}, "rows": [{"password": "p", "n": 1}], "empty_secret": ""}
		out = r.redact(data)
		self.assertEqual(out["client_secret"], "***")
		self.assertEqual(out["nested"], {"api_token": "***", "ok": 2})
		self.assertEqual(out["rows"], [{"password": "***", "n": 1}])
		self.assertEqual(out["empty_secret"], "")
		self.assertEqual(data["client_secret"], "x")

	def test_extra_keys(self):
		self.assertEqual(r.redact({"custom": "v"}, extra_keys=["custom"]), {"custom": "***"})


if __name__ == "__main__":
	unittest.main()
