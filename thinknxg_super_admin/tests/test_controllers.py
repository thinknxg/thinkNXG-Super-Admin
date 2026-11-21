"""Controller tests. These need a bench site with the app installed:

	bench --site <test-site> run-tests --app thinknxg_super_admin

NOT executed in the environment that generated this file (no bench available). Run them first.
"""

import frappe
from frappe.tests import IntegrationTestCase

from thinknxg_super_admin.security.audit import record


def make_org(code="test-org"):
	if frappe.db.exists("ThinkNXG Organization", code):
		return frappe.get_doc("ThinkNXG Organization", code)
	return frappe.get_doc(
		{"doctype": "ThinkNXG Organization", "org_code": code, "org_name": code.title()}
	).insert()


class TestCentralUser(IntegrationTestCase):
	def test_uid_generated_and_email_normalized(self):
		make_org()
		user = frappe.get_doc(
			{
				"doctype": "ThinkNXG Central User",
				"email": "  Ali@Example.COM ",
				"first_name": "Ali",
				"organization": "test-org",
			}
		).insert()
		self.assertEqual(user.name, user.central_uid)
		self.assertEqual(user.email, "ali@example.com")
		self.assertEqual(user.status, "Pending")
		user.central_uid = "something-else"
		self.assertRaises(frappe.ValidationError, user.save)

	def test_duplicate_email_rejected(self):
		make_org()
		data = {
			"doctype": "ThinkNXG Central User",
			"email": "dup@example.com",
			"first_name": "A",
			"organization": "test-org",
		}
		frappe.get_doc(data).insert()
		self.assertRaises(
			frappe.DuplicateEntryError, frappe.get_doc({**data, "email": "DUP@example.com"}).insert
		)

	def test_cannot_delete(self):
		make_org()
		user = frappe.get_doc(
			{
				"doctype": "ThinkNXG Central User",
				"email": "del@example.com",
				"first_name": "D",
				"organization": "test-org",
			}
		).insert()
		self.assertRaises(frappe.ValidationError, user.delete)


class TestAuditLog(IntegrationTestCase):
	def test_only_record_can_write(self):
		direct = frappe.get_doc(
			{
				"doctype": "ThinkNXG Audit Log",
				"timestamp": frappe.utils.now_datetime(),
				"actor": "x",
				"action": "y",
			}
		)
		self.assertRaises(frappe.PermissionError, direct.insert, ignore_permissions=True)

	def test_record_redacts_and_is_immutable(self):
		record("test", "X", "1", after={"client_secret": "hunter2", "ok": 1})
		row = frappe.get_last_doc("ThinkNXG Audit Log")
		self.assertNotIn("hunter2", row.after)
		row.action = "tampered"
		self.assertRaises(frappe.PermissionError, row.save, ignore_permissions=True)
		self.assertRaises(frappe.PermissionError, row.delete, ignore_permissions=True)


class TestManagedSite(IntegrationTestCase):
	def test_rejects_unsafe_urls(self):
		make_org()
		for url in ("http://a.example.com", "https://127.0.0.1", "https://a.example.com/path"):
			doc = frappe.get_doc(
				{
					"doctype": "ThinkNXG Managed Site",
					"site_name": "bad-site",
					"display_name": "Bad",
					"organization": "test-org",
					"site_url": url,
				}
			)
			self.assertRaises(frappe.ValidationError, doc.insert)

	def test_cannot_start_active(self):
		make_org()
		doc = frappe.get_doc(
			{
				"doctype": "ThinkNXG Managed Site",
				"site_name": "act-site",
				"display_name": "A",
				"organization": "test-org",
				"site_url": "https://act-site.example.com",
				"status": "Active",
			}
		)
		self.assertRaises(frappe.ValidationError, doc.insert)
