import frappe
from frappe.model.document import Document

from thinknxg_super_admin.security.audit import record_doc_event
from thinknxg_super_admin.utils import rules
from thinknxg_super_admin.utils.frappe_helpers import immutable, run_rule


class ThinkNXGOrganization(Document):
	def validate(self):
		run_rule(rules.require_slug, self.org_code, "Organization code")
		immutable(self, "org_code")
		if self.contact_email:
			self.contact_email = run_rule(rules.normalize_email, self.contact_email)

	def on_update(self):
		record_doc_event(self)

	def on_trash(self):
		for doctype in ("ThinkNXG Managed Site", "ThinkNXG Central User"):
			if frappe.db.exists(doctype, {"organization": self.name}):
				frappe.throw(f"Organization {self.name} is used by {doctype} records. Archive it instead.")
		record_doc_event(self, "delete")
