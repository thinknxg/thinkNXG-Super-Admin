import frappe
from frappe.model.document import Document

from thinknxg_super_admin.security.audit import record_doc_event
from thinknxg_super_admin.utils import rules
from thinknxg_super_admin.utils.frappe_helpers import run_rule


class ThinkNXGSecurityPolicy(Document):
	def validate(self):
		if (self.password_min_length or 0) < 10:
			frappe.throw("Minimum password length must be at least 10.")
		if (self.max_failed_logins or 0) < 3 or (self.lockout_minutes or 0) < 1:
			frappe.throw("Allow at least 3 failed logins and a lockout of at least 1 minute.")
		if (self.session_idle_ttl_minutes or 0) < 5 or (
			self.session_absolute_ttl_minutes or 0
		) < self.session_idle_ttl_minutes:
			frappe.throw("Session lifetimes are invalid: idle >= 5 minutes and absolute >= idle.")
		cidrs = run_rule(rules.validate_cidrs, [row.cidr for row in self.allowed_ip_ranges])
		for row, cidr in zip(self.allowed_ip_ranges, cidrs, strict=True):
			row.cidr = cidr

	def on_update(self):
		record_doc_event(self)

	def on_trash(self):
		if frappe.db.exists("ThinkNXG Organization", {"security_policy": self.name}):
			frappe.throw("This policy is assigned to an organization.")
		record_doc_event(self, "delete")
