import frappe
from frappe.model.document import Document


class ThinkNXGAuditLog(Document):
	"""Append-only. Rows are written only by ``security.audit.record``."""

	def before_insert(self):
		if not frappe.flags.get("tnxg_audit_write"):
			frappe.throw("Audit entries can only be written by the system.", frappe.PermissionError)

	def validate(self):
		if not self.is_new():
			frappe.throw("Audit entries cannot be modified.", frappe.PermissionError)

	def on_trash(self):
		if not frappe.flags.get("tnxg_audit_retention"):
			frappe.throw("Audit entries cannot be deleted.", frappe.PermissionError)
