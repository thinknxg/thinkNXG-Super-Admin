import frappe
from frappe.model.document import Document

from thinknxg_super_admin.security.audit import record_doc_event
from thinknxg_super_admin.utils.frappe_helpers import immutable


class ThinkNXGRoleTemplate(Document):
	def validate(self):
		immutable(self, "template_name")
		apps = [row.application for row in self.applicable_apps]
		if len(apps) != len(set(apps)):
			frappe.throw("An application is listed twice.")
		if self.is_new():
			self.is_privileged = 0

	def on_update(self):
		record_doc_event(self)

	def on_trash(self):
		if frappe.db.exists("ThinkNXG Assignment Role", {"role_template": self.name}) or frappe.db.exists(
			"ThinkNXG Role Mapping", {"role_template": self.name}
		):
			frappe.throw("This template is used by mappings or assignments. Disable it instead.")
		record_doc_event(self, "delete")
