import frappe
from frappe.model.document import Document

from thinknxg_super_admin.security.audit import record_doc_event
from thinknxg_super_admin.utils import rules
from thinknxg_super_admin.utils.frappe_helpers import run_rule


class ThinkNXGApplicationRegistry(Document):
	def validate(self):
		self.launch_path = run_rule(rules.validate_launch_path, self.launch_path)
		roles = [row.role_name.strip() for row in self.default_role_catalogue if row.role_name]
		if len(roles) != len(set(roles)):
			frappe.throw("A role is listed twice in the default role catalogue.")

	def on_update(self):
		record_doc_event(self)

	def on_trash(self):
		if frappe.db.exists("ThinkNXG Site Application", {"application": self.name}):
			frappe.throw("This application is used by registered sites.")
		record_doc_event(self, "delete")
