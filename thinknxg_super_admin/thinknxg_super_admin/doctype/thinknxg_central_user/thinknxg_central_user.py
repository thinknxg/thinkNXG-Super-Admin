import uuid

import frappe
from frappe.model.document import Document

from thinknxg_super_admin.provisioning import service
from thinknxg_super_admin.security.audit import record_doc_event
from thinknxg_super_admin.security.permissions import can_manage_organization, is_super_admin
from thinknxg_super_admin.utils import rules
from thinknxg_super_admin.utils.frappe_helpers import immutable, run_rule


class ThinkNXGCentralUser(Document):
	def autoname(self):
		self.central_uid = str(uuid.uuid4())
		self.name = self.central_uid

	def validate(self):
		immutable(self, "central_uid")
		self.email = run_rule(rules.normalize_email, self.email)
		if frappe.db.exists("ThinkNXG Central User", {"email": self.email, "name": ("!=", self.name)}):
			frappe.throw(
				f"A central user with email {self.email} already exists.", frappe.DuplicateEntryError
			)
		self.full_name = " ".join(p for p in (self.first_name, self.last_name) if p)
		self.validate_status()
		self.validate_scope()
		self.validate_super_admin_flag()

	def validate_status(self):
		before = self.get_doc_before_save()
		if self.is_new():
			run_rule(rules.check_initial, rules.USER_INITIAL, self.status, "user")
		else:
			run_rule(
				rules.check_transition,
				rules.USER_TRANSITIONS,
				before.status if before else None,
				self.status,
				"User",
			)

	def validate_scope(self):
		if is_super_admin():
			return
		if not self.organization or not can_manage_organization(self.organization):
			frappe.throw("You can only manage users of organizations you administer.", frappe.PermissionError)

	def validate_super_admin_flag(self):
		before = self.get_doc_before_save()
		changed = bool(self.is_super_admin) != bool(before.is_super_admin if before else 0)
		if changed and frappe.session.user != "Administrator" and "System Manager" not in frappe.get_roles():
			frappe.throw("Only a System Manager can change the Super Admin flag.", frappe.PermissionError)
		if self.is_super_admin and not self.central_frappe_user:
			frappe.throw("A Super Admin needs a linked central Desk user.")

	def on_update(self):
		record_doc_event(self)
		service.on_central_user_change(self)

	def on_trash(self):
		frappe.throw("Central users are never deleted. Deactivate the user instead.")
