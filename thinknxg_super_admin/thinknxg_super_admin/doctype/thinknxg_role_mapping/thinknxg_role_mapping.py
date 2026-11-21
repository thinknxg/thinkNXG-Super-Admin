import frappe
from frappe.model.document import Document

from thinknxg_super_admin.security.audit import record_doc_event
from thinknxg_super_admin.security.permissions import is_super_admin
from thinknxg_super_admin.utils import rules


class ThinkNXGRoleMapping(Document):
	def validate(self):
		template = frappe.get_cached_doc("ThinkNXG Role Template", self.role_template)
		if self.is_new() and not template.enabled:
			frappe.throw(f"Role template {template.name} is disabled.")

		roles = [(row.site_role or "").strip() for row in self.roles]
		if not roles or not all(roles):
			frappe.throw("At least one role is required and role names cannot be empty.")
		if len(roles) != len(set(roles)):
			frappe.throw("A role is listed twice.")
		for row in self.roles:
			row.site_role = row.site_role.strip()

		if self.site:
			catalogue = frappe.db.get_value("ThinkNXG Managed Site", self.site, "roles_catalogue")
			missing = rules.validate_roles_exist(roles, frappe.parse_json(catalogue) if catalogue else [])
			if missing:
				frappe.throw("These roles do not exist on the site: " + ", ".join(missing))

		if self.is_new() and frappe.db.exists(
			"ThinkNXG Role Mapping",
			{"role_template": self.role_template, "site": self.site or ["is", "not set"]},
		):
			frappe.throw("A mapping for this template and site already exists. Edit it instead.")

		privileged = bool(rules.privileged_roles_in(roles))
		if privileged and not is_super_admin():
			frappe.throw(
				"Only a Super Admin can map a template to System Manager or Administrator.",
				frappe.PermissionError,
			)
		self.is_privileged = 1 if privileged else 0

		before = self.get_doc_before_save()
		if before is not None:
			changed = sorted(r.site_role for r in before.roles) != sorted(roles) or self.has_value_changed(
				"effective_from"
			)
			if changed:
				if not (self.change_reason or "").strip():
					frappe.throw("A change reason is required when changing a mapping.")
				self.version = (before.version or 1) + 1
		self.changed_by = frappe.session.user

	def on_update(self):
		record_doc_event(self)
		self.sync_template_privilege()

	def on_trash(self):
		record_doc_event(self, "delete")
		self.sync_template_privilege(exclude_self=True)

	def sync_template_privilege(self, exclude_self=False):
		filters = {"role_template": self.role_template, "is_privileged": 1}
		if exclude_self:
			filters["name"] = ("!=", self.name)
		flag = 1 if frappe.db.exists("ThinkNXG Role Mapping", filters) else 0
		frappe.db.set_value(
			"ThinkNXG Role Template", self.role_template, "is_privileged", flag, update_modified=False
		)
		frappe.clear_document_cache("ThinkNXG Role Template", self.role_template)
