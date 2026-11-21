import frappe
from frappe.model.document import Document

from thinknxg_super_admin.provisioning import service
from thinknxg_super_admin.provisioning.roles import desired_roles_for
from thinknxg_super_admin.security.audit import record_doc_event
from thinknxg_super_admin.security.permissions import can_manage_organization, is_super_admin
from thinknxg_super_admin.utils import rules
from thinknxg_super_admin.utils.frappe_helpers import run_rule

ACTIVE_STATES = ("Requested", "Provisioning", "Active")


def _signature(doc):
	return sorted((r.role_template, r.override_roles or "") for r in doc.role_templates)


class ThinkNXGSiteUserAssignment(Document):
	def autoname(self):
		self.name = rules.assignment_name(self.central_user, self.site)

	def validate(self):
		before = self.get_doc_before_save()
		if self.is_new():
			run_rule(rules.check_initial, rules.ASSIGNMENT_INITIAL, self.status, "assignment")
			self.requested_by = frappe.session.user
		else:
			run_rule(
				rules.check_transition,
				rules.ASSIGNMENT_TRANSITIONS,
				before.status if before else None,
				self.status,
				"Assignment",
			)

		roles_changed = self.is_new() or (before is not None and _signature(before) != _signature(self))
		if self.status in ACTIVE_STATES and roles_changed:
			self.validate_grant()
		if self.expires_on and (roles_changed or self.has_value_changed("expires_on")):
			if frappe.utils.getdate(self.expires_on) <= frappe.utils.getdate(frappe.utils.today()):
				frappe.throw("Expiry date must be in the future.")

	def validate_grant(self):
		site = frappe.get_cached_doc("ThinkNXG Managed Site", self.site)
		user = frappe.get_cached_doc("ThinkNXG Central User", self.central_user)
		if site.status != "Active":
			frappe.throw(f"Site {site.name} is {site.status}. Access can only be granted on an Active site.")
		if user.status not in ("Pending", "Active"):
			frappe.throw(f"User {user.email} is {user.status} and cannot receive new access.")
		if not can_manage_organization(site.organization):
			frappe.throw(
				"You can only grant access on sites of organizations you manage.", frappe.PermissionError
			)
		if not self.role_templates:
			frappe.throw("At least one role template is required.")

		seen = set()
		site_apps = {row.application for row in site.supported_apps}
		privileged = False
		for row in self.role_templates:
			if row.role_template in seen:
				frappe.throw(f"Role template {row.role_template} is listed twice.")
			seen.add(row.role_template)
			template = frappe.get_cached_doc("ThinkNXG Role Template", row.role_template)
			if not template.enabled:
				frappe.throw(f"Role template {template.name} is disabled.")
			allowed_apps = {a.application for a in template.applicable_apps}
			if allowed_apps and site_apps and not (allowed_apps & site_apps):
				frappe.throw(
					f"Role template {template.name} does not apply to the applications on {site.name}."
				)
			privileged = privileged or bool(template.is_privileged)

		roles = run_rule(desired_roles_for, self)
		missing = rules.validate_roles_exist(
			roles, frappe.parse_json(site.roles_catalogue) if site.roles_catalogue else []
		)
		if missing:
			frappe.throw("These roles do not exist on the site: " + ", ".join(missing))
		privileged = privileged or bool(rules.privileged_roles_in(roles))

		if privileged:
			policy = frappe.db.get_value("ThinkNXG Organization", site.organization, "security_policy")
			if policy and not frappe.db.get_value(
				"ThinkNXG Security Policy", policy, "allow_privileged_roles"
			):
				frappe.throw("The organization's security policy does not allow privileged roles.")
		run_rule(
			rules.validate_privileged_approval,
			privileged=privileged,
			requested_by=self.requested_by,
			approved_by=self.approved_by,
			requester_is_super_admin=is_super_admin(self.requested_by),
			approver_is_super_admin=bool(self.approved_by) and is_super_admin(self.approved_by),
		)
		self.approved_privileged_roles = (
			"\n".join(rules.privileged_roles_in(roles)) if privileged and self.approved_by else ""
		)

	def on_update(self):
		record_doc_event(self)
		if not self.flags.get("tnxg_from_executor"):
			service.on_assignment_change(self)

	def on_trash(self):
		frappe.throw("Assignments are kept for history. Set the status to Removed instead.")
