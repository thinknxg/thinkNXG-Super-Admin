"""Role and organization scoping for the central site.

Fail closed: an Org Admin without any User Permission on ThinkNXG Organization sees nothing.
Frappe's own user-permission engine would otherwise treat "no restriction rows" as "no restriction".
"""

import frappe

from thinknxg_super_admin.setup.roles import AUDITOR, ORG_ADMIN, SUPER_ADMIN

ORG_DOCTYPE = "ThinkNXG Organization"
UNSCOPED_ROLES = {SUPER_ADMIN, AUDITOR, "System Manager"}


def _roles(user: str) -> set[str]:
	return set(frappe.get_roles(user))


def is_super_admin(user: str | None = None) -> bool:
	user = user or frappe.session.user
	return user == "Administrator" or SUPER_ADMIN in _roles(user)


def has_unscoped_access(user: str | None = None) -> bool:
	user = user or frappe.session.user
	return user == "Administrator" or bool(_roles(user) & UNSCOPED_ROLES)


def allowed_organizations(user: str | None = None) -> list[str]:
	from frappe.core.doctype.user_permission.user_permission import get_user_permissions

	user = user or frappe.session.user
	rows = get_user_permissions(user).get(ORG_DOCTYPE, [])
	return sorted({r.get("doc") for r in rows if r.get("doc")})


def can_manage_organization(organization: str | None, user: str | None = None) -> bool:
	user = user or frappe.session.user
	if is_super_admin(user):
		return True
	return bool(organization) and ORG_ADMIN in _roles(user) and organization in allowed_organizations(user)


def org_condition(doctype: str, field: str, user: str | None = None) -> str:
	user = user or frappe.session.user
	if has_unscoped_access(user):
		return ""
	orgs = allowed_organizations(user) if ORG_ADMIN in _roles(user) else []
	if not orgs:
		return "1=0"
	escaped = ", ".join(frappe.db.escape(o) for o in orgs)
	return f"`tab{doctype}`.`{field}` in ({escaped})"


def doc_organization(doc) -> str | None:
	org = doc.get("organization") if doc.meta.has_field("organization") else None
	if org:
		return org
	if doc.get("site"):
		return frappe.db.get_value("ThinkNXG Managed Site", doc.get("site"), "organization")
	return None


def has_org_permission(doc, user=None, ptype=None):
	"""Document-level hook: Org Admins only touch documents of their own organizations."""
	user = user or frappe.session.user
	if has_unscoped_access(user):
		return True
	if doc.doctype == ORG_DOCTYPE:
		return can_manage_organization(doc.name, user)
	org = doc_organization(doc)
	if org is None:
		# Not yet attached to an organization (for example a new Central User without one).
		return ptype == "create"
	return can_manage_organization(org, user)


# Per-DocType wrappers: Frappe calls the query hook with only ``user``.
def qc_organization(user=None):
	return org_condition(ORG_DOCTYPE, "name", user)


def qc_managed_site(user=None):
	return org_condition("ThinkNXG Managed Site", "organization", user)


def qc_central_user(user=None):
	return org_condition("ThinkNXG Central User", "organization", user)


def qc_assignment(user=None):
	return org_condition("ThinkNXG Site User Assignment", "organization", user)


def qc_provisioning_request(user=None):
	return org_condition("ThinkNXG Provisioning Request", "organization", user)


def qc_provisioning_log(user=None):
	return org_condition("ThinkNXG Provisioning Log", "organization", user)


def qc_health_log(user=None):
	return org_condition("ThinkNXG Site Health Log", "organization", user)


def qc_login_activity(user=None):
	return org_condition("ThinkNXG Login Activity", "organization", user)


def qc_alert(user=None):
	return org_condition("ThinkNXG Alert", "organization", user)
