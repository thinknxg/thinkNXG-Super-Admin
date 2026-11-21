"""Operator actions on alerts."""

import frappe

from thinknxg_super_admin.security import audit
from thinknxg_super_admin.security.permissions import can_manage_organization, is_super_admin

ALERT = "ThinkNXG Alert"


@frappe.whitelist(methods=["POST"])
def acknowledge(alert: str) -> str:
	"""Stop reminders for an Open alert. It still escalates and resolves on its own."""
	doc = frappe.get_doc(ALERT, alert)
	allowed = can_manage_organization(doc.organization) if doc.organization else is_super_admin()
	if not allowed:
		frappe.throw("Not permitted", frappe.PermissionError)
	if doc.status != "Open":
		frappe.throw(f"A {doc.status} alert cannot be acknowledged.")
	doc.status = "Acknowledged"
	doc.acknowledged_by = frappe.session.user
	doc.acknowledged_at = frappe.utils.now_datetime()
	doc.save(ignore_permissions=True)
	audit.record("alert.acknowledged", ALERT, alert)
	return "Acknowledged"
