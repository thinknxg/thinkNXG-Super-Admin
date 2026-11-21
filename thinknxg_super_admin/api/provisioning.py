"""Operator actions on provisioning requests."""

import frappe

from thinknxg_super_admin.provisioning import service
from thinknxg_super_admin.security import audit
from thinknxg_super_admin.security.permissions import can_manage_organization

REQUEST = "ThinkNXG Provisioning Request"


def _load(name: str):
	doc = frappe.get_doc(REQUEST, name)
	if not can_manage_organization(doc.organization):
		frappe.throw("Not permitted", frappe.PermissionError)
	return doc


@frappe.whitelist(methods=["POST"])
def retry(request: str) -> str:
	"""Requeue a Failed or Needs Review request. Attempts start again from 1."""
	doc = _load(request)
	if doc.status not in ("Failed", "Needs Review"):
		frappe.throw(f"A {doc.status} request cannot be retried.")
	doc.status = "Queued"
	doc.attempt_count = 0
	doc.next_retry_at = None
	doc.save()
	audit.record("provisioning.retry", REQUEST, request)
	service.queue(request)
	return "Queued"


@frappe.whitelist(methods=["POST"])
def cancel(request: str) -> str:
	doc = _load(request)
	if doc.status not in ("Queued", "Retrying", "Needs Review", "Running"):
		frappe.throw(f"A {doc.status} request cannot be cancelled.")
	doc.status = "Cancelled"
	doc.save()
	audit.record("provisioning.cancel", REQUEST, request)
	return "Cancelled"
