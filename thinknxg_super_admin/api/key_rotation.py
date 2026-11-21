"""Super Admin controls for central signing key rotation."""

import frappe

from thinknxg_super_admin.security import rotation
from thinknxg_super_admin.security.permissions import is_super_admin


def _guard():
	if not is_super_admin():
		frappe.throw("Not permitted", frappe.PermissionError)


@frappe.whitelist(methods=["GET"])
def status() -> dict:
	_guard()
	return rotation.status()


@frappe.whitelist(methods=["POST"])
def begin() -> dict:
	_guard()
	return rotation.begin()


@frappe.whitelist(methods=["POST"])
def complete(accept_pending=None) -> dict:
	_guard()
	names = frappe.parse_json(accept_pending) if isinstance(accept_pending, str) else accept_pending
	if names is not None and not (isinstance(names, list) and all(isinstance(n, str) for n in names)):
		frappe.throw("accept_pending must be a list of site names.")
	return rotation.complete(names)


@frappe.whitelist(methods=["POST"])
def cancel() -> dict:
	_guard()
	return rotation.cancel()
