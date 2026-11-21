"""Administrative actions on Managed Sites (called from the Desk form)."""

import frappe

from thinknxg_super_admin.authentication import site_ops
from thinknxg_super_admin.security import audit
from thinknxg_super_admin.security.permissions import can_manage_organization
from thinknxg_super_admin.utils import site_rules

SITE = "ThinkNXG Managed Site"


def _load(site: str):
	doc = frappe.get_doc(SITE, site)
	if not can_manage_organization(doc.organization):
		frappe.throw("Not permitted", frappe.PermissionError)
	return doc


@frappe.whitelist(methods=["POST"])
def create_pairing_code(site: str) -> dict:
	"""Issue a single-use pairing code (valid 30 minutes). It is returned once and never stored."""
	doc = _load(site)
	if doc.status not in ("Draft", "Inactive"):
		frappe.throw("Pairing is only possible while the site is Draft or Inactive.")
	code, code_hash = site_rules.new_pairing_code()
	expires = frappe.utils.add_to_date(frappe.utils.now_datetime(), seconds=site_rules.PAIRING_TTL_SECONDS)
	frappe.db.set_value(
		SITE,
		site,
		{"pairing_code_hash": code_hash, "pairing_expires_at": expires, "pairing_attempts": 0},
		update_modified=False,
	)
	audit.record("site.pairing_code_created", SITE, site)
	return {"code": code, "expires_at": str(expires)}


@frappe.whitelist(methods=["POST"])
def disconnect(site: str) -> dict:
	"""Permanently disconnect a site: blocks its signed requests and disables its Keycloak client.

	Disconnected is terminal. Existing Desk sessions on the site end at their normal expiry unless
	users are signed out centrally (Phase 6).
	"""
	doc = _load(site)
	if doc.status == "Disconnected":
		return {"status": "Disconnected"}
	doc.status = "Disconnected"
	doc.connection_status = "Unknown"
	doc.save()
	try:
		site_ops.set_client_enabled(site, False)
		client_disabled = True
	except Exception:
		frappe.log_error(title="Keycloak client could not be disabled for " + site)
		client_disabled = False
	audit.record("site.disconnected", SITE, site, after={"client_disabled": client_disabled})
	return {"status": "Disconnected", "keycloak_client_disabled": client_disabled}
