"""Central signing key rotation with overlap.

1. ``begin``: generate a next key and ask every active site to stage it. The request is signed with
   the current key, which every site already trusts.
2. ``complete``: once every active site has staged the next key, make it the signing key. Sites accept
   both keys until the first request signed with the new one arrives, then drop the old one.
"""

import uuid

import frappe
from frappe.utils.password import get_decrypted_password, set_encrypted_password

from thinknxg_super_admin.provisioning import agent_client
from thinknxg_super_admin.security import audit, keyring, signing

SSO = "ThinkNXG SSO Configuration"
SITE = "ThinkNXG Managed Site"
STAGE_ENDPOINT = "keys.stage_central_key"


def _next() -> tuple[str | None, str | None]:
	return (
		frappe.db.get_single_value(SSO, "central_next_key_id"),
		frappe.db.get_single_value(SSO, "central_next_public_key"),
	)


def _paired_sites(fields=("name", "site_url", "central_key_acked")):
	return frappe.get_all(
		SITE, filters={"status": "Active", "agent_key_id": ("is", "set")}, fields=list(fields)
	)


def status() -> dict:
	next_id, _ = _next()
	acked = {s.name: s.central_key_acked for s in _paired_sites()}
	ready, pending = keyring.rotation_status(next_id, acked)
	return {
		"current_key_id": frappe.db.get_single_value(SSO, "central_key_id"),
		"next_key_id": next_id,
		"ready": ready,
		"pending_sites": pending,
	}


def begin() -> dict:
	next_id, _ = _next()
	if not next_id:
		private_pem, public_pem = signing.generate_keypair()
		next_id = "central-" + uuid.uuid4().hex[:16]
		frappe.db.set_single_value(
			SSO, {"central_next_key_id": next_id, "central_next_public_key": public_pem}
		)
		set_encrypted_password(SSO, SSO, private_pem, "central_next_private_key")
		audit.record("sso.central_key_rotation_started", SSO, SSO, after={"next_key_id": next_id})
	_, public_pem = _next()
	results = {}
	for site in _paired_sites():
		if site.central_key_acked == next_id:
			results[site.name] = "staged"
			continue
		try:
			http_status, message = agent_client.call(
				site.site_url, STAGE_ENDPOINT, {"key_id": next_id, "public_key": public_pem}
			)
		except agent_client.AgentCallError as exc:
			results[site.name] = exc.code
			continue
		if http_status == 200 and message.get("ok") is True:
			frappe.db.set_value(SITE, site.name, "central_key_acked", next_id, update_modified=False)
			results[site.name] = "staged"
		else:
			results[site.name] = str(message.get("code") or f"http_{http_status}")
	frappe.db.commit()
	return {"next_key_id": next_id, "sites": results, **status()}


def complete(accept_pending: list[str] | None = None) -> dict:
	"""Switch signing to the next key. Sites that have not staged it must be listed in ``accept_pending``.

	A site left out of overlap rejects the new signatures and shows as offline until it is paired again.
	"""
	state = status()
	if not state["next_key_id"]:
		frappe.throw("No rotation is in progress.")
	unaccepted = sorted(set(state["pending_sites"]) - set(accept_pending or []))
	if unaccepted:
		frappe.throw("These sites have not staged the new key: " + ", ".join(unaccepted))
	next_id, next_public = _next()
	next_private = get_decrypted_password(SSO, SSO, "central_next_private_key", raise_exception=False)
	if not next_private:
		frappe.throw("The next private key is missing; cancel and start again.")
	old_id = frappe.db.get_single_value(SSO, "central_key_id")
	set_encrypted_password(SSO, SSO, next_private, "central_private_key")
	frappe.db.set_single_value(
		SSO,
		{
			"central_key_id": next_id,
			"central_public_key": next_public,
			"central_next_key_id": None,
			"central_next_public_key": None,
		},
	)
	frappe.db.delete("__Auth", {"doctype": SSO, "name": SSO, "fieldname": "central_next_private_key"})
	audit.record(
		"sso.central_key_rotated",
		SSO,
		SSO,
		before={"key_id": old_id},
		after={"key_id": next_id, "sites_without_overlap": state["pending_sites"]},
	)
	frappe.db.commit()
	return status()


def cancel() -> dict:
	next_id, _ = _next()
	if next_id:
		frappe.db.set_single_value(SSO, {"central_next_key_id": None, "central_next_public_key": None})
		frappe.db.delete("__Auth", {"doctype": SSO, "name": SSO, "fieldname": "central_next_private_key"})
		audit.record("sso.central_key_rotation_cancelled", SSO, SSO, before={"next_key_id": next_id})
		frappe.db.commit()
	return status()
