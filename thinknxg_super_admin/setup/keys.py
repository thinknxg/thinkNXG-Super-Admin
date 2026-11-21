"""Central Ed25519 signing key (used to sign requests from Super Admin to site agents)."""

import uuid

import frappe
from frappe.utils.password import get_decrypted_password, set_encrypted_password

from thinknxg_super_admin.security import signing

SSO = "ThinkNXG SSO Configuration"


def ensure_central_keys() -> None:
	"""Create the keypair once. Idempotent; never rotates an existing key."""
	if frappe.db.get_single_value(SSO, "central_key_id") and get_decrypted_password(
		SSO, SSO, "central_private_key", raise_exception=False
	):
		return
	private_pem, public_pem = signing.generate_keypair()
	frappe.db.set_single_value(
		SSO,
		{"central_key_id": "central-" + uuid.uuid4().hex[:16], "central_public_key": public_pem},
	)
	set_encrypted_password(SSO, SSO, private_pem, "central_private_key")
	frappe.db.commit()


def central_signer():
	"""Return ``(key_id, private_key)`` or raise if keys are missing."""
	key_id = frappe.db.get_single_value(SSO, "central_key_id")
	pem = get_decrypted_password(SSO, SSO, "central_private_key", raise_exception=False)
	if not key_id or not pem:
		frappe.throw("Central signing key is not set up. Run bench migrate.")
	return key_id, signing.load_private_key(pem)
