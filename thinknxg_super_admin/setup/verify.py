"""Post-restore and post-upgrade check: can this site still read every secret it stored?

	bench --site SITE execute thinknxg_super_admin.setup.verify.verify_secrets

A restore with the wrong ``encryption_key`` brings back every Password field unreadable. This finds
that immediately instead of at the first login.
"""

import frappe
from frappe.utils.password import get_decrypted_password

from thinknxg_super_admin.security import keyring, signing

SSO = "ThinkNXG SSO Configuration"


def _derived_public(private_pem: str) -> bytes:
	from cryptography.hazmat.primitives import serialization

	key = signing.load_private_key(private_pem)
	return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def verify_secrets() -> dict:
	rows = frappe.db.sql("select doctype, name, fieldname from `__Auth` where encrypted = 1", as_dict=True)
	unreadable = []
	for row in rows:
		try:
			readable = (
				get_decrypted_password(row.doctype, row.name, row.fieldname, raise_exception=False)
				is not None
			)
		except Exception:
			readable = False
		if not readable:
			unreadable.append(f"{row.doctype}/{row.name}/{row.fieldname}")

	central_ok = False
	try:
		pem = get_decrypted_password(SSO, SSO, "central_private_key", raise_exception=False)
		public = frappe.db.get_single_value(SSO, "central_public_key")
		central_ok = bool(pem and public and _derived_public(pem) == keyring.raw_public_bytes(public))
	except Exception:
		central_ok = False
	return {
		"ok": central_ok and not unreadable,
		"encrypted_values": len(rows),
		"unreadable": unreadable,
		"central_signing_key_matches_public": central_ok,
	}
