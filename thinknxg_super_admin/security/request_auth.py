"""Authenticate signed requests coming from managed sites (Ed25519, see ``signing.py``)."""

from datetime import timedelta

import frappe

from thinknxg_super_admin.security import signing

SITE = "ThinkNXG Managed Site"
PREVIOUS_KEY_GRACE = timedelta(hours=24)


def _site_for(key_id: str, allow_previous: bool):
	"""Return ``(site_name, pem, via_previous)`` for an Active site holding ``key_id``."""
	row = frappe.db.get_value(
		SITE, {"agent_key_id": key_id, "status": "Active"}, ["name", "agent_public_key"]
	)
	if row and row[1]:
		return row[0], row[1], False
	if allow_previous:
		row = frappe.db.get_value(
			SITE,
			{
				"agent_prev_key_id": key_id,
				"status": "Active",
				"agent_prev_expires": (">", frappe.utils.now_datetime()),
			},
			["name", "agent_prev_public_key"],
		)
		if row and row[1]:
			return row[0], row[1], True
	return None, None, False


def _claim(request_id: str, ttl: int) -> bool:
	return bool(frappe.cache.set(frappe.cache.make_key("thinknxg_replay:" + request_id), 1, nx=True, ex=ttl))


def verify_site_request(*, allow_previous: bool = False) -> dict:
	"""Verify the current request and return ``{"site", "key_id", "request_id", "previous"}``.

	``allow_previous`` accepts a rotated-out key during its grace period. Only the endpoint that
	confirms a key rotation may set it, so a stolen old key cannot do anything else.

	Raises ``frappe.AuthenticationError`` (HTTP 401) with a generic message on any failure; the
	precise reason is only logged.
	"""
	req = frappe.request
	path = req.path + (("?" + req.query_string.decode("latin-1")) if req.query_string else "")

	def _load_key(key_id: str):
		_site, pem, _prev = _site_for(key_id, allow_previous)
		if not pem:
			return None
		try:
			return signing.load_public_key(pem)
		except Exception:
			return None

	try:
		verified = signing.verify_request(
			req.method,
			path,
			req.get_data(),
			req.headers,
			public_key_loader=_load_key,
			claim_request_id=_claim,
		)
	except signing.SignatureError as exc:
		frappe.logger("thinknxg_super_admin").warning("signed_request_rejected code=%s", exc.code)
		frappe.throw("Unauthorized", frappe.AuthenticationError)
	site, _pem, previous = _site_for(verified.key_id, allow_previous)
	if not site:
		frappe.throw("Unauthorized", frappe.AuthenticationError)
	return {"site": site, "key_id": verified.key_id, "request_id": verified.request_id, "previous": previous}
