"""Signed calls from Super Admin to a site agent."""

import json

import frappe

from thinknxg_super_admin.security import pinned_http, signing
from thinknxg_super_admin.setup.keys import central_signer

TIMEOUT = (3.05, 20)
MAX_BYTES = 256 * 1024
BASE = "/api/method/thinknxg_site_agent.api.v1."


class AgentCallError(Exception):
	def __init__(self, code: str, http_status: int | None = None, message: str = ""):
		super().__init__(message or code)
		self.code = code
		self.http_status = http_status


def call(site_url: str, endpoint: str, payload: dict | None = None) -> tuple[int, dict]:
	"""POST (with ``payload``) or GET ``endpoint`` on the site. Returns ``(http_status, message)``.

	Non-2xx answers that carry a JSON ``message`` object are returned, not raised, so callers can
	read the agent's error ``code``. Network problems raise :class:`AgentCallError`.
	"""
	path = BASE + endpoint
	method = "POST" if payload is not None else "GET"
	body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode() if payload is not None else b""
	key_id, key = central_signer()
	headers = signing.sign_request(key, key_id, method, path, body)
	if payload is not None:
		headers["Content-Type"] = "application/json"
	try:
		resp = pinned_http.request(method, site_url, path, headers=headers, body=body, timeout=TIMEOUT, max_bytes=MAX_BYTES)
	except pinned_http.PinnedError as exc:
		raise AgentCallError(exc.code, exc.status) from exc
	try:
		message = json.loads(resp.body).get("message")
	except (ValueError, AttributeError):
		message = None
	if not isinstance(message, dict):
		if resp.status == 200:
			raise AgentCallError("response_invalid", 200)
		raise AgentCallError(f"http_{resp.status}", resp.status)
	return resp.status, message
