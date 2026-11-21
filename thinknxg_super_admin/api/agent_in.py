"""Endpoints called by managed sites. Authentication is the Ed25519 request signature."""

import json
import uuid

import frappe
from frappe.rate_limiter import rate_limit

from thinknxg_super_admin.authentication import site_ops
from thinknxg_super_admin.provisioning.roles import desired_roles_for
from thinknxg_super_admin.security import audit, keyring, request_auth, signing
from thinknxg_super_admin.utils import rules, site_rules

# An assignment must be at least approved (Provisioning) to let a user be created on first login.
LOGIN_ALLOWED_STATUSES = ("Provisioning", "Active")


def _deny(site: str, reason: str, central_uid: str | None = None) -> dict:
	frappe.get_doc(
		{
			"doctype": "ThinkNXG Login Activity",
			"event": "Access Denied",
			"site": site,
			"organization": frappe.db.get_value("ThinkNXG Managed Site", site, "organization"),
			"central_user": central_uid
			if central_uid and frappe.db.exists("ThinkNXG Central User", central_uid)
			else None,
			"timestamp": frappe.utils.now_datetime(),
			"ip_address": getattr(frappe.local, "request_ip", None),
			"reason": reason,
		}
	).insert(ignore_permissions=True)
	return {"allowed": False, "reason": reason}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=120, seconds=60)
def authorize_login():
	"""May this central user be created and signed in on the calling site?

	Request body (signed JSON): ``{"central_uid": <uuid4>, "email": <str>}``.
	Response: ``{"allowed": true, "roles": [...], "first_name": ..., "last_name": ...}`` or
	``{"allowed": false, "reason": <code>}``. Roles are advisory: the site refuses privileged
	roles itself.
	"""
	caller = request_auth.verify_site_request()
	site = caller["site"]
	try:
		data = json.loads(frappe.request.get_data() or b"{}")
		parsed = uuid.UUID(str(data["central_uid"]))
		if parsed.version != 4 or str(parsed) != str(data["central_uid"]).lower():
			raise ValueError("central_uid is not a UUIDv4")
		uid = str(parsed)
		email = rules.normalize_email(data["email"])
	except ValueError, KeyError, TypeError, rules.RuleError:
		return _deny(site, "bad_request")

	if not frappe.db.get_value("ThinkNXG Managed Site", site, "auto_create_on_first_login"):
		return _deny(site, "auto_create_disabled", uid)
	user = frappe.db.get_value(
		"ThinkNXG Central User", uid, ["status", "email", "first_name", "last_name"], as_dict=True
	)
	if not user or user.status != "Active":
		return _deny(site, "user_not_active", uid)
	if user.email != email:
		return _deny(site, "email_mismatch", uid)

	name = rules.assignment_name(uid, site)
	if not frappe.db.exists("ThinkNXG Site User Assignment", name):
		return _deny(site, "not_assigned", uid)
	assignment = frappe.get_doc("ThinkNXG Site User Assignment", name)
	if assignment.status not in LOGIN_ALLOWED_STATUSES:
		return _deny(site, "assignment_not_active", uid)
	if assignment.expires_on and frappe.utils.getdate(assignment.expires_on) < frappe.utils.getdate():
		return _deny(site, "assignment_expired", uid)

	return {
		"allowed": True,
		"assignment": name,
		"first_name": user.first_name,
		"last_name": user.last_name,
		"roles": desired_roles_for(assignment),
	}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=10, seconds=600)
def pair(
	site_name: str | None = None,
	code: str | None = None,
	agent_public_key: str | None = None,
	agent_version: str | None = None,
):
	"""Pair a site agent using a single-use code (created in Desk, valid 30 minutes).

	The agent generates its own keypair and sends only the public key; its private key never
	leaves the site. The response carries the central public key and the OIDC client settings,
	including the client secret, which is shown to the agent exactly once (Keycloak keeps it).
	Every failure returns the same generic 401; the reason is only logged.
	"""
	if not (frappe.request.scheme == "https" or frappe.conf.get("developer_mode")):
		frappe.throw("Unauthorized", frappe.AuthenticationError)
	try:
		return _pair(site_name, code, agent_public_key, agent_version)
	except (rules.RuleError, ValueError) as exc:
		frappe.logger("thinknxg_super_admin").warning(
			"pairing_rejected code=%s", getattr(exc, "code", "invalid")
		)
		frappe.throw("Unauthorized", frappe.AuthenticationError)


def _pair(site_name, code, agent_public_key, agent_version) -> dict:
	if not isinstance(site_name, str) or not rules.is_valid_slug(site_name):
		raise rules.RuleError("pairing_invalid", "bad site name")
	row = frappe.db.get_value(
		"ThinkNXG Managed Site",
		site_name,
		["status", "pairing_code_hash", "pairing_expires_at", "pairing_attempts"],
		as_dict=True,
		for_update=True,
	)
	if not row:
		raise rules.RuleError("pairing_invalid", "unknown site")
	attempts = (row.pairing_attempts or 0) + 1
	frappe.db.set_value(
		"ThinkNXG Managed Site", site_name, "pairing_attempts", attempts, update_modified=False
	)
	frappe.db.commit()  # failed guesses must persist even though we raise below
	site_rules.check_pairing(
		row.pairing_code_hash,
		frappe.utils.get_datetime(row.pairing_expires_at) if row.pairing_expires_at else None,
		attempts,
		code,
		frappe.utils.now_datetime(),
	)
	if row.status not in ("Draft", "Inactive"):
		raise rules.RuleError("pairing_invalid", "site not pairable")
	try:
		signing.load_public_key(agent_public_key or "")
	except Exception as exc:
		raise ValueError("bad public key") from exc

	site = frappe.get_doc("ThinkNXG Managed Site", site_name)
	client_id, client_secret = site_ops.ensure_client(site)
	key_id = "agt-" + uuid.uuid4().hex
	site.update(
		{
			"keycloak_client_id": client_id,
			"agent_key_id": key_id,
			"agent_public_key": agent_public_key,
			"agent_api_version": (agent_version or "")[:64],
			"paired_at": frappe.utils.now_datetime(),
			"pairing_code_hash": None,  # single use
			"pairing_expires_at": None,
			"pairing_attempts": 0,
			"connection_status": "Unknown",
		}
	)
	site.save(ignore_permissions=True)
	audit.record("site.paired", "ThinkNXG Managed Site", site_name, actor=f"site:{site_name}")
	frappe.db.commit()

	sso = frappe.get_single("ThinkNXG SSO Configuration")
	idp = frappe.get_doc("ThinkNXG Identity Provider", sso.identity_provider)
	return {
		"api_version": "1",
		"central_url": frappe.utils.get_url(),
		"central_key_id": sso.central_key_id,
		"central_public_key": sso.central_public_key,
		"agent_key_id": key_id,
		"issuer_url": idp.issuer_url,
		"client_id": client_id,
		"client_secret": client_secret,
		"auto_create_on_first_login": int(bool(site.auto_create_on_first_login)),
	}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=120, seconds=60)
def report_linked():
	"""A site created a user on first login. Move the assignment from Provisioning to Active."""
	caller = request_auth.verify_site_request()
	site = caller["site"]
	try:
		data = json.loads(frappe.request.get_data() or b"{}")
		parsed = uuid.UUID(str(data["central_uid"]))
		if parsed.version != 4 or str(parsed) != str(data["central_uid"]).lower():
			raise ValueError("central_uid is not a UUIDv4")
		site_user = str(data["site_user"])[:140]
	except ValueError, KeyError, TypeError:
		return {"ok": False, "code": "bad_request"}
	name = rules.assignment_name(str(parsed), site)
	if not frappe.db.exists("ThinkNXG Site User Assignment", name):
		return {"ok": False, "code": "not_assigned"}
	doc = frappe.get_doc("ThinkNXG Site User Assignment", name)
	doc.flags.tnxg_from_executor = True
	if doc.status == "Provisioning":
		doc.status = "Active"
		doc.provisioned_at = doc.provisioned_at or frappe.utils.now_datetime()
	if doc.status in ("Active", "Provisioning"):
		doc.link_state = "Linked"
		doc.site_user = site_user
		doc.last_synced_at = frappe.utils.now_datetime()
		doc.save(ignore_permissions=True)
	return {"ok": True}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=300, seconds=60)
def report_login():
	"""A site completed an OIDC login. Recorded only for users with an assignment on that site.

	The site is authenticated by its signature, so it can only write activity for itself; the
	user is looked up by central_uid and ignored when no assignment exists. Values are bounded.
	"""
	caller = request_auth.verify_site_request()
	site = caller["site"]
	try:
		data = json.loads(frappe.request.get_data() or b"{}")
		parsed = uuid.UUID(str(data["central_uid"]))
		if parsed.version != 4 or str(parsed) != str(data["central_uid"]).lower():
			raise ValueError("central_uid is not a UUIDv4")
		ip = str(data.get("ip") or "")[:45]
		agent = str(data.get("user_agent") or "")[:300]
	except ValueError, KeyError, TypeError:
		return {"ok": False, "code": "bad_request"}
	uid = str(parsed)
	if not frappe.db.exists("ThinkNXG Site User Assignment", rules.assignment_name(uid, site)):
		return {"ok": False, "code": "not_assigned"}
	now = frappe.utils.now_datetime()
	frappe.get_doc(
		{
			"doctype": "ThinkNXG Login Activity",
			"event": "Login Success",
			"central_user": uid,
			"site": site,
			"organization": frappe.db.get_value("ThinkNXG Managed Site", site, "organization"),
			"timestamp": now,
			"ip_address": ip,
			"user_agent": agent,
		}
	).insert(ignore_permissions=True)
	frappe.db.set_value(
		"ThinkNXG Central User", uid, {"last_login": now, "last_site_accessed": site}, update_modified=False
	)
	return {"ok": True}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=10, seconds=600)
def rotate_agent_key():
	"""A site replaces its signing key. The old key keeps working only for this call for 24 hours.

	Signed by the current key. A request signed by the previous key is accepted only to confirm a
	rotation that already happened (the site did not see the reply), never to start another one,
	so a stolen old key cannot take over the site.
	"""
	caller = request_auth.verify_site_request(allow_previous=True)
	site = caller["site"]
	try:
		data = json.loads(frappe.request.get_data() or b"{}")
		new_id, new_pem = data["new_key_id"], data["new_public_key"]
	except ValueError, KeyError, TypeError:
		return {"ok": False, "code": "bad_request"}
	doc = frappe.db.get_value(
		"ThinkNXG Managed Site", site, ["agent_key_id", "agent_public_key"], as_dict=True
	)
	current = keyring.KeyEntry(doc.agent_key_id, doc.agent_public_key)
	try:
		if new_id == doc.agent_key_id:
			same = keyring.raw_public_bytes(new_pem) == keyring.raw_public_bytes(doc.agent_public_key)
			return {"ok": True} if same else {"ok": False, "code": "key_id_reused"}
		if caller["previous"]:
			return {"ok": False, "code": "stale_key"}
		keyring.validate_new_key(new_id, new_pem, [current])
	except keyring.KeyringError as exc:
		return {"ok": False, "code": exc.code}
	frappe.db.set_value(
		"ThinkNXG Managed Site",
		site,
		{
			"agent_prev_key_id": doc.agent_key_id,
			"agent_prev_public_key": doc.agent_public_key,
			"agent_prev_expires": frappe.utils.add_to_date(frappe.utils.now_datetime(), hours=24),
			"agent_key_id": new_id,
			"agent_public_key": new_pem,
		},
	)
	audit.record(
		"site.agent_key_rotated",
		"ThinkNXG Managed Site",
		site,
		before={"key_id": doc.agent_key_id},
		after={"key_id": new_id},
	)
	return {"ok": True}
