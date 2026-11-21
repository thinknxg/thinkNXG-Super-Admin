"""Runs one Provisioning Request: IdP step, then the signed site call, with logging and retries."""

import json
import random
import time

import frappe

from thinknxg_super_admin.authentication import keycloak as kc
from thinknxg_super_admin.authentication import site_ops
from thinknxg_super_admin.provisioning import agent_client, plan
from thinknxg_super_admin.security import audit

REQUEST = "ThinkNXG Provisioning Request"
ASSIGNMENT = "ThinkNXG Site User Assignment"
LOCK_TTL = 180


class StepFailed(Exception):
	def __init__(self, code: str, http_status: int | None = None, message: str = ""):
		super().__init__(message or code)
		self.code = code
		self.http_status = http_status


def _log(req, step: str, started: float, *, http_status=None, code=None, message="") -> None:
	frappe.get_doc(
		{
			"doctype": "ThinkNXG Provisioning Log",
			"request": req.name,
			"site": req.site,
			"organization": req.organization,
			"attempt": req.attempt_count,
			"step": step,
			"http_status": http_status,
			"response_code": code,
			"duration_ms": int((time.monotonic() - started) * 1000),
			"message": (message or "")[:500],
		}
	).insert(ignore_permissions=True)


# --------------------------------------------------------------------------- identity provider


def _kc_user_rep(user) -> dict:
	return kc.user_representation(
		central_uid=user.central_uid, email=user.email, first_name=user.first_name, last_name=user.last_name, enabled=user.status == "Active"
	)


def idp_block(central_uid: str) -> None:
	"""Disable the Keycloak account and end all its IdP sessions (back-channel logout to sites)."""
	user = frappe.get_doc("ThinkNXG Central User", central_uid)
	if not user.keycloak_user_id:
		return
	admin = site_ops.get_admin()
	admin.set_user_enabled(user.keycloak_user_id, False)
	admin.logout_user(user.keycloak_user_id)


def _idp_step(req, user, operation: str) -> None:
	blocked = user.status in ("Suspended", "Deactivated")
	if blocked:
		idp_block(user.name)
		return
	if operation not in plan.APPLY_OPS:
		return  # assignment-level disable: the user keeps their IdP account for other sites
	admin = site_ops.get_admin()
	rep = _kc_user_rep(user)
	kc_id = admin.create_user(rep)
	admin.update_user(kc_id, rep)
	if user.keycloak_user_id != kc_id:
		frappe.db.set_value("ThinkNXG Central User", user.name, "keycloak_user_id", kc_id, update_modified=False)


# --------------------------------------------------------------------------- the run


def run_request(request_name: str) -> None:
	req = _claim(request_name)
	if not req:
		return
	try:
		_execute(req)
	except StepFailed as exc:
		_failed(req, exc.code, exc.http_status, str(exc))
	except Exception:
		frappe.log_error(title=f"Provisioning {request_name} crashed")
		_failed(req, "internal_error", None, "Unexpected error; see the Error Log")
	finally:
		frappe.cache.delete_value(f"tnxg_prov_lock|{req.assignment or req.name}")


def _claim(request_name: str):
	row = frappe.db.get_value(REQUEST, request_name, ["status", "next_retry_at", "assignment"], as_dict=True, for_update=True)
	if not row or row.status not in ("Queued", "Retrying"):
		return None
	if row.status == "Retrying" and not plan.due_for_retry(row.status, frappe.utils.get_datetime(row.next_retry_at) if row.next_retry_at else None, frappe.utils.now_datetime()):
		return None
	lock = frappe.cache.make_key(f"tnxg_prov_lock|{row.assignment or request_name}")
	if not frappe.cache.set(lock, 1, nx=True, ex=LOCK_TTL):
		return None  # another change for this assignment is running; the reconciler requeues us
	req = frappe.get_doc(REQUEST, request_name)
	req.status = "Running"
	req.attempt_count = (req.attempt_count or 0) + 1
	req.started_at = frappe.utils.now_datetime()
	req.save(ignore_permissions=True)
	frappe.db.commit()
	return req


def _execute(req) -> None:
	state = json.loads(req.desired_state)
	site = frappe.get_doc("ThinkNXG Managed Site", req.site)
	user = frappe.get_doc("ThinkNXG Central User", req.central_user)
	if site.status != "Active":
		raise StepFailed("conflict", None, f"Site is {site.status}; reconnect it or review this request.")

	started = time.monotonic()
	try:
		_idp_step(req, user, req.operation)
	except kc.KeycloakError as exc:
		_log(req, "idp", started, code=exc.code, message=str(exc))
		raise StepFailed(exc.code, None, str(exc)) from exc
	_log(req, "idp", started, code="ok")

	started = time.monotonic()
	try:
		status, message = agent_client.call(site.site_url, "provision.apply", dict(state, idempotency_key=req.idempotency_key[:64]))
	except agent_client.AgentCallError as exc:
		_log(req, "site_apply", started, http_status=exc.http_status, code=exc.code, message=str(exc))
		raise StepFailed(exc.code, exc.http_status, str(exc)) from exc
	if status != 200 or message.get("ok") is not True:
		code = message.get("code") or f"http_{status}"
		_log(req, "site_apply", started, http_status=status, code=code, message=message.get("message", ""))
		raise StepFailed(code, status, message.get("message", ""))
	_log(req, "site_apply", started, http_status=status, code="ok")
	_succeeded(req, message)


def _assignment(req):
	if not req.assignment or not frappe.db.exists(ASSIGNMENT, req.assignment):
		return None
	doc = frappe.get_doc(ASSIGNMENT, req.assignment)
	doc.flags.tnxg_from_executor = True  # our own status changes must not queue new requests
	return doc


def _succeeded(req, message: dict) -> None:
	now = frappe.utils.now_datetime()
	assignment = _assignment(req)
	if assignment:
		target = plan.ASSIGNMENT_AFTER[req.operation]
		if target != assignment.status and target in _next(assignment.status):
			assignment.status = target
		assignment.link_state = message.get("link_state") or assignment.link_state
		assignment.site_user = message.get("site_user") or assignment.site_user
		assignment.last_synced_at = now
		assignment.last_error = ""
		if target == "Active" and not assignment.provisioned_at:
			assignment.provisioned_at = now
		assignment.save(ignore_permissions=True)
	req.reload()
	req.status = "Succeeded"
	req.finished_at = now
	req.last_error = ""
	req.save(ignore_permissions=True)
	audit.record("provisioning.succeeded", REQUEST, req.name, actor="system")
	frappe.db.commit()


def _next(status: str):
	from thinknxg_super_admin.utils import rules

	return rules.ASSIGNMENT_TRANSITIONS.get(status, frozenset())


def _failed(req, code: str, http_status: int | None, message: str) -> None:
	frappe.db.rollback()
	req.reload()
	new_status, delay = plan.classify_failure(code, http_status, req.attempt_count or 1, random.uniform(-0.2, 0.2))
	req.status = new_status
	req.last_error = f"{code}: {message}"[:140]
	req.next_retry_at = frappe.utils.add_to_date(frappe.utils.now_datetime(), seconds=delay) if delay else None
	if new_status != "Retrying":
		req.finished_at = frappe.utils.now_datetime()
	req.save(ignore_permissions=True)
	assignment = _assignment(req)
	if assignment and new_status in ("Failed", "Needs Review"):
		assignment.last_error = req.last_error
		if new_status == "Needs Review" and code in ("link_required", "conflict"):
			assignment.link_state = "Link Required" if code == "link_required" else "Conflict"
		if new_status == "Failed" and "Failed" in _next(assignment.status):
			assignment.status = "Failed"
		assignment.save(ignore_permissions=True)
	audit.record(f"provisioning.{new_status.lower().replace(' ', '_')}", REQUEST, req.name, actor="system", after={"code": code})
	frappe.db.commit()
