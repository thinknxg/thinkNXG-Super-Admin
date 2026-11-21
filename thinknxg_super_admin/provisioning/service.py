"""Turns assignment and user changes into Provisioning Requests (durable, idempotent, retried).

Nothing here talks to Keycloak or a site. It only records what must happen and queues the
executor, so a failing site never blocks saving an assignment.
"""

import json

import frappe

from thinknxg_super_admin.provisioning import plan
from thinknxg_super_admin.provisioning.roles import desired_roles_for

REQUEST = "ThinkNXG Provisioning Request"
ASSIGNMENT = "ThinkNXG Site User Assignment"
LIVE = ("Active", "Provisioning")


def _signature(doc) -> str:
	return json.dumps(sorted((r.role_template, r.override_roles or "") for r in doc.role_templates))


def on_assignment_change(doc) -> None:
	before = doc.get_doc_before_save()
	op = plan.assignment_events(
		{"status": before.status, "roles_signature": _signature(before)} if before else None,
		{"status": doc.status, "roles_signature": _signature(doc)},
	)
	if not op:
		return
	if doc.status == "Requested":  # approved on creation: move on to Provisioning
		frappe.db.set_value(ASSIGNMENT, doc.name, "status", "Provisioning", update_modified=False)
		doc.status = "Provisioning"
	enqueue_request(doc, op)


def desired_state_for(assignment, operation: str, central_user=None) -> dict:
	user = central_user or frappe.get_cached_doc("ThinkNXG Central User", assignment.central_user)
	site = frappe.get_cached_doc("ThinkNXG Managed Site", assignment.site)
	roles = desired_roles_for(assignment) if operation in plan.APPLY_OPS else []
	approved = [r for r in (assignment.approved_privileged_roles or "").splitlines() if r]
	return plan.build_desired_state(
		operation=operation,
		central_uid=user.central_uid,
		email=user.email,
		first_name=user.first_name,
		last_name=user.last_name,
		roles=roles,
		approved_privileged=plan.approved_privileged_roles(approved, privileged_approved=bool(approved)) if approved else [],
		deprovision_policy=site.deprovision_policy or "Disable",
		assignment=assignment.name,
	)


def enqueue_request(assignment, operation: str, *, salt: str | None = None):
	"""Create (or find) the request for this exact change and queue it. Returns its name."""
	state = desired_state_for(assignment, operation)
	key_state = dict(state, _salt=salt) if salt else state
	key = plan.request_key(operation, state["central_uid"], assignment.site, key_state)
	existing = frappe.db.get_value(REQUEST, {"idempotency_key": key, "status": ("not in", ("Failed", "Cancelled"))}, "name")
	if existing:
		return existing
	org = frappe.db.get_value("ThinkNXG Managed Site", assignment.site, "organization")
	req = frappe.get_doc(
		{
			"doctype": REQUEST,
			"operation": operation,
			"central_user": assignment.central_user,
			"site": assignment.site,
			"assignment": assignment.name,
			"organization": org,
			"idempotency_key": key,
			"desired_state": json.dumps(state, sort_keys=True),
		}
	).insert(ignore_permissions=True)
	queue(req.name)
	return req.name


def queue(request_name: str) -> None:
	frappe.enqueue(
		"thinknxg_super_admin.provisioning.executor.run_request",
		queue="default",
		request_name=request_name,
		job_id=f"tnxg-prov|{request_name}",
		deduplicate=True,
		enqueue_after_commit=True,
	)


# --------------------------------------------------------------------------- central user lifecycle


def on_central_user_change(user) -> None:
	before = user.get_doc_before_save()
	if not before:
		return
	if before.status != user.status:
		if user.status in ("Suspended", "Deactivated"):
			frappe.enqueue(
				"thinknxg_super_admin.provisioning.service.block_user",
				queue="short",
				central_uid=user.name,
				reason="User Suspended",
				enqueue_after_commit=True,
			)
		elif user.status == "Active" and before.status in ("Suspended", "Deactivated"):
			frappe.enqueue(
				"thinknxg_super_admin.provisioning.service.unblock_user",
				queue="short",
				central_uid=user.name,
				enqueue_after_commit=True,
			)
	elif user.status == "Active" and (before.first_name, before.last_name, before.email) != (user.first_name, user.last_name, user.email):
		for name in frappe.get_all(ASSIGNMENT, filters={"central_user": user.name, "status": "Active"}, pluck="name"):
			enqueue_request(frappe.get_doc(ASSIGNMENT, name), "Update User")


def block_user(central_uid: str, reason: str = "User Suspended") -> None:
	"""Stop access everywhere: block the IdP account first, then disable every site account.

	The IdP block comes first so no new login can start. Keycloak then ends its sessions and sends
	back-channel logout to every site. Each Disable request also ends the site's own sessions, so a
	missed back-channel call cannot leave a session alive.
	"""
	from thinknxg_super_admin.provisioning import executor

	try:
		executor.idp_block(central_uid)
	except Exception:
		frappe.log_error(title="Immediate IdP block failed; the Disable requests will retry it")
	for name in frappe.get_all(ASSIGNMENT, filters={"central_user": central_uid, "status": ("in", LIVE)}, pluck="name"):
		doc = frappe.get_doc(ASSIGNMENT, name)
		doc.status = "Disabled"
		doc.disabled_reason = reason
		doc.save(ignore_permissions=True)  # on_update queues the Disable User request
	frappe.db.commit()


def unblock_user(central_uid: str) -> None:
	for name in frappe.get_all(
		ASSIGNMENT, filters={"central_user": central_uid, "status": "Disabled", "disabled_reason": "User Suspended"}, pluck="name"
	):
		doc = frappe.get_doc(ASSIGNMENT, name)
		doc.status = "Provisioning"
		doc.disabled_reason = ""
		doc.save(ignore_permissions=True)  # Disabled -> Provisioning queues Enable User
	frappe.db.commit()


def expire_assignments() -> None:
	"""Daily: disable Active assignments whose expiry date has passed."""
	for name in frappe.get_all(ASSIGNMENT, filters={"status": "Active", "expires_on": ("<=", frappe.utils.today())}, pluck="name"):
		doc = frappe.get_doc(ASSIGNMENT, name)
		doc.status = "Disabled"
		doc.disabled_reason = "Expired"
		doc.save(ignore_permissions=True)
	frappe.db.commit()


def resync_stale(limit: int = 100, older_than_days: int = 7) -> None:
	"""Daily: re-assert the desired state of the least recently synced Active assignments."""
	cutoff = frappe.utils.add_days(frappe.utils.now_datetime(), -older_than_days)
	rows = frappe.get_all(
		ASSIGNMENT,
		filters={"status": "Active"},
		or_filters=[["last_synced_at", "is", "not set"], ["last_synced_at", "<", cutoff]],
		order_by="last_synced_at asc",
		limit=limit,
		pluck="name",
	)
	for name in rows:
		enqueue_request(frappe.get_doc(ASSIGNMENT, name), "Resync User", salt=frappe.utils.today())
