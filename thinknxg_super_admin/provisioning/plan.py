"""Pure planning for provisioning requests (no ``frappe`` import)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta

from thinknxg_super_admin.utils import rules

OPERATIONS = (
	"Create User",
	"Update User",
	"Disable User",
	"Enable User",
	"Deprovision User",
	"Resync User",
)
# Operations that leave the site user enabled with the desired roles.
APPLY_OPS = frozenset({"Create User", "Update User", "Enable User", "Resync User"})
# Agent-side operation names (the agent API is smaller than the request vocabulary).
AGENT_OP = {
	"Create User": "upsert",
	"Update User": "upsert",
	"Resync User": "upsert",
	"Enable User": "upsert",
	"Disable User": "disable",
	"Deprovision User": "deprovision",
}
# What the assignment becomes when the request succeeds.
ASSIGNMENT_AFTER = {
	"Create User": "Active",
	"Update User": "Active",
	"Resync User": "Active",
	"Enable User": "Active",
	"Disable User": "Disabled",
	"Deprovision User": "Removed",
}
RUNNING_TIMEOUT = timedelta(minutes=10)
QUEUED_GRACE = timedelta(minutes=2)
AGENT_RETRYABLE_HTTP = frozenset({408, 425, 429, 500, 502, 503, 504})


def build_desired_state(
	*,
	operation: str,
	central_uid: str,
	email: str,
	first_name: str | None,
	last_name: str | None,
	roles: Iterable[str],
	approved_privileged: Iterable[str],
	deprovision_policy: str,
	assignment: str,
) -> dict:
	"""The exact, versioned payload sent to the agent. Roles and approvals are sorted and unique."""
	if operation not in OPERATIONS:
		raise rules.RuleError("validation_failed", f"Unknown operation {operation}.")
	roles = sorted(set(roles))
	approved = sorted(set(approved_privileged) & set(roles))
	return {
		"operation": AGENT_OP[operation],
		"central_uid": central_uid,
		"email": rules.normalize_email(email),
		"first_name": (first_name or "")[:140],
		"last_name": (last_name or "")[:140],
		"roles": roles,
		"approved_privileged": approved,
		"deprovision_policy": deprovision_policy,
		"assignment": assignment,
	}


def desired_version(state: Mapping) -> str:
	"""Stable short hash of everything that changes the outcome on the site."""
	canonical = json.dumps(state, sort_keys=True, separators=(",", ":"))
	return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def request_key(operation: str, central_uid: str, site: str, state: Mapping) -> str:
	return rules.idempotency_key(operation, central_uid, site, desired_version(state))


def approved_privileged_roles(roles: Iterable[str], *, privileged_approved: bool) -> list[str]:
	"""Privileged roles may be sent only for an assignment that passed second-approver review."""
	if not privileged_approved:
		return []
	return sorted(set(rules.privileged_roles_in(roles)) - {"Administrator"})


def classify_failure(code: str | None, http_status: int | None, attempts_done: int, jitter: float = 0.0) -> tuple[str, int | None]:
	"""Return ``(request_status, delay_seconds)`` after a failed attempt.

	``link_required`` and ``conflict`` need a human (Needs Review). Other non-retryable codes fail
	outright. Retryable ones back off 1m, 5m, 30m, 2h, 12h and then fail.
	"""
	if code in ("link_required", "conflict"):
		return "Needs Review", None
	if not rules.is_retryable(code):
		return "Failed", None
	if http_status is not None and 400 <= http_status < 500 and http_status not in AGENT_RETRYABLE_HTTP:
		return "Failed", None
	delay = rules.retry_delay_seconds(attempts_done, jitter)
	return ("Retrying", delay) if delay else ("Failed", None)


def due_for_retry(status: str, next_retry_at: datetime | None, now: datetime) -> bool:
	return status == "Retrying" and next_retry_at is not None and next_retry_at <= now


def stuck_running(status: str, started_at: datetime | None, now: datetime) -> bool:
	return status == "Running" and started_at is not None and now - started_at > RUNNING_TIMEOUT


def stale_queued(status: str, creation: datetime, now: datetime) -> bool:
	return status == "Queued" and now - creation > QUEUED_GRACE


def assignment_events(before: Mapping | None, after: Mapping) -> str | None:
	"""Which operation (if any) an assignment change calls for.

	``before`` is ``None`` for a new assignment. Mappings need ``status`` and ``roles_signature``.
	"""
	status = after["status"]
	if before is None:
		return "Create User" if status == "Requested" else None
	if before["status"] == status:
		if status == "Active" and before["roles_signature"] != after["roles_signature"]:
			return "Update User"
		return None
	return {
		("Requested", "Provisioning"): "Create User",
		("Disabled", "Provisioning"): "Enable User",
		("Failed", "Provisioning"): "Create User",
		("Active", "Provisioning"): "Update User",
		("Active", "Disabled"): "Disable User",
		("Active", "Removing"): "Deprovision User",
		("Disabled", "Removing"): "Deprovision User",
		("Failed", "Removing"): "Deprovision User",
	}.get((before["status"], status))
