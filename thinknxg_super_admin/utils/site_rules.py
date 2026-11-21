"""Pure rules for site pairing and health evaluation (no ``frappe`` import)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections.abc import Mapping, Sequence
from datetime import datetime

from thinknxg_super_admin.utils.rules import RuleError

# ------------------------------------------------------------------ pairing codes

PAIRING_TTL_SECONDS = 30 * 60
PAIRING_MAX_ATTEMPTS = 5


def normalize_code(code: str | None) -> str:
	return (code or "").strip().upper().replace("-", "").replace(" ", "")


def hash_code(code: str) -> str:
	return hashlib.sha256(normalize_code(code).encode()).hexdigest()


def new_pairing_code() -> tuple[str, str]:
	"""Return ``(code, hash)``. The code is shown once; only the hash is stored.

	160 bits of entropy, so a short expiry plus an attempt limit make guessing infeasible.
	"""
	raw = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
	code = "TNXG-" + "-".join(raw[i : i + 8] for i in range(0, len(raw), 8))
	return code, hash_code(code)


def check_pairing(
	stored_hash: str | None,
	expires_at: datetime | None,
	attempts_including_this: int,
	supplied: str | None,
	now: datetime,
) -> None:
	"""Raise :class:`RuleError` unless ``supplied`` matches an open, unexpired, unlocked pairing.

	``attempts_including_this`` must already have been incremented atomically by the caller, so
	concurrent guesses cannot exceed the limit.
	"""
	if not stored_hash or not expires_at:
		raise RuleError("pairing_invalid", "Pairing is not open.")
	if attempts_including_this > PAIRING_MAX_ATTEMPTS:
		raise RuleError("pairing_locked", "Too many attempts. Create a new pairing code.")
	if now > expires_at:
		raise RuleError("pairing_expired", "Pairing code expired.")
	if not hmac.compare_digest(hash_code(supplied or ""), stored_hash):
		raise RuleError("pairing_invalid", "Pairing code is not valid.")


# ------------------------------------------------------------------ health

MAX_CLOCK_SKEW_MS = 30_000  # request signatures tolerate 120 s; warn well before that
MAX_QUEUE_BACKLOG = 500
MAX_LATENCY_MS = 5_000
OFFLINE_AFTER_FAILURES = 3


def _int(value, name: str, low: int, high: int) -> int:
	if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
		raise RuleError("health_invalid", f"{name} is out of range.")
	return value


def _text(value, name: str, limit: int = 64) -> str:
	if not isinstance(value, str) or len(value) > limit:
		raise RuleError("health_invalid", f"{name} is invalid.")
	return value


def parse_health_payload(payload) -> dict:
	"""Validate untrusted data from a site agent. Unknown keys are dropped."""
	if not isinstance(payload, Mapping):
		raise RuleError("health_invalid", "Health payload must be an object.")
	return {
		"agent_version": _text(payload.get("agent_version"), "agent_version"),
		"frappe_version": _text(payload.get("frappe_version"), "frappe_version"),
		"erpnext_version": _text(payload.get("erpnext_version") or "", "erpnext_version"),
		"queue_backlog": _int(payload.get("queue_backlog"), "queue_backlog", 0, 10**9),
		"scheduler_ok": bool(payload.get("scheduler_ok") is True),
		"server_time_ms": _int(payload.get("server_time_ms"), "server_time_ms", 0, 10**14),
	}


def clock_skew_ms(agent_ms: int, sent_ms: int, received_ms: int) -> int:
	"""Agent clock minus the midpoint of the request round trip (positive: agent is ahead)."""
	return int(agent_ms - (sent_ms + received_ms) / 2)


def evaluate_connection(checks: Sequence[Mapping]) -> str:
	"""Connection status from health checks, newest first.

	Offline after ``OFFLINE_AFTER_FAILURES`` consecutive failures; Degraded after any failure or
	when the latest check shows a problem; Online otherwise.
	"""
	if not checks:
		return "Unknown"
	failures = 0
	for check in checks:
		if check.get("reachable"):
			break
		failures += 1
	if failures >= OFFLINE_AFTER_FAILURES:
		return "Offline"
	if failures:
		return "Degraded"
	latest = checks[0]
	if (
		not latest.get("scheduler_ok", True)
		or (latest.get("queue_backlog") or 0) > MAX_QUEUE_BACKLOG
		or abs(latest.get("clock_skew_ms") or 0) > MAX_CLOCK_SKEW_MS
		or (latest.get("latency_ms") or 0) > MAX_LATENCY_MS
	):
		return "Degraded"
	return "Online"


# ------------------------------------------------------------------ role catalogue

MAX_CATALOGUE_ROLES = 2000


def parse_catalogue(message) -> list[str]:
	"""Validate an agent's role catalogue and return the sorted, de-duplicated role names."""
	roles = message.get("roles") if isinstance(message, Mapping) else None
	if not isinstance(roles, list) or len(roles) > MAX_CATALOGUE_ROLES:
		raise RuleError("catalogue_invalid", "Role catalogue is not a list of acceptable size.")
	if any(not isinstance(r, str) or not r or len(r) > 140 for r in roles):
		raise RuleError("catalogue_invalid", "Role catalogue contains an invalid name.")
	return sorted(set(roles))
