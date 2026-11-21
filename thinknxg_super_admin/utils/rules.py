"""Pure business rules for thinkNXG Super Admin (no ``frappe`` import, fully unit-testable).

Controllers call these and translate :class:`RuleError` into ``frappe.throw``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from urllib.parse import urlsplit

# Path of the OIDC callback on every managed site. Phase 4 implements it; Managed Site
# redirect URIs are validated against this contract.
AGENT_CALLBACK_PATH = "/api/method/thinknxg_site_agent.api.v1.auth.callback"

# A grant of any of these roles needs a second approver. Extend only by code review.
PRIVILEGED_ROLES = frozenset({"System Manager", "Administrator"})

SECRET_KEY_PARTS = ("secret", "password", "passwd", "token", "private_key", "pairing_code", "api_key", "authorization")

SLUG_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Public suffixes with more than one label that matter for GCC and common markets. Used only to
# split a host into domain and subdomain for display and filtering, never for security.
MULTI_LABEL_SUFFIXES = frozenset(
	{
		"com.om", "co.om", "org.om", "net.om", "gov.om", "edu.om",
		"com.sa", "org.sa", "net.sa", "gov.sa", "edu.sa",
		"co.ae", "com.ae", "net.ae", "org.ae", "gov.ae",
		"com.qa", "net.qa", "org.qa", "com.kw", "com.bh", "org.bh",
		"co.uk", "org.uk", "ac.uk", "co.in", "net.in", "org.in", "com.au", "co.za",
	}
)


class RuleError(ValueError):
	"""A violated business rule. ``code`` is a stable machine code."""

	def __init__(self, code: str, message: str):
		super().__init__(message)
		self.code = code
		self.message = message


# ---------------------------------------------------------------- identifiers


def is_valid_slug(value: str | None) -> bool:
	return bool(value) and bool(SLUG_RE.match(value))


def require_slug(value: str | None, label: str) -> str:
	if not is_valid_slug(value):
		raise RuleError(
			"validation_failed",
			f"{label} must use lowercase letters, digits and hyphens (max 64 characters, "
			"no leading or trailing hyphen).",
		)
	return value  # type: ignore[return-value]


def normalize_email(value: str | None) -> str:
	email = (value or "").strip().lower()
	if not EMAIL_RE.match(email) or len(email) > 254:
		raise RuleError("validation_failed", "A valid email address is required.")
	return email


def split_host(host: str) -> tuple[str, str]:
	"""Return (domain, subdomain) for display. ``a.b.example.com.om`` -> (``example.com.om``, ``a.b``)."""
	labels = host.lower().rstrip(".").split(".")
	if len(labels) < 2:
		return host, ""
	tail = 3 if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES else 2
	if len(labels) <= tail:
		return ".".join(labels), ""
	return ".".join(labels[-tail:]), ".".join(labels[:-tail])


def assignment_name(central_user: str, site: str) -> str:
	"""Deterministic primary key so (user, site) is unique at the database level."""
	digest = hashlib.sha256(f"{central_user}\n{site}".encode()).hexdigest()
	return "ASG-" + digest[:24]


def idempotency_key(operation: str, central_uid: str, site: str, desired_version: str | int) -> str:
	raw = "\n".join([operation, central_uid, site, str(desired_version)])
	return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------- URLs


def validate_https_url(url: str, *, allow_path: bool, label: str) -> str:
	"""Validate an https URL and return it without trailing slash. No network access."""
	parts = urlsplit((url or "").strip())
	if parts.scheme != "https" or not parts.hostname:
		raise RuleError("validation_failed", f"{label} must be an https URL.")
	if parts.username or parts.password or parts.fragment or parts.query:
		raise RuleError("validation_failed", f"{label} must not contain credentials, query or fragment.")
	if not allow_path and parts.path not in ("", "/"):
		raise RuleError("validation_failed", f"{label} must be an origin without a path.")
	return f"https://{parts.netloc.lower()}{parts.path.rstrip('/')}"


def validate_redirect_uris(origin: str, uris: Iterable[str]) -> list[str]:
	"""Every redirect URI must be https, same origin as the site, exact (no wildcard)."""
	cleaned: list[str] = []
	for raw in uris:
		uri = (raw or "").strip()
		if "*" in uri:
			raise RuleError("validation_failed", f"Wildcards are not allowed in redirect URIs: {uri}")
		parts = urlsplit(uri)
		if parts.scheme != "https" or parts.fragment or parts.username or parts.password:
			raise RuleError("validation_failed", f"Invalid redirect URI: {uri}")
		if f"https://{parts.netloc.lower()}" != origin:
			raise RuleError("validation_failed", f"Redirect URI {uri} is not on the site origin {origin}.")
		if not parts.path.startswith("/") or parts.path.startswith("//"):
			raise RuleError("validation_failed", f"Invalid redirect URI path: {uri}")
		if uri in cleaned:
			raise RuleError("validation_failed", f"Duplicate redirect URI: {uri}")
		cleaned.append(uri)
	return cleaned


def validate_launch_path(path: str) -> str:
	"""Relative same-site path only: blocks open redirects through the app launch path."""
	p = (path or "").strip()
	if not p.startswith("/") or p.startswith("//") or "\\" in p or "://" in p or "\n" in p or "\r" in p:
		raise RuleError("validation_failed", "Launch path must be a relative path starting with a single '/'.")
	return p


def validate_cidrs(values: Iterable[str]) -> list[str]:
	out = []
	for v in values:
		try:
			out.append(str(ipaddress.ip_network((v or "").strip(), strict=False)))
		except ValueError:
			raise RuleError("validation_failed", f"Invalid CIDR range: {v}") from None
	return out


# ---------------------------------------------------------------- roles and privilege


def is_privileged_role(role: str) -> bool:
	return (role or "").strip() in PRIVILEGED_ROLES


def privileged_roles_in(roles: Iterable[str]) -> list[str]:
	return sorted({r.strip() for r in roles if is_privileged_role(r)})


def parse_override_roles(text: str | None) -> list[str]:
	"""Override roles are stored as a JSON list of role names."""
	if not text or not text.strip():
		return []
	try:
		data = json.loads(text)
	except ValueError:
		raise RuleError("validation_failed", "Override roles must be a JSON list of role names.") from None
	if not isinstance(data, list) or len(data) > 50:
		raise RuleError("validation_failed", "Override roles must be a JSON list of at most 50 role names.")
	roles = []
	for item in data:
		if not isinstance(item, str) or not item.strip() or len(item) > 140:
			raise RuleError("validation_failed", "Every override role must be a non-empty string.")
		if item.strip() not in roles:
			roles.append(item.strip())
	return roles


def validate_privileged_approval(
	*,
	privileged: bool,
	requested_by: str | None,
	approved_by: str | None,
	requester_is_super_admin: bool,
	approver_is_super_admin: bool,
) -> None:
	"""Granting System Manager or Administrator needs two different Super Admins."""
	if not privileged:
		return
	if not requester_is_super_admin:
		raise RuleError("forbidden", "Only a Super Admin can request a privileged role.")
	if not approved_by:
		raise RuleError("approval_required", "A second approver is required for privileged roles.")
	if approved_by == requested_by:
		raise RuleError("approval_required", "The approver must be a different person from the requester.")
	if not approver_is_super_admin:
		raise RuleError("forbidden", "The approver must hold the Super Admin role.")


def resolve_roles(template: str, site: str, mappings: Sequence[Mapping], *, now: datetime | None = None) -> list[str]:
	"""Roles a template grants on a site. A site-specific mapping fully replaces the default one."""
	now = now or datetime.now()
	site_specific = None
	default = None
	for m in mappings:
		if m.get("role_template") != template:
			continue
		eff = m.get("effective_from")
		if eff and eff > now:
			continue
		if m.get("site") == site:
			site_specific = m
		elif not m.get("site"):
			default = m
	chosen = site_specific or default
	if chosen is None:
		raise RuleError("validation_failed", f"Role template {template} has no mapping for site {site}.")
	return sorted({r.strip() for r in chosen.get("roles", []) if r and r.strip()})


def desired_roles(
	templates: Iterable[str],
	site: str,
	mappings: Sequence[Mapping],
	overrides: Iterable[str] = (),
	*,
	now: datetime | None = None,
) -> list[str]:
	roles: set[str] = set(r.strip() for r in overrides if r and r.strip())
	for t in templates:
		roles.update(resolve_roles(t, site, mappings, now=now))
	return sorted(roles)


def validate_roles_exist(roles: Iterable[str], catalogue: Iterable[str] | None) -> list[str]:
	"""Return roles missing from the site's reported catalogue (empty catalogue = unknown, no check)."""
	known = set(catalogue or [])
	if not known:
		return []
	return sorted({r for r in roles if r not in known})


# ---------------------------------------------------------------- state machines

ASSIGNMENT_INITIAL = "Requested"
ASSIGNMENT_TRANSITIONS: dict[str, frozenset[str]] = {
	"Requested": frozenset({"Provisioning", "Failed", "Removed"}),
	"Provisioning": frozenset({"Active", "Failed", "Removing"}),
	"Active": frozenset({"Provisioning", "Disabled", "Removing"}),
	"Disabled": frozenset({"Provisioning", "Removing"}),
	"Removing": frozenset({"Removed", "Failed"}),
	"Failed": frozenset({"Provisioning", "Removing", "Removed"}),
	"Removed": frozenset({"Requested"}),
}

REQUEST_INITIAL = "Queued"
REQUEST_TRANSITIONS: dict[str, frozenset[str]] = {
	"Queued": frozenset({"Running", "Cancelled"}),
	"Running": frozenset({"Succeeded", "Retrying", "Failed", "Needs Review", "Cancelled"}),
	"Retrying": frozenset({"Running", "Failed", "Cancelled"}),
	"Failed": frozenset({"Queued"}),
	"Needs Review": frozenset({"Queued", "Cancelled"}),
	"Succeeded": frozenset(),
	"Cancelled": frozenset(),
}

USER_INITIAL = "Pending"
USER_TRANSITIONS: dict[str, frozenset[str]] = {
	"Pending": frozenset({"Active", "Deactivated"}),
	"Active": frozenset({"Suspended", "Deactivated"}),
	"Suspended": frozenset({"Active", "Deactivated"}),
	"Deactivated": frozenset({"Active"}),
}

SITE_INITIAL = "Draft"
SITE_TRANSITIONS: dict[str, frozenset[str]] = {
	"Draft": frozenset({"Active", "Disconnected"}),
	"Active": frozenset({"Inactive", "Disconnected"}),
	"Inactive": frozenset({"Active", "Disconnected"}),
	"Disconnected": frozenset(),
}


def check_transition(table: Mapping[str, frozenset[str]], old: str | None, new: str, label: str) -> None:
	if old is None or old == new:
		return
	if new not in table.get(old, frozenset()):
		raise RuleError("conflict", f"{label} cannot change from {old} to {new}.")


def check_initial(initial: str, new: str, label: str) -> None:
	if new != initial:
		raise RuleError("conflict", f"A new {label} must start as {initial}.")


# ---------------------------------------------------------------- retry policy

RETRY_SCHEDULE_SECONDS = (60, 300, 1800, 7200, 43200)
NON_RETRYABLE_CODES = frozenset(
	{"validation_failed", "forbidden", "link_required", "conflict", "unsupported_version", "approval_required"}
)


def retry_delay_seconds(attempts_done: int, jitter: float = 0.0) -> int | None:
	"""Delay before the next attempt, or None when attempts are exhausted.

	``jitter`` is a fraction in [-0.2, 0.2] chosen by the caller (keeps this function deterministic).
	"""
	if attempts_done < 1 or attempts_done > len(RETRY_SCHEDULE_SECONDS):
		return None
	jitter = max(-0.2, min(0.2, jitter))
	return max(1, round(RETRY_SCHEDULE_SECONDS[attempts_done - 1] * (1 + jitter)))


def is_retryable(code: str | None) -> bool:
	return (code or "") not in NON_RETRYABLE_CODES


# ---------------------------------------------------------------- redaction


def redact(value, extra_keys: Iterable[str] = ()):
	"""Deep-copy ``value`` replacing secret-looking values with ``***`` (for audit and logs)."""
	extra = {k.lower() for k in extra_keys}

	def secret(key) -> bool:
		k = str(key).lower()
		return k in extra or any(part in k for part in SECRET_KEY_PARTS)

	if isinstance(value, Mapping):
		return {k: ("***" if secret(k) and v not in (None, "") else redact(v, extra)) for k, v in value.items()}
	if isinstance(value, (list, tuple)):
		return [redact(v, extra) for v in value]
	return value
