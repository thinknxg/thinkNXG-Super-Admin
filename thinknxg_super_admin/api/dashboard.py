"""Server-side aggregation for the overview page. Org Admins only ever see their own organizations."""

import frappe

from thinknxg_super_admin.monitoring import summary
from thinknxg_super_admin.security.permissions import allowed_organizations, has_unscoped_access
from thinknxg_super_admin.setup.roles import AUDITOR, ORG_ADMIN, SUPER_ADMIN

VIEWERS = {SUPER_ADMIN, AUDITOR, ORG_ADMIN, "System Manager"}
LIST_LIMIT = 20
DAYS = 7


def _scope():
	"""``None`` for unscoped viewers, otherwise the organizations the user may see (possibly none)."""
	user = frappe.session.user
	roles = set(frappe.get_roles(user))
	if user != "Administrator" and not roles & VIEWERS:
		frappe.throw("Not permitted", frappe.PermissionError)
	if has_unscoped_access(user):
		return None
	return allowed_organizations(user)  # fail closed: an Org Admin without organizations sees nothing


def _f(scope, filters=None, field="organization"):
	filters = dict(filters or {})
	if scope is not None:
		filters[field] = ("in", scope or ["__none__"])
	return filters


def _count_by(doctype, group_field, scope, filters=None):
	rows = frappe.get_all(
		doctype, filters=_f(scope, filters), fields=[group_field, "count(name) as n"], group_by=group_field
	)
	return rows


@frappe.whitelist(methods=["GET"])
def overview() -> dict:
	scope = _scope()
	now = frappe.utils.now_datetime()
	day_ago = frappe.utils.add_to_date(now, hours=-24)
	week_ago = frappe.utils.add_days(frappe.utils.getdate(), -(DAYS - 1))

	sites = frappe.get_all(
		"ThinkNXG Managed Site",
		filters=_f(scope),
		fields=["name", "display_name", "organization", "status", "connection_status", "last_health_check"],
	)
	active = [s for s in sites if s.status == "Active"]
	requests = frappe.get_all(
		"ThinkNXG Provisioning Request",
		filters=_f(scope, {"creation": (">=", week_ago)}),
		fields=["creation", "status"],
		limit=20000,
	)
	review = frappe.get_all(
		"ThinkNXG Provisioning Request",
		filters=_f(scope, {"status": ("in", ("Needs Review", "Failed"))}),
		fields=["name", "operation", "site", "status", "last_error", "modified"],
		order_by="modified desc",
		limit=LIST_LIMIT,
	)
	alerts = frappe.get_all(
		"ThinkNXG Alert",
		filters=_f(scope, {"status": ("in", ("Open", "Acknowledged"))}),
		fields=["name", "severity", "status", "alert_type", "title", "site", "last_seen"],
		order_by="last_seen desc",
		limit=LIST_LIMIT,
	)
	activity = frappe.get_all(
		"ThinkNXG Login Activity",
		filters=_f(scope),
		fields=["central_user", "site", "event", "timestamp", "reason"],
		order_by="timestamp desc",
		limit=LIST_LIMIT,
	)
	emails = {
		r.name: r.email
		for r in frappe.get_all("ThinkNXG Central User", filters={"name": ("in", [a.central_user for a in activity if a.central_user] or ["-"])}, fields=["name", "email"])
	}
	return {
		"generated_at": str(now),
		"sites": {
			"total": len(sites),
			"active": len(active),
			"connection": summary.fill_counts([{"s": s.connection_status or "Unknown", "n": 1} for s in active], "s", summary.CONNECTION_ORDER),
		},
		"users": summary.fill_counts(_count_by("ThinkNXG Central User", "status", scope), "status", ("Pending", "Active", "Suspended", "Deactivated")),
		"assignments": summary.fill_counts(
			_count_by("ThinkNXG Site User Assignment", "status", scope),
			"status",
			("Requested", "Provisioning", "Active", "Disabled", "Removing", "Removed", "Failed"),
		),
		"requests_daily": summary.daily_buckets([{"day": r.creation, "status": r.status, "n": 1} for r in requests], DAYS, frappe.utils.getdate()),
		"alerts_open": summary.fill_counts(
			_count_by("ThinkNXG Alert", "severity", scope, {"status": "Open"}), "severity", ("Critical", "Warning", "Info")
		),
		"denied_24h": frappe.db.count("ThinkNXG Login Activity", _f(scope, {"event": "Access Denied", "timestamp": (">=", day_ago)})),
		"logins_24h": frappe.db.count("ThinkNXG Login Activity", _f(scope, {"event": "Login Success", "timestamp": (">=", day_ago)})),
		"attention_sites": [
			{**s, "last_health_check": str(s.last_health_check or "")}
			for s in summary.rank_sites_needing_attention(sites, LIST_LIMIT)
		],
		"needs_attention_requests": [{**r, "last_error": summary.clip(r.last_error), "modified": str(r.modified)} for r in review],
		"open_alerts": [{**a, "last_seen": str(a.last_seen)} for a in alerts],
		"recent_activity": [
			{
				"event": a.event,
				"site": a.site,
				"user": emails.get(a.central_user, ""),
				"timestamp": str(a.timestamp),
				"reason": summary.clip(a.reason, 80),
			}
			for a in activity
		],
	}
