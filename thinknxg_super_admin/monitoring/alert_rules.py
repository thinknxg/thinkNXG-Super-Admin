"""Pure alert rules: which conditions are alerts, and when to notify (no ``frappe`` import)."""

from __future__ import annotations

import html
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta

SEVERITY_RANK = {"Info": 0, "Warning": 1, "Critical": 2}

DEFAULTS = {
	"renotify_hours": 6,
	"needs_review_after_minutes": 60,
	"queue_stuck_minutes": 15,
	"failure_threshold": 5,
	"denial_threshold": 10,
	"stale_health_minutes": 15,
	"email_min_severity": "Warning",
	"enable_email": 1,
	"enable_in_app": 1,
}


def with_defaults(settings: Mapping | None) -> dict:
	"""Fill unset (None) settings with defaults. Single DocTypes return None until first saved."""
	out = dict(DEFAULTS)
	for key, value in (settings or {}).items():
		if value is not None and key in DEFAULTS:
			out[key] = value
	return out


def _cand(key, type_, severity, title, message, site=None, organization=None):
	return {
		"key": key,
		"type": type_,
		"severity": severity,
		"title": title[:140],
		"message": message[:500],
		"site": site,
		"organization": organization,
	}


def evaluate(snapshot: Mapping, settings: Mapping, now: datetime) -> list[dict]:
	"""Return the alert conditions that are true right now.

	``snapshot`` keys: ``sites`` (name, organization, status, connection_status, last_health_check),
	``needs_review`` (site, organization, count_overdue), ``failures`` (site, organization, count),
	``denials`` (site, organization, count), ``queue`` (oldest_queued_age_seconds, count).
	"""
	s = with_defaults(settings)
	out: list[dict] = []
	for site in snapshot.get("sites", []):
		if site.get("status") != "Active":
			continue
		name, org = site["name"], site.get("organization")
		conn = site.get("connection_status")
		if conn == "Offline":
			out.append(_cand(f"site_offline|{name}", "Site Offline", "Critical", f"Site {name} is offline", "Three consecutive health checks failed. Users cannot be provisioned or signed in via this site.", name, org))
		elif conn == "Degraded":
			out.append(_cand(f"site_degraded|{name}", "Site Degraded", "Warning", f"Site {name} is degraded", "The latest health check shows a problem (failed check, stopped scheduler, long queue, clock drift or slow response).", name, org))
		last = site.get("last_health_check")
		if last and now - last > timedelta(minutes=int(s["stale_health_minutes"])):
			out.append(_cand(f"site_stale|{name}", "Health Check Stale", "Warning", f"No recent health check for {name}", f"The last health check was more than {s['stale_health_minutes']} minutes ago. Check the scheduler and workers on the central site.", name, org))
	for row in snapshot.get("needs_review", []):
		if row["count_overdue"] > 0:
			out.append(_cand(f"needs_review|{row['site']}", "Needs Review", "Warning", f"{row['count_overdue']} provisioning request(s) need review on {row['site']}", f"Requests have waited more than {s['needs_review_after_minutes']} minutes for a decision (link required or conflict).", row["site"], row.get("organization")))
	for row in snapshot.get("failures", []):
		if row["count"] >= int(s["failure_threshold"]):
			out.append(_cand(f"failures|{row['site']}", "Repeated Failures", "Critical", f"{row['count']} provisioning failures on {row['site']} in the last hour", "Check the site's health and the Provisioning Log for the failing step.", row["site"], row.get("organization")))
	for row in snapshot.get("denials", []):
		if row["count"] >= int(s["denial_threshold"]):
			out.append(_cand(f"denial_spike|{row['site']}", "Login Denials", "Warning", f"{row['count']} denied logins on {row['site']} in 10 minutes", "A burst of denials can mean a misconfigured assignment or an attempted abuse of first-login creation.", row["site"], row.get("organization")))
	queue = snapshot.get("queue") or {}
	if (queue.get("oldest_queued_age_seconds") or 0) > int(s["queue_stuck_minutes"]) * 60:
		out.append(_cand("queue_stuck", "Queue Stuck", "Critical", "Provisioning queue is not draining", f"A request has been queued for more than {s['queue_stuck_minutes']} minutes. Check that background workers are running.", None, None))
	return out


def reconcile(open_alerts: Mapping[str, Mapping], candidates: Sequence[Mapping], now: datetime, renotify_hours: int) -> dict:
	"""Compare open alerts with current conditions.

	``open_alerts`` maps key to ``{status, severity, last_notified_at}`` for Open and Acknowledged
	alerts (Resolved ones are not included, so a recurring condition re-opens as a new occurrence).

	Returns ``{"open": [...], "update": [...], "resolve": [keys], "notify": [(key, event)]}``
	where event is ``opened``, ``escalated``, ``reminder`` or ``resolved``. Acknowledged alerts
	are never reminded about, but they still escalate and still resolve.
	"""
	by_key = {c["key"]: c for c in candidates}
	result = {"open": [], "update": [], "resolve": [], "notify": []}
	for key, cand in by_key.items():
		prev = open_alerts.get(key)
		if prev is None:
			result["open"].append(cand)
			result["notify"].append((key, "opened"))
			continue
		result["update"].append(cand)
		if SEVERITY_RANK[cand["severity"]] > SEVERITY_RANK[prev["severity"]]:
			result["notify"].append((key, "escalated"))
		elif prev["status"] == "Open":
			last = prev.get("last_notified_at")
			if last is None or now - last >= timedelta(hours=int(renotify_hours)):
				result["notify"].append((key, "reminder"))
	for key in open_alerts:
		if key not in by_key:
			result["resolve"].append(key)
			result["notify"].append((key, "resolved"))
	return result


def meets_email_threshold(severity: str, minimum: str) -> bool:
	return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(minimum, 1)


def render_digest(items: Iterable[Mapping], base_url: str) -> tuple[str, str, str]:
	"""Build ``(subject, html, text)`` for one recipient. All values are HTML-escaped.

	Each item: ``event``, ``severity``, ``title``, ``message``, ``link``. Contains no user data.
	"""
	items = list(items)
	if not items:
		raise ValueError("nothing to render")
	worst = max(items, key=lambda i: SEVERITY_RANK.get(i["severity"], 0))["severity"]
	subject = f"[thinkNXG Super Admin] {len(items)} alert update(s), highest severity {worst}"
	rows_html, rows_text = [], []
	for i in items:
		url = base_url.rstrip("/") + i["link"]
		rows_html.append(
			f"<li><b>{html.escape(i['event'].title())} / {html.escape(i['severity'])}</b>: "
			f"<a href=\"{html.escape(url, quote=True)}\">{html.escape(i['title'])}</a><br>{html.escape(i['message'])}</li>"
		)
		rows_text.append(f"- {i['event'].title()} / {i['severity']}: {i['title']}\n  {i['message']}\n  {url}")
	body = "<p>Alert updates from thinkNXG Super Admin:</p><ul>" + "".join(rows_html) + "</ul>"
	return subject[:200], body, "\n".join(rows_text)
