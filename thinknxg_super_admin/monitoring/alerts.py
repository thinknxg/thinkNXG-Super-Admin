"""Evaluate alert conditions every 5 minutes, keep Alert documents in step, and notify."""

import hashlib

import frappe

from thinknxg_super_admin.monitoring import alert_rules, notifier

ALERT = "ThinkNXG Alert"
SETTINGS = "ThinkNXG Alert Settings"
LOCK = "thinknxg_alert_evaluator"


def alert_name(key: str) -> str:
	return "ALT-" + hashlib.sha256(key.encode()).hexdigest()[:20]


def load_settings() -> dict:
	doc = frappe.get_cached_doc(SETTINGS)
	return {k: doc.get(k) for k in [*alert_rules.DEFAULTS, "extra_email_recipients"]}


def build_snapshot(settings: dict, now) -> dict:
	cfg = alert_rules.with_defaults(settings)
	review_before = frappe.utils.add_to_date(now, minutes=-int(cfg["needs_review_after_minutes"]))
	hour_ago = frappe.utils.add_to_date(now, hours=-1)
	ten_min_ago = frappe.utils.add_to_date(now, minutes=-10)
	oldest = frappe.get_all(
		"ThinkNXG Provisioning Request",
		filters={"status": "Queued"},
		fields=["creation"],
		order_by="creation asc",
		limit=1,
	)
	return {
		"sites": frappe.get_all(
			"ThinkNXG Managed Site",
			fields=["name", "organization", "status", "connection_status", "last_health_check"],
		),
		"needs_review": frappe.get_all(
			"ThinkNXG Provisioning Request",
			filters={"status": "Needs Review", "modified": ("<", review_before)},
			fields=["site", "organization", "count(name) as count_overdue"],
			group_by="site, organization",
		),
		"failures": frappe.get_all(
			"ThinkNXG Provisioning Request",
			filters={"status": "Failed", "modified": (">=", hour_ago)},
			fields=["site", "organization", "count(name) as count"],
			group_by="site, organization",
		),
		"denials": frappe.get_all(
			"ThinkNXG Login Activity",
			filters={"event": "Access Denied", "timestamp": (">=", ten_min_ago), "site": ("is", "set")},
			fields=["site", "organization", "count(name) as count"],
			group_by="site, organization",
		),
		"queue": {
			"oldest_queued_age_seconds": int(
				(now - frappe.utils.get_datetime(oldest[0].creation)).total_seconds()
			)
			if oldest
			else 0,
			"count": frappe.db.count("ThinkNXG Provisioning Request", {"status": "Queued"}),
		},
	}


def evaluate_all() -> None:
	"""Scheduler entry. A cache lock keeps overlapping runs from double-notifying."""
	if not frappe.cache.set(frappe.cache.make_key(LOCK), 1, nx=True, ex=240):
		return
	try:
		now = frappe.utils.now_datetime()
		run(now)
		# Heartbeat for api.ops.healthz: only a completed run counts, so a dead scheduler is visible.
		frappe.db.set_single_value(SETTINGS, "last_evaluated_at", now)
		frappe.db.commit()
	finally:
		frappe.cache.delete_value(LOCK)


def run(now) -> list[dict]:
	settings = load_settings()
	candidates = alert_rules.evaluate(build_snapshot(settings, now), settings, now)
	open_rows = frappe.get_all(
		ALERT,
		filters={"status": ("in", ("Open", "Acknowledged"))},
		fields=["name", "alert_key", "status", "severity", "last_notified_at"],
	)
	open_alerts = {
		r.alert_key: {
			"status": r.status,
			"severity": r.severity,
			"last_notified_at": frappe.utils.get_datetime(r.last_notified_at) if r.last_notified_at else None,
		}
		for r in open_rows
	}
	plan = alert_rules.reconcile(
		open_alerts, candidates, now, int(alert_rules.with_defaults(settings)["renotify_hours"])
	)
	by_key = {c["key"]: c for c in candidates}
	docs: dict[str, object] = {}

	for cand in plan["open"]:
		docs[cand["key"]] = _open(cand, now)
	for cand in plan["update"]:
		doc = frappe.get_doc(ALERT, alert_name(cand["key"]))
		doc.update(
			{
				"severity": cand["severity"],
				"title": cand["title"],
				"message": cand["message"],
				"last_seen": now,
			}
		)
		doc.save(ignore_permissions=True)
		docs[cand["key"]] = doc
	for key in plan["resolve"]:
		doc = frappe.get_doc(ALERT, alert_name(key))
		doc.update({"status": "Resolved", "resolved_at": now})
		doc.save(ignore_permissions=True)
		docs[key] = doc

	events = []
	for key, event in plan["notify"]:
		doc = docs[key]
		events.append(
			{
				"name": doc.name,
				"event": event,
				"severity": doc.severity,
				"title": doc.title,
				"message": doc.message,
				"organization": doc.organization,
			}
		)
	frappe.db.commit()  # persist state before sending, so a mail failure cannot cause a repeat notification
	if events:
		notifier.deliver(events, settings)
		for ev in events:
			if ev["event"] != "resolved":
				frappe.db.set_value(
					ALERT,
					ev["name"],
					{
						"last_notified_at": now,
						"notification_count": (
							frappe.db.get_value(ALERT, ev["name"], "notification_count") or 0
						)
						+ 1,
					},
					update_modified=False,
				)
		frappe.db.commit()
	del by_key
	return events


def _open(cand: dict, now):
	name = alert_name(cand["key"])
	values = {
		"alert_key": cand["key"],
		"alert_type": cand["type"],
		"severity": cand["severity"],
		"site": cand["site"],
		"organization": cand["organization"],
		"title": cand["title"],
		"message": cand["message"],
		"status": "Open",
		"first_seen": now,
		"last_seen": now,
		"resolved_at": None,
		"acknowledged_by": None,
		"acknowledged_at": None,
		"last_notified_at": None,
	}
	if frappe.db.exists(ALERT, name):
		doc = frappe.get_doc(ALERT, name)
		doc.update(values)
		doc.occurrence_count = (doc.occurrence_count or 0) + 1
		doc.save(ignore_permissions=True)
		return doc
	return frappe.get_doc(
		{"doctype": ALERT, **values, "occurrence_count": 1, "notification_count": 0}
	).insert(ignore_permissions=True)


def purge_old() -> None:
	"""Daily retention: resolved alerts after 90 days, login activity after 180 days."""
	frappe.flags.tnxg_retention = True
	try:
		cutoff = frappe.utils.add_days(frappe.utils.now_datetime(), -90)
		frappe.db.delete(ALERT, {"status": "Resolved", "resolved_at": ("<", cutoff)})
		frappe.db.delete(
			"ThinkNXG Login Activity",
			{"timestamp": ("<", frappe.utils.add_days(frappe.utils.now_datetime(), -180))},
		)
		frappe.db.commit()
	finally:
		frappe.flags.tnxg_retention = False
