"""Health polling: Super Admin calls each paired site's signed ``health.status`` endpoint."""

import json
import time

import frappe

from thinknxg_super_admin.security import pinned_http, signing
from thinknxg_super_admin.setup.keys import central_signer
from thinknxg_super_admin.utils import site_rules
from thinknxg_super_admin.utils.rules import RuleError

SITE = "ThinkNXG Managed Site"
STATUS_PATH = "/api/method/thinknxg_site_agent.api.v1.health.status"
TIMEOUT = (3.05, 8)
MAX_BYTES = 16 * 1024
HISTORY = 5
RETENTION_DAYS = 30


def poll_all() -> None:
	"""Scheduler entry (every 5 minutes): enqueue one deduplicated check per paired site."""
	sites = frappe.get_all(
		SITE, filters={"status": ("in", ("Draft", "Active", "Inactive")), "agent_key_id": ("is", "set")}, pluck="name"
	)
	for name in sites:
		frappe.enqueue(
			"thinknxg_super_admin.monitoring.health.check_site",
			queue="short",
			site_name=name,
			job_id=f"tnxg-health|{name}",
			deduplicate=True,
		)


def _probe(site_url: str) -> tuple[dict | None, int, int | None, str | None]:
	"""Return ``(payload, latency_ms, skew_ms, error)``. Never raises for network problems."""
	key_id, key = central_signer()
	headers = signing.sign_request(key, key_id, "GET", STATUS_PATH, b"")
	sent = int(time.time() * 1000)
	try:
		resp = pinned_http.request("GET", site_url, STATUS_PATH, headers=headers, timeout=TIMEOUT, max_bytes=MAX_BYTES)
	except pinned_http.PinnedError as exc:
		return None, 0, None, exc.code
	received = int(time.time() * 1000)
	if resp.status != 200:
		return None, received - sent, None, f"http_{resp.status}"
	try:
		payload = site_rules.parse_health_payload(json.loads(resp.body).get("message"))
	except (ValueError, AttributeError):
		return None, received - sent, None, "response_invalid"
	except RuleError as exc:
		return None, received - sent, None, exc.code
	return payload, received - sent, site_rules.clock_skew_ms(payload["server_time_ms"], sent, received), None


def check_site(site_name: str) -> str:
	"""Run one health check, store it, and update the site's connection status."""
	site = frappe.db.get_value(SITE, site_name, ["site_url", "organization", "status"], as_dict=True)
	if not site or site.status == "Disconnected":
		return "Unknown"
	payload, latency, skew, error = _probe(site.site_url)
	frappe.get_doc(
		{
			"doctype": "ThinkNXG Site Health Log",
			"site": site_name,
			"organization": site.organization,
			"checked_at": frappe.utils.now_datetime(),
			"reachable": 1 if payload else 0,
			"latency_ms": latency,
			"agent_version": payload and payload["agent_version"],
			"frappe_version": payload and payload["frappe_version"],
			"erpnext_version": payload and payload["erpnext_version"],
			"queue_backlog": payload["queue_backlog"] if payload else 0,
			"scheduler_ok": 1 if payload and payload["scheduler_ok"] else 0,
			"clock_skew_ms": skew or 0,
			"error": error,
		}
	).insert(ignore_permissions=True)
	history = frappe.get_all(
		"ThinkNXG Site Health Log",
		filters={"site": site_name},
		fields=["reachable", "scheduler_ok", "queue_backlog", "clock_skew_ms", "latency_ms"],
		order_by="checked_at desc, name desc",
		limit=HISTORY,
	)
	status = site_rules.evaluate_connection(history)
	updates = {"connection_status": status, "last_health_check": frappe.utils.now_datetime()}
	if payload:
		updates["agent_api_version"] = payload["agent_version"]
	frappe.db.set_value(SITE, site_name, updates, update_modified=False)
	frappe.db.commit()
	return status


def purge_old_logs() -> None:
	cutoff = frappe.utils.add_days(frappe.utils.now_datetime(), -RETENTION_DAYS)
	frappe.db.delete("ThinkNXG Site Health Log", {"checked_at": ("<", cutoff)})
