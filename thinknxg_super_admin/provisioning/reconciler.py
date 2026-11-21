"""Scheduler safety net: retries due requests and recovers lost or stuck ones."""

import frappe

from thinknxg_super_admin.provisioning import plan, service

REQUEST = "ThinkNXG Provisioning Request"
BATCH = 200


def reconcile() -> None:
	now = frappe.utils.now_datetime()
	rows = frappe.get_all(
		REQUEST,
		filters={"status": ("in", ("Queued", "Retrying", "Running"))},
		fields=["name", "status", "next_retry_at", "started_at", "creation"],
		order_by="creation asc",
		limit=BATCH,
	)
	for row in rows:
		retry_at = frappe.utils.get_datetime(row.next_retry_at) if row.next_retry_at else None
		started = frappe.utils.get_datetime(row.started_at) if row.started_at else None
		if plan.due_for_retry(row.status, retry_at, now) or plan.stale_queued(row.status, row.creation, now):
			service.queue(row.name)
		elif plan.stuck_running(row.status, started, now):
			doc = frappe.get_doc(REQUEST, row.name)
			doc.status = "Retrying"
			doc.next_retry_at = now
			doc.last_error = "timeout: the previous attempt did not finish"
			doc.save(ignore_permissions=True)
	frappe.db.commit()
