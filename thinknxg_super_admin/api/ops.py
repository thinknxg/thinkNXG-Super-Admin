"""Liveness endpoint for an external uptime monitor. Reveals nothing but ok / not ok."""

import frappe
from frappe.rate_limiter import rate_limit

from thinknxg_super_admin.utils import ops_rules

SETTINGS = "ThinkNXG Alert Settings"


@frappe.whitelist(allow_guest=True, methods=["GET"])
@rate_limit(limit=30, seconds=60)
def healthz():
	try:
		frappe.db.sql("select 1")
		db_ok = True
		last = frappe.db.get_single_value(SETTINGS, "last_evaluated_at")
	except Exception:
		db_ok, last = False, None
	ok, reason = ops_rules.health_verdict(
		db_ok=db_ok,
		last_evaluated_at=frappe.utils.get_datetime(last) if last else None,
		now=frappe.utils.now_datetime(),
	)
	if not ok:
		frappe.logger("thinknxg_super_admin").warning("healthz failing reason=%s", reason)
		frappe.local.response["http_status_code"] = 503
	return {"ok": ok}
