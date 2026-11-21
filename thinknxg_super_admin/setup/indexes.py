"""Composite indexes that DocType JSON cannot express. Idempotent."""

import frappe

COMPOSITE_INDEXES = (
	("ThinkNXG Provisioning Request", ["site", "status"]),
	("ThinkNXG Provisioning Request", ["status", "next_retry_at"]),
	("ThinkNXG Site Health Log", ["site", "checked_at"]),
	("ThinkNXG Login Activity", ["central_user", "timestamp"]),
	("ThinkNXG Audit Log", ["target_doctype", "target_name"]),
	("ThinkNXG Provisioning Log", ["request", "attempt"]),
)


def ensure_indexes():
	for doctype, fields in COMPOSITE_INDEXES:
		if frappe.db.table_exists(doctype):
			frappe.db.add_index(doctype, fields)
