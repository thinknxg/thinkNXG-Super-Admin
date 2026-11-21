"""Append-only audit trail. ``record`` is the only supported way to write ThinkNXG Audit Log rows.

Failure to write an audit row fails the surrounding operation (fail closed).
"""

import json

import frappe

from thinknxg_super_admin.utils.rules import redact

MAX_ACTION = 140


def _dump(value, extra_keys=()):
	if value is None:
		return None
	return json.dumps(redact(value, extra_keys), default=str, sort_keys=True)


def record(
	action, target_doctype=None, target_name=None, before=None, after=None, actor=None, extra_secret_keys=()
):
	frappe.flags.tnxg_audit_write = True
	try:
		frappe.get_doc(
			{
				"doctype": "ThinkNXG Audit Log",
				"timestamp": frappe.utils.now_datetime(),
				"actor": actor or frappe.session.user,
				"action": (action or "")[:MAX_ACTION],
				"target_doctype": target_doctype,
				"target_name": target_name,
				"before": _dump(before, extra_secret_keys),
				"after": _dump(after, extra_secret_keys),
				"ip_address": getattr(frappe.local, "request_ip", None),
				"request_id": getattr(frappe.local, "tnxg_request_id", None),
			}
		).insert(ignore_permissions=True)
	finally:
		frappe.flags.tnxg_audit_write = False


def record_doc_event(doc, action=None):
	"""Audit a document create, update or delete with secret fields redacted."""
	secrets = [df.fieldname for df in doc.meta.fields if df.fieldtype == "Password"]
	if action is None:
		action = "create" if doc.flags.in_insert else "update"
	previous = doc.get_doc_before_save() if action == "update" else None
	record(
		f"{doc.doctype}: {action}",
		doc.doctype,
		doc.name,
		before=previous.as_dict() if previous else None,
		after=None if action == "delete" else doc.as_dict(),
		extra_secret_keys=secrets,
	)
