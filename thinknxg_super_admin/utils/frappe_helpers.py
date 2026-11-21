"""Small helpers shared by controllers."""

import frappe

from thinknxg_super_admin.utils.rules import RuleError


def run_rule(fn, *args, **kwargs):
	"""Call a pure rule function and turn :class:`RuleError` into a Frappe validation error."""
	try:
		return fn(*args, **kwargs)
	except RuleError as e:
		frappe.throw(e.message, title=e.code.replace("_", " ").title())


def immutable(doc, *fieldnames):
	"""Throw if a saved document tries to change one of ``fieldnames``."""
	if doc.is_new():
		return
	for fieldname in fieldnames:
		if doc.has_value_changed(fieldname):
			frappe.throw(f"{doc.meta.get_label(fieldname)} cannot be changed after the record is created.")
