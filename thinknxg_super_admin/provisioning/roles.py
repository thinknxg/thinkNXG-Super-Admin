"""Load role mappings and compute the roles an assignment should have on a site."""

import frappe

from thinknxg_super_admin.utils import rules


def load_mappings(templates, site):
	"""Mappings (default and site specific) for the given templates, as plain dicts."""
	names = frappe.get_all(
		"ThinkNXG Role Mapping",
		filters={"role_template": ("in", list(templates))},
		or_filters=[["site", "=", site], ["site", "is", "not set"]],
		pluck="name",
	)
	out = []
	for name in names:
		doc = frappe.get_cached_doc("ThinkNXG Role Mapping", name)
		out.append(
			{
				"role_template": doc.role_template,
				"site": doc.site or None,
				"roles": [row.site_role for row in doc.roles],
				"effective_from": doc.effective_from,
				"version": doc.version,
			}
		)
	return out


def desired_roles_for(assignment) -> list[str]:
	templates = [row.role_template for row in assignment.role_templates]
	if not templates:
		return []
	overrides = []
	for row in assignment.role_templates:
		overrides.extend(rules.parse_override_roles(row.override_roles))
	return rules.desired_roles(
		templates,
		assignment.site,
		load_mappings(templates, assignment.site),
		overrides,
		now=frappe.utils.now_datetime(),
	)
