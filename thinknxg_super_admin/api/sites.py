"""Site switching for signed-in central users."""

from urllib.parse import quote

import frappe

from thinknxg_super_admin.security import audit
from thinknxg_super_admin.utils import rules
from thinknxg_super_admin.utils.frappe_helpers import run_rule

AGENT_START_PATH = "/api/method/thinknxg_site_agent.api.v1.auth.start"


@frappe.whitelist(methods=["GET"])
def launch(site: str, path: str | None = None):
	"""Send the signed-in central user to ``site``'s agent, which starts the OIDC login.

	Only the site's own registered origin is ever used as the target, and ``path`` must be a
	same-site relative path, so this endpoint cannot be used as an open redirect.
	"""
	central_user = frappe.db.get_value("ThinkNXG Central User", {"central_frappe_user": frappe.session.user}, ["name", "status"], as_dict=True)
	if not central_user or central_user.status != "Active":
		frappe.throw("Not permitted", frappe.PermissionError)
	assignment = frappe.db.get_value(
		"ThinkNXG Site User Assignment",
		rules.assignment_name(central_user.name, site),
		["status", "site"],
		as_dict=True,
	)
	if not assignment or assignment.status != "Active":
		frappe.throw("Not permitted", frappe.PermissionError)
	site_doc = frappe.db.get_value("ThinkNXG Managed Site", site, ["site_url", "status"], as_dict=True)
	if not site_doc or site_doc.status != "Active" or not site_doc.site_url:
		frappe.throw("Site is not available", frappe.ValidationError)
	target = site_doc.site_url.rstrip("/") + AGENT_START_PATH
	if path:
		target += "?next=" + quote(run_rule(rules.validate_launch_path, path), safe="/")
	frappe.get_doc(
		{
			"doctype": "ThinkNXG Login Activity",
			"event": "Site Launch",
			"organization": frappe.db.get_value("ThinkNXG Managed Site", site, "organization"),
			"central_user": central_user.name,
			"site": site,
			"timestamp": frappe.utils.now_datetime(),
			"ip_address": getattr(frappe.local, "request_ip", None),
		}
	).insert(ignore_permissions=True)
	audit.record("site.launch", "ThinkNXG Managed Site", site)
	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = target
