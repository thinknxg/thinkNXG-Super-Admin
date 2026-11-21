"""Daily refresh of each site's role catalogue (used to reject unknown roles at assignment time)."""

import hashlib
import json

import frappe

from thinknxg_super_admin.provisioning import agent_client
from thinknxg_super_admin.utils import site_rules
from thinknxg_super_admin.utils.rules import RuleError

SITE = "ThinkNXG Managed Site"


def refresh_all() -> None:
	for name in frappe.get_all(SITE, filters={"status": "Active"}, pluck="name"):
		frappe.enqueue(
			"thinknxg_super_admin.monitoring.catalogue.refresh_site",
			queue="short",
			site_name=name,
			job_id=f"tnxg-catalogue|{name}",
			deduplicate=True,
		)


def refresh_site(site_name: str) -> bool:
	url = frappe.db.get_value(SITE, site_name, "site_url")
	try:
		status, message = agent_client.call(url, "roles.catalogue")
		roles = site_rules.parse_catalogue(message)
	except (agent_client.AgentCallError, RuleError):
		frappe.log_error(title=f"Role catalogue refresh failed for {site_name}")
		return False
	if status != 200:
		return False
	digest = hashlib.sha256("\n".join(roles).encode()).hexdigest()
	frappe.db.set_value(
		SITE, site_name, {"roles_catalogue": json.dumps(roles), "roles_catalogue_hash": digest}, update_modified=False
	)
	frappe.db.commit()
	return True
