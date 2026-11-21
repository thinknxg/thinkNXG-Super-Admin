app_name = "thinknxg_super_admin"
app_title = "thinkNXG Super Admin"
app_publisher = "Kreatao"
app_description = "Centralized SSO and multi-site management for thinkNXG / Frappe v16"
app_email = "sales@kreatao.com"
app_license = "MIT"

# Install on a dedicated central site only.
required_apps = ["frappe"]

# Roles, baseline configuration and composite indexes are created idempotently on install and on every migrate.
after_install = "thinknxg_super_admin.setup.install.after_install"
after_migrate = "thinknxg_super_admin.setup.install.after_migrate"

# Organization scoping. Org Admins see and touch only their own organizations, and see nothing at all
# if they have no User Permission on ThinkNXG Organization (fail closed). Super Admin, Auditor and
# System Manager are unscoped.
_perm = "thinknxg_super_admin.security.permissions"

permission_query_conditions = {
	"ThinkNXG Organization": f"{_perm}.qc_organization",
	"ThinkNXG Managed Site": f"{_perm}.qc_managed_site",
	"ThinkNXG Central User": f"{_perm}.qc_central_user",
	"ThinkNXG Site User Assignment": f"{_perm}.qc_assignment",
	"ThinkNXG Provisioning Request": f"{_perm}.qc_provisioning_request",
	"ThinkNXG Provisioning Log": f"{_perm}.qc_provisioning_log",
	"ThinkNXG Site Health Log": f"{_perm}.qc_health_log",
	"ThinkNXG Login Activity": f"{_perm}.qc_login_activity",
	"ThinkNXG Alert": f"{_perm}.qc_alert",
}

has_permission = {
	doctype: f"{_perm}.has_org_permission"
	for doctype in (
		"ThinkNXG Organization",
		"ThinkNXG Managed Site",
		"ThinkNXG Central User",
		"ThinkNXG Site User Assignment",
		"ThinkNXG Provisioning Request",
		"ThinkNXG Provisioning Log",
		"ThinkNXG Site Health Log",
		"ThinkNXG Login Activity",
		"ThinkNXG Alert",
	)
}

scheduler_events = {
	"cron": {
		"*/5 * * * *": [
			"thinknxg_super_admin.monitoring.health.poll_all",
			"thinknxg_super_admin.provisioning.reconciler.reconcile",
			"thinknxg_super_admin.monitoring.alerts.evaluate_all",
		]
	},
	"daily": [
		"thinknxg_super_admin.monitoring.health.purge_old_logs",
		"thinknxg_super_admin.provisioning.service.expire_assignments",
		"thinknxg_super_admin.provisioning.service.resync_stale",
		"thinknxg_super_admin.monitoring.catalogue.refresh_all",
		"thinknxg_super_admin.monitoring.alerts.purge_old",
	],
}

# Auth hooks and session hooks are added in the phase that implements their targets.
