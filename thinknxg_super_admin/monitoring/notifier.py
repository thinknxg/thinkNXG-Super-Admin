"""Deliver alert events: in-app Notification Log entries and one email digest per recipient.

Frappe's "Alert" notification type never emails by itself (it is in ``notification_skip_email_types``),
so email is sent explicitly here, exactly once per recipient and run. Email failures are logged and
never stop the in-app notification or the evaluation loop.
"""

import frappe

from thinknxg_super_admin.monitoring import alert_rules
from thinknxg_super_admin.setup.roles import ORG_ADMIN, SUPER_ADMIN

NOTIFICATION_TYPE = "Alert"
SKIP_USERS = {"Administrator", "Guest"}


def _enabled(users) -> list[str]:
	if not users:
		return []
	rows = frappe.get_all("User", filters={"name": ("in", list(users)), "enabled": 1}, pluck="name")
	return [u for u in rows if u not in SKIP_USERS]


def super_admins() -> list[str]:
	return _enabled(frappe.get_all("Has Role", filters={"role": SUPER_ADMIN, "parenttype": "User"}, pluck="parent"))


def org_admins(organization: str | None) -> list[str]:
	if not organization:
		return []
	scoped = frappe.get_all(
		"User Permission", filters={"allow": "ThinkNXG Organization", "for_value": organization}, pluck="user"
	)
	holders = set(frappe.get_all("Has Role", filters={"role": ORG_ADMIN, "parenttype": "User", "parent": ("in", scoped or ["-"])}, pluck="parent"))
	return _enabled(holders)


def recipients_for(organization: str | None) -> list[str]:
	return sorted(set(super_admins()) | set(org_admins(organization)))


def _link(name: str) -> str:
	return f"/app/thinknxg-alert/{name}"


def deliver(events: list[dict], settings: dict) -> None:
	"""``events``: dicts with name, event, severity, title, message, organization."""
	cfg = alert_rules.with_defaults(settings)
	per_user: dict[str, list[dict]] = {}
	for ev in events:
		for user in recipients_for(ev.get("organization")):
			per_user.setdefault(user, []).append(ev)

	if cfg["enable_in_app"]:
		for user, items in per_user.items():
			for ev in items:
				try:
					frappe.get_doc(
						{
							"doctype": "Notification Log",
							"for_user": user,
							"from_user": "Administrator",
							"type": NOTIFICATION_TYPE,
							"subject": f"{ev['event'].title()}: {ev['title']}"[:140],
							"email_content": ev["message"],
							"document_type": "ThinkNXG Alert",
							"document_name": ev["name"],
						}
					).insert(ignore_permissions=True)
				except Exception:
					frappe.log_error(title="Alert in-app notification failed")

	if not cfg["enable_email"]:
		return
	base = frappe.utils.get_url()
	minimum = cfg["email_min_severity"]
	extra = [x.strip() for x in (settings.get("extra_email_recipients") or "").splitlines() if x.strip()]
	mail: dict[str, list[dict]] = {}
	for user, items in per_user.items():
		address = frappe.db.get_value("User", user, "email")
		if address:
			mail.setdefault(address, []).extend(i for i in items if alert_rules.meets_email_threshold(i["severity"], minimum))
	for address in extra:
		mail.setdefault(address, []).extend(i for i in events if alert_rules.meets_email_threshold(i["severity"], minimum))
	for address, items in mail.items():
		seen, unique = set(), []
		for i in items:
			if (i["name"], i["event"]) not in seen:
				seen.add((i["name"], i["event"]))
				unique.append(i)
		if not unique:
			continue
		subject, body, _text = alert_rules.render_digest([dict(i, link=_link(i["name"])) for i in unique], base)
		try:
			frappe.sendmail(recipients=[address], subject=subject, message=body)
		except Exception:
			frappe.log_error(title="Alert email failed")
