import frappe
from frappe.model.document import Document
from frappe.utils import validate_email_address

from thinknxg_super_admin.security.audit import record_doc_event

RANGES = {
	"renotify_hours": (1, 168),
	"stale_health_minutes": (6, 1440),
	"needs_review_after_minutes": (5, 10080),
	"queue_stuck_minutes": (5, 1440),
	"failure_threshold": (1, 1000),
	"denial_threshold": (1, 1000),
}


class ThinkNXGAlertSettings(Document):
	def validate(self):
		for field, (low, high) in RANGES.items():
			value = self.get(field)
			if value is not None and not low <= int(value) <= high:
				frappe.throw(f"{self.meta.get_label(field)} must be between {low} and {high}.")
		lines = [x.strip() for x in (self.extra_email_recipients or "").splitlines() if x.strip()]
		if len(lines) > 20:
			frappe.throw("At most 20 extra recipients.")
		for line in lines:
			if not validate_email_address(line):
				frappe.throw(f"{line} is not a valid email address.")
		self.extra_email_recipients = "\n".join(dict.fromkeys(x.lower() for x in lines))

	def on_update(self):
		record_doc_event(self)
