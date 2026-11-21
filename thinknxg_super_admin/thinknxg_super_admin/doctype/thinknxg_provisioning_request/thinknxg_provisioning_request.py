import frappe
from frappe.model.document import Document

from thinknxg_super_admin.security.audit import record_doc_event
from thinknxg_super_admin.utils import rules
from thinknxg_super_admin.utils.frappe_helpers import run_rule


class ThinkNXGProvisioningRequest(Document):
	def before_insert(self):
		self.status = rules.REQUEST_INITIAL
		self.attempt_count = 0
		self.requested_by = self.requested_by or frappe.session.user

	def validate(self):
		if not self.idempotency_key:
			frappe.throw("An idempotency key is required.")
		if self.desired_state:
			frappe.parse_json(self.desired_state)
		before = self.get_doc_before_save()
		if before is not None:
			run_rule(
				rules.check_transition,
				rules.REQUEST_TRANSITIONS,
				before.status,
				self.status,
				"Provisioning request",
			)

	def on_update(self):
		if self.flags.in_insert or self.has_value_changed("status"):
			record_doc_event(self)

	def on_trash(self):
		if not frappe.flags.get("tnxg_retention"):
			frappe.throw("Provisioning requests are kept for history.")
