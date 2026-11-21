import hashlib

import frappe
from frappe.model.document import Document


class ThinkNXGAlert(Document):
	"""Written only by the alert evaluator and the acknowledge API. One document per alert key."""

	def autoname(self):
		self.name = "ALT-" + hashlib.sha256((self.alert_key or "").encode()).hexdigest()[:20]

	def on_trash(self):
		if not frappe.flags.get("tnxg_retention"):
			frappe.throw("Alerts are kept for history. They resolve on their own when the condition clears.")
