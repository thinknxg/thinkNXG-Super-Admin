import frappe
from frappe.model.document import Document

from thinknxg_super_admin.utils.frappe_helpers import immutable


class ThinkNXGUserSession(Document):
	def validate(self):
		immutable(self, "keycloak_sid", "central_user")
