import frappe
from frappe.model.document import Document

from thinknxg_super_admin.security.audit import record_doc_event


class ThinkNXGSSOConfiguration(Document):
	def validate(self):
		self.require_pkce = 1
		if not 60 <= (self.access_token_ttl_seconds or 0) <= 900:
			frappe.throw("Access token lifetime must be between 60 and 900 seconds.")
		if (self.session_idle_ttl_minutes or 0) < 5:
			frappe.throw("Idle session lifetime must be at least 5 minutes.")
		if (self.session_absolute_ttl_minutes or 0) < self.session_idle_ttl_minutes:
			frappe.throw("Absolute session lifetime cannot be shorter than the idle lifetime.")
		if (self.jwks_cache_ttl_seconds or 0) < 60:
			frappe.throw("JWKS cache lifetime must be at least 60 seconds.")
		for line in (self.allowed_redirect_suffixes or "").splitlines():
			if line.strip() and not line.strip().startswith("."):
				frappe.throw(
					f"Redirect suffix {line.strip()} must start with a dot, for example .thinknxg.com"
				)

	def on_update(self):
		record_doc_event(self)
