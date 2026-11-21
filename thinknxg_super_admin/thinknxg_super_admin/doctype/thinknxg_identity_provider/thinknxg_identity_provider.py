import re

import frappe
from frappe.model.document import Document

from thinknxg_super_admin.security.audit import record_doc_event
from thinknxg_super_admin.utils import rules
from thinknxg_super_admin.utils.frappe_helpers import run_rule

REALM_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class ThinkNXGIdentityProvider(Document):
	def validate(self):
		if self.provider_type == "Keycloak":
			if not (self.server_url and self.realm):
				frappe.throw("Server URL and realm are required for Keycloak.")
			if not REALM_RE.match(self.realm):
				frappe.throw("Invalid realm name.")
			self.server_url = run_rule(
				rules.validate_https_url, self.server_url, allow_path=False, label="Server URL"
			)
			self.issuer_url = f"{self.server_url}/realms/{self.realm}"
			oidc = f"{self.issuer_url}/protocol/openid-connect"
			self.authorization_endpoint = f"{oidc}/auth"
			self.token_endpoint = f"{oidc}/token"
			self.jwks_uri = f"{oidc}/certs"
			self.end_session_endpoint = f"{oidc}/logout"
		else:
			self.issuer_url = run_rule(
				rules.validate_https_url, self.issuer_url, allow_path=True, label="Issuer URL"
			)
			for fieldname in ("authorization_endpoint", "token_endpoint", "jwks_uri", "end_session_endpoint"):
				value = self.get(fieldname)
				if value:
					self.set(
						fieldname, run_rule(rules.validate_https_url, value, allow_path=True, label=fieldname)
					)

	def on_update(self):
		record_doc_event(self)

	def on_trash(self):
		if frappe.db.get_single_value("ThinkNXG SSO Configuration", "identity_provider") == self.name:
			frappe.throw("This provider is the active SSO identity provider.")
		record_doc_event(self, "delete")
