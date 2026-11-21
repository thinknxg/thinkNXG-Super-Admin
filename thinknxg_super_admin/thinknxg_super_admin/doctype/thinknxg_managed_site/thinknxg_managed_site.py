from urllib.parse import urlsplit

import frappe
from frappe.model.document import Document

from thinknxg_super_admin.security.audit import record_doc_event
from thinknxg_super_admin.security.permissions import can_manage_organization
from thinknxg_super_admin.security.ssrf import UnsafeURLError, validate_outbound_url
from thinknxg_super_admin.utils import rules
from thinknxg_super_admin.utils.frappe_helpers import immutable, run_rule


class ThinkNXGManagedSite(Document):
	def validate(self):
		run_rule(rules.require_slug, self.site_name, "Site name")
		immutable(self, "site_name", "organization")
		if self.is_new() and not can_manage_organization(self.organization):
			frappe.throw("You can only register sites for organizations you manage.", frappe.PermissionError)
		self.validate_status()
		self.validate_url()
		self.validate_redirect_uris()
		self.derive_domain()
		if self.contact_email:
			self.contact_email = run_rule(rules.normalize_email, self.contact_email)

	def validate_status(self):
		before = self.get_doc_before_save()
		old = before.status if before else None
		if self.is_new():
			run_rule(rules.check_initial, rules.SITE_INITIAL, self.status, "site")
		else:
			run_rule(rules.check_transition, rules.SITE_TRANSITIONS, old, self.status, "Site")
		if self.status == "Active" and old != "Active":
			missing = [
				label
				for label, ok in (
					("a Keycloak client", bool(self.keycloak_client_id)),
					("the site agent public key", bool(self.agent_public_key)),
					(
						"a successful health check (connection status Online)",
						self.connection_status == "Online",
					),
				)
				if not ok
			]
			if missing:
				frappe.throw("A site cannot be activated without " + ", ".join(missing) + ".")

	def validate_url(self):
		before = self.get_doc_before_save()
		old_status = before.status if before else None
		if before and self.has_value_changed("site_url") and old_status == "Active":
			frappe.throw("The site URL cannot change while the site is Active. Set it Inactive first.")
		# Resolve DNS only when the site is being activated or its URL changed while Active-bound.
		resolve = self.status == "Active" and (
			self.is_new() or self.has_value_changed("status") or self.has_value_changed("site_url")
		)
		try:
			self.site_url = validate_outbound_url(self.site_url, resolve=resolve)
		except UnsafeURLError as e:
			frappe.throw(str(e), title="Invalid site URL")

	def validate_redirect_uris(self):
		if not self.redirect_uris:
			self.append("redirect_uris", {"uri": self.site_url + rules.AGENT_CALLBACK_PATH})
		run_rule(rules.validate_redirect_uris, self.site_url, [row.uri for row in self.redirect_uris])

	def derive_domain(self):
		self.domain, self.subdomain = rules.split_host(urlsplit(self.site_url).hostname or "")

	def on_update(self):
		record_doc_event(self)
		self.sync_keycloak_client()

	def sync_keycloak_client(self):
		"""Push redirect-URI changes to Keycloak in the background (the secret is untouched)."""
		before = self.get_doc_before_save()
		if not (before and self.keycloak_client_id and self.status != "Disconnected"):
			return
		if sorted(r.uri for r in before.redirect_uris) != sorted(r.uri for r in self.redirect_uris):
			frappe.enqueue(
				"thinknxg_super_admin.authentication.site_ops.sync_client",
				queue="short",
				site_name=self.name,
				job_id=f"tnxg-kc-sync|{self.name}",
				deduplicate=True,
				enqueue_after_commit=True,
			)

	def on_trash(self):
		if self.status != "Draft" or frappe.db.exists("ThinkNXG Site User Assignment", {"site": self.name}):
			frappe.throw("Only a Draft site without assignments can be deleted. Disconnect the site instead.")
		record_doc_event(self, "delete")
