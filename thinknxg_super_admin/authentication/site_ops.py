"""Keycloak operations on a Managed Site (create or update its OIDC client)."""

import frappe

from thinknxg_super_admin.authentication import keycloak as kc


def get_admin() -> kc.KeycloakAdmin:
	provider_name = frappe.db.get_single_value("ThinkNXG SSO Configuration", "identity_provider")
	if not provider_name:
		frappe.throw("No identity provider is selected in SSO Configuration.")
	idp = frappe.get_doc("ThinkNXG Identity Provider", provider_name)
	if idp.provider_type != "Keycloak":
		frappe.throw("Automatic client management is only implemented for Keycloak.")
	secret = idp.get_password("admin_client_secret", raise_exception=False)
	if not (idp.admin_client_id and secret):
		frappe.throw("The identity provider has no admin client credentials.")
	return kc.KeycloakAdmin(idp.server_url, idp.realm, idp.admin_client_id, secret, cache=frappe.cache)


def client_rep(site) -> dict:
	return kc.client_representation(
		site_name=site.name,
		site_origin=site.site_url,
		redirect_uris=[row.uri for row in site.redirect_uris],
		display_name=site.display_name,
	)


def ensure_client(site) -> tuple[str, str]:
	"""Create or update the site's client. Returns ``(client_id, client_secret)``."""
	rep = client_rep(site)
	_uuid, secret = get_admin().ensure_client(rep)
	return rep["clientId"], secret


def sync_client(site_name: str) -> None:
	"""Background job: push redirect-URI changes to Keycloak. The secret is not read or stored."""
	site = frappe.get_doc("ThinkNXG Managed Site", site_name)
	if not site.keycloak_client_id or site.status == "Disconnected":
		return
	get_admin().ensure_client(client_rep(site))


def set_client_enabled(site_name: str, enabled: bool) -> None:
	client_id = frappe.db.get_value("ThinkNXG Managed Site", site_name, "keycloak_client_id")
	if client_id:
		get_admin().set_client_enabled(client_id, enabled)
