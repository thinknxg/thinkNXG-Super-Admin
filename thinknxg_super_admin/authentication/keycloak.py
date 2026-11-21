"""Keycloak adapter: pure representation builders plus a thin Admin API client.

The builders encode the security posture of every site client (confidential, auth-code + PKCE
S256, exact redirect URIs, no refresh tokens, no direct grants, back-channel logout) and are
unit-tested without Keycloak. The client class is the only part that does network I/O.
"""

import json
import re
from urllib.parse import quote, urlsplit

AGENT_BACKCHANNEL_PATH = "/api/method/thinknxg_site_agent.api.v1.auth.backchannel_logout"
CLIENT_PREFIX = "tnxg-site-"
TIMEOUT = (3.05, 10)
MAX_RESPONSE_BYTES = 1024 * 1024


class KeycloakError(Exception):
	def __init__(self, code: str, message: str = ""):
		super().__init__(message or code)
		self.code = code


def client_id_for(site_name: str) -> str:
	slug = re.sub(r"[^a-z0-9-]+", "-", (site_name or "").lower()).strip("-")
	if not slug:
		raise KeycloakError("validation_failed", "Site name cannot produce a client id")
	return (CLIENT_PREFIX + slug)[:100]


def central_uid_mapper() -> dict:
	"""Put the immutable central uid into the ID token. Sites key users on this claim."""
	return {
		"name": "central_uid",
		"protocol": "openid-connect",
		"protocolMapper": "oidc-usermodel-attribute-mapper",
		"consentRequired": False,
		"config": {
			"user.attribute": "central_uid",
			"claim.name": "central_uid",
			"jsonType.label": "String",
			"id.token.claim": "true",
			"access.token.claim": "false",
			"userinfo.token.claim": "false",
			"introspection.token.claim": "false",
		},
	}


def client_representation(*, site_name: str, site_origin: str, redirect_uris: list[str], display_name: str | None = None) -> dict:
	origin = urlsplit(site_origin)
	if origin.scheme != "https" or not origin.hostname:
		raise KeycloakError("validation_failed", "site_origin must be an https origin")
	if not redirect_uris:
		raise KeycloakError("validation_failed", "At least one redirect URI is required")
	for uri in redirect_uris:
		if "*" in uri or urlsplit(uri).netloc != origin.netloc:
			raise KeycloakError("validation_failed", f"Redirect URI must be exact and on the site origin: {uri}")
	return {
		"clientId": client_id_for(site_name),
		"name": display_name or site_name,
		"enabled": True,
		"protocol": "openid-connect",
		"publicClient": False,
		"clientAuthenticatorType": "client-secret",
		"standardFlowEnabled": True,
		"implicitFlowEnabled": False,
		"directAccessGrantsEnabled": False,
		"serviceAccountsEnabled": False,
		"fullScopeAllowed": False,
		"rootUrl": "",
		"redirectUris": list(redirect_uris),
		"webOrigins": [],
		"attributes": {
			"pkce.code.challenge.method": "S256",
			"use.refresh.tokens": "false",
			"backchannel.logout.url": f"{origin.scheme}://{origin.netloc}{AGENT_BACKCHANNEL_PATH}",
			"backchannel.logout.session.required": "true",
			"backchannel.logout.revoke.offline.tokens": "false",
			"post.logout.redirect.uris": "+",
		},
		"protocolMappers": [central_uid_mapper()],
	}


def user_representation(*, central_uid: str, email: str, first_name: str | None, last_name: str | None, enabled: bool = True) -> dict:
	return {
		"username": email,
		"email": email,
		"emailVerified": True,  # Super Admin is the source of truth for the address
		"firstName": first_name or "",
		"lastName": last_name or "",
		"enabled": bool(enabled),
		"attributes": {"central_uid": [central_uid]},
	}


class KeycloakAdmin:
	"""Admin REST client authenticated with a service-account (client credentials)."""

	def __init__(self, server_url: str, realm: str, client_id: str, client_secret: str, *, cache=None, session=None):
		import requests

		self.base = server_url.rstrip("/")
		self.realm = realm
		self.client_id = client_id
		self.client_secret = client_secret
		self._cache = cache
		self._http = session or requests.Session()
		self._http.max_redirects = 0

	# ------------------------------------------------------------------ plumbing
	def _url(self, path: str) -> str:
		return f"{self.base}/admin/realms/{quote(self.realm, safe='')}{path}"

	def _token(self) -> str:
		key = f"thinknxg_kc_admin_token:{self.realm}:{self.client_id}"
		if self._cache and (tok := self._cache.get_value(key)):
			return tok
		resp = self._http.post(
			f"{self.base}/realms/{quote(self.realm, safe='')}/protocol/openid-connect/token",
			data={"grant_type": "client_credentials"},
			auth=(self.client_id, self.client_secret),
			timeout=TIMEOUT,
			allow_redirects=False,
		)
		if resp.status_code != 200:
			raise KeycloakError("kc_auth_failed", f"Token request failed ({resp.status_code})")
		data = resp.json()
		tok = data["access_token"]
		if self._cache:
			self._cache.set_value(key, tok, expires_in_sec=max(10, int(data.get("expires_in", 60)) - 30))
		return tok

	def _call(self, method: str, path: str, *, json_body=None, expected=(200, 201, 204)):
		resp = self._http.request(
			method,
			self._url(path),
			json=json_body,
			headers={"Authorization": f"Bearer {self._token()}"},
			timeout=TIMEOUT,
			allow_redirects=False,
		)
		if resp.status_code not in expected:
			raise KeycloakError(f"kc_http_{resp.status_code}", f"{method} {path} failed")
		return resp

	# ------------------------------------------------------------------ users
	def find_user_id(self, email: str) -> str | None:
		resp = self._call("GET", f"/users?email={quote(email, safe='')}&exact=true")
		rows = resp.json()
		return rows[0]["id"] if rows else None

	def create_user(self, rep: dict) -> str:
		resp = self._call("POST", "/users", json_body=rep, expected=(201, 409))
		if resp.status_code == 201:
			return resp.headers["Location"].rstrip("/").rsplit("/", 1)[-1]
		existing = self.find_user_id(rep["email"])
		if not existing:
			raise KeycloakError("kc_conflict", "User conflict but no matching user found")
		current = self._call("GET", f"/users/{existing}").json()
		if (current.get("attributes") or {}).get("central_uid") != rep["attributes"]["central_uid"]:
			raise KeycloakError("kc_identity_conflict", "A different identity already uses this email")
		return existing

	def update_user(self, keycloak_user_id: str, rep: dict) -> None:
		"""Sync name, email, enabled flag and the central_uid attribute (PUT replaces them)."""
		self._call("PUT", f"/users/{quote(keycloak_user_id, safe='')}", json_body=rep)

	def set_user_enabled(self, keycloak_user_id: str, enabled: bool) -> None:
		self._call("PUT", f"/users/{quote(keycloak_user_id, safe='')}", json_body={"enabled": bool(enabled)})

	def logout_user(self, keycloak_user_id: str) -> None:
		"""End every IdP session. Keycloak then sends back-channel logout to each site."""
		self._call("POST", f"/users/{quote(keycloak_user_id, safe='')}/logout")

	# ------------------------------------------------------------------ clients
	def ensure_client(self, rep: dict) -> tuple[str, str]:
		"""Create or update a site client. Returns ``(client_uuid, client_secret)``."""
		found = self._call("GET", f"/clients?clientId={quote(rep['clientId'], safe='')}").json()
		if found:
			uuid = found[0]["id"]
			self._call("PUT", f"/clients/{uuid}", json_body=rep)
		else:
			resp = self._call("POST", "/clients", json_body=rep, expected=(201,))
			uuid = resp.headers["Location"].rstrip("/").rsplit("/", 1)[-1]
		secret = self._call("GET", f"/clients/{uuid}/client-secret").json()["value"]
		return uuid, secret

	def set_client_enabled(self, client_id: str, enabled: bool) -> None:
		found = self._call("GET", f"/clients?clientId={quote(client_id, safe='')}").json()
		if not found:
			return
		self._call("PUT", f"/clients/{found[0]['id']}", json_body={**found[0], "enabled": bool(enabled)})

	def delete_client(self, client_uuid: str) -> None:
		self._call("DELETE", f"/clients/{quote(client_uuid, safe='')}")
