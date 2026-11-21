"""Headless check of the login flow against the dev Keycloak stack. Tokens are validated and dropped.

Usage:  python3 smoke_test.py            (after `docker compose up -d` in this folder)

It drives the real authorization-code + PKCE flow as the test user, then runs the agent's own
validation code (``thinknxg_site_agent.auth.oidc``) on the resulting ID token. It also proves the
negative cases against live tokens: wrong nonce, wrong audience and a replayed code are rejected.
Run with the agent app importable, e.g. from the repo root:  PYTHONPATH=../../../thinknxg_site_agent
"""

import html
import re
import sys

import requests
from thinknxg_site_agent.auth import oidc

ISSUER = "http://localhost:8080/realms/thinknxg"
CLIENT_ID, CLIENT_SECRET = "tnxg-site-demo", "dev-only-secret-change-me"
REDIRECT = "http://localhost:8000/api/method/thinknxg_site_agent.api.v1.auth.callback"
USER, PASSWORD = "alice@example.test", "Passw0rd!dev"
EXPECTED_UID = "6f1c2a52-3d0b-4c43-9a6b-2f6a1d0e8c11"


def fail(msg):
	print("FAIL:", msg)
	sys.exit(1)


def main():
	disc = requests.get(f"{ISSUER}/.well-known/openid-configuration", timeout=10).json()
	if disc["issuer"] != ISSUER:
		fail(f"issuer mismatch: {disc['issuer']}")
	for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
		oidc.check_endpoint(disc[k], ISSUER, allow_insecure_localhost=True)
	jwks = requests.get(disc["jwks_uri"], timeout=10).json()

	public, _stored = oidc.make_flow(next_path="/app")
	url = oidc.build_authorize_url(
		disc["authorization_endpoint"], client_id=CLIENT_ID, redirect_uri=REDIRECT,
		state=public["state"], nonce=public["nonce"], verifier=public["verifier"],
	)
	s = requests.Session()
	page = s.get(url, timeout=10)
	m = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page.text) or re.search(r'action="([^"]+)"', page.text)
	if not m:
		fail("login form not found")
	resp = s.post(html.unescape(m.group(1)), data={"username": USER, "password": PASSWORD}, allow_redirects=False, timeout=10)
	loc = resp.headers.get("Location", "")
	if not loc.startswith(REDIRECT):
		fail(f"expected redirect to the site callback, got {resp.status_code} {loc[:120]}")
	q = dict(p.split("=", 1) for p in loc.split("?", 1)[1].split("&"))
	if q.get("state") != public["state"]:
		fail("state not echoed")
	code = q["code"]

	body = oidc.token_request_body(code=code, redirect_uri=REDIRECT, client_id=CLIENT_ID, verifier=public["verifier"])
	tok = requests.post(disc["token_endpoint"], data=body, auth=(CLIENT_ID, CLIENT_SECRET), timeout=10)
	if tok.status_code != 200:
		fail(f"token exchange failed: {tok.status_code} {tok.text[:200]}")
	payload = tok.json()
	if "refresh_token" in payload:
		fail("a refresh token was issued; the client must have use.refresh.tokens=false")
	id_token = oidc.extract_id_token(payload)

	def keys(kid):
		return oidc.select_signing_key(jwks, kid)

	claims = oidc.validate_id_token(id_token, keys, issuer=ISSUER, client_id=CLIENT_ID, nonce=public["nonce"])
	if claims["central_uid"] != EXPECTED_UID:
		fail("central_uid claim missing or wrong; check the user profile and the protocol mapper")
	oidc.validate_email_claims(claims)
	print("OK  id_token valid: sub present, central_uid matches, email verified, sid:", bool(claims.get("sid")))

	for label, kwargs, want in (
		("wrong nonce", {"nonce": "x"}, "nonce_mismatch"),
		("wrong audience", {"client_id": "other"}, "aud_mismatch"),
		("wrong issuer", {"issuer": ISSUER + "x"}, "iss_mismatch"),
	):
		args = {"issuer": ISSUER, "client_id": CLIENT_ID, "nonce": public["nonce"]}
		args.update(kwargs)
		try:
			oidc.validate_id_token(id_token, keys, **args)
		except oidc.OIDCError as exc:
			if exc.code != want:
				fail(f"{label}: expected {want}, got {exc.code}")
			print("OK  rejected:", label)
		else:
			fail(f"{label} was accepted")

	again = requests.post(disc["token_endpoint"], data=body, auth=(CLIENT_ID, CLIENT_SECRET), timeout=10)
	if again.status_code == 200:
		fail("authorization code was accepted twice")
	print("OK  authorization code is single use")
	print("All checks passed. Tokens were validated in memory and discarded.")


if __name__ == "__main__":
	main()
