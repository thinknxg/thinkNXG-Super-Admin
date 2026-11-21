import unittest

from thinknxg_super_admin.authentication import keycloak as kc

ORIGIN = "https://acme.example.com"
CB = ORIGIN + "/api/method/thinknxg_site_agent.api.v1.auth.callback"


class TestClientRepresentation(unittest.TestCase):
	def rep(self, **kw):
		args = {"site_name": "Acme ERP", "site_origin": ORIGIN, "redirect_uris": [CB]}
		args.update(kw)
		return kc.client_representation(**args)

	def test_security_posture(self):
		r = self.rep()
		self.assertFalse(r["publicClient"])
		self.assertTrue(r["standardFlowEnabled"])
		self.assertFalse(r["implicitFlowEnabled"])
		self.assertFalse(r["directAccessGrantsEnabled"])
		self.assertFalse(r["serviceAccountsEnabled"])
		self.assertEqual(r["attributes"]["pkce.code.challenge.method"], "S256")
		self.assertEqual(r["attributes"]["use.refresh.tokens"], "false")
		self.assertEqual(r["attributes"]["backchannel.logout.session.required"], "true")
		self.assertEqual(r["redirectUris"], [CB])
		self.assertEqual(r["webOrigins"], [])

	def test_backchannel_url_is_on_site_origin(self):
		self.assertEqual(
			self.rep()["attributes"]["backchannel.logout.url"],
			ORIGIN + "/api/method/thinknxg_site_agent.api.v1.auth.backchannel_logout",
		)

	def test_central_uid_mapper_targets_id_token_only(self):
		cfg = self.rep()["protocolMappers"][0]["config"]
		self.assertEqual(cfg["claim.name"], "central_uid")
		self.assertEqual(cfg["id.token.claim"], "true")
		self.assertEqual(cfg["access.token.claim"], "false")

	def test_rejects_wildcards_foreign_hosts_and_http(self):
		for uris in ([ORIGIN + "/*"], ["https://evil.example.com/cb"], ["https://acme.example.com.evil.com/cb"], []):
			with self.assertRaises(kc.KeycloakError):
				self.rep(redirect_uris=uris)
		with self.assertRaises(kc.KeycloakError):
			self.rep(site_origin="http://acme.example.com", redirect_uris=["http://acme.example.com/cb"])

	def test_client_id_is_slugged_and_prefixed(self):
		self.assertEqual(kc.client_id_for("Acme ERP!"), "tnxg-site-acme-erp")
		with self.assertRaises(kc.KeycloakError):
			kc.client_id_for("###")


class TestUserRepresentation(unittest.TestCase):
	def test_carries_central_uid_attribute(self):
		r = kc.user_representation(central_uid="u", email="a@b.com", first_name="A", last_name=None)
		self.assertEqual(r["attributes"], {"central_uid": ["u"]})
		self.assertTrue(r["enabled"])
		self.assertEqual(r["username"], "a@b.com")


class _Resp:
	def __init__(self, status, body=None, headers=None):
		self.status_code, self._body, self.headers = status, body, headers or {}

	def json(self):
		return self._body


class _Http:
	def __init__(self, replies):
		self.replies, self.calls = list(replies), []
		self.max_redirects = 0

	def post(self, url, **kw):  # only the token endpoint uses .post
		self.calls.append(("POST", url, kw))
		return _Resp(200, {"access_token": "T", "expires_in": 60})

	def request(self, method, url, **kw):
		self.calls.append((method, url, kw))
		return self.replies.pop(0)


class TestAdminClient(unittest.TestCase):
	def admin(self, replies):
		http = _Http(replies)
		return kc.KeycloakAdmin("https://sso.example.com", "thinknxg", "svc", "sec", session=http), http

	def test_create_user_returns_id_from_location(self):
		a, _ = self.admin([_Resp(201, None, {"Location": "https://sso/admin/realms/r/users/abc-123"})])
		rep = kc.user_representation(central_uid="u", email="a@b.com", first_name=None, last_name=None)
		self.assertEqual(a.create_user(rep), "abc-123")

	def test_conflict_with_other_identity_is_refused(self):
		a, _ = self.admin([_Resp(409), _Resp(200, [{"id": "x"}]), _Resp(200, {"attributes": {"central_uid": ["someone-else"]}})])
		rep = kc.user_representation(central_uid="u", email="a@b.com", first_name=None, last_name=None)
		with self.assertRaises(kc.KeycloakError) as ctx:
			a.create_user(rep)
		self.assertEqual(ctx.exception.code, "kc_identity_conflict")

	def test_conflict_with_same_identity_is_idempotent(self):
		a, _ = self.admin([_Resp(409), _Resp(200, [{"id": "x"}]), _Resp(200, {"attributes": {"central_uid": ["u"]}})])
		rep = kc.user_representation(central_uid="u", email="a@b.com", first_name=None, last_name=None)
		self.assertEqual(a.create_user(rep), "x")

	def test_unexpected_status_raises_with_code(self):
		a, _ = self.admin([_Resp(500)])
		with self.assertRaises(kc.KeycloakError) as ctx:
			a.logout_user("id")
		self.assertEqual(ctx.exception.code, "kc_http_500")

	def test_never_follows_redirects_and_sends_bearer(self):
		a, http = self.admin([_Resp(204)])
		a.logout_user("id")
		_method, url, kw = http.calls[-1]
		self.assertFalse(kw["allow_redirects"])
		self.assertEqual(kw["headers"]["Authorization"], "Bearer T")
		self.assertTrue(url.endswith("/admin/realms/thinknxg/users/id/logout"))


if __name__ == "__main__":
	unittest.main()
