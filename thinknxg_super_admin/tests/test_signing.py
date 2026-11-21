import unittest

from thinknxg_super_admin.security import signing as s


class TestSigning(unittest.TestCase):
	def setUp(self):
		self.priv_pem, self.pub_pem = s.generate_keypair()
		self.priv = s.load_private_key(self.priv_pem)
		self.pub = s.load_public_key(self.pub_pem)
		self.seen = set()

	def _claim(self, rid, ttl):
		if rid in self.seen:
			return False
		self.seen.add(rid)
		return True

	def _verify(self, method, path, body, headers, now=None, keys=None):
		keys = {"k1": self.pub} if keys is None else keys
		return s.verify_request(
			method,
			path,
			body,
			headers,
			public_key_loader=keys.get,
			claim_request_id=self._claim,
			now=now,
		)

	def test_roundtrip(self):
		h = s.sign_request(self.priv, "k1", "POST", "/api/x?a=1", b"{}", now=1000)
		v = self._verify("post", "/api/x?a=1", b"{}", h, now=1000)
		self.assertEqual(v.key_id, "k1")

	def test_header_names_case_insensitive(self):
		h = s.sign_request(self.priv, "k1", "GET", "/p", None, now=1000)
		h = {k.lower(): v for k, v in h.items()}
		self._verify("GET", "/p", None, h, now=1000)

	def test_tampered_body_rejected(self):
		h = s.sign_request(self.priv, "k1", "POST", "/p", b"a", now=1000)
		with self.assertRaises(s.SignatureError) as cm:
			self._verify("POST", "/p", b"b", h, now=1000)
		self.assertEqual(cm.exception.code, "signature_invalid")

	def test_tampered_path_and_method_rejected(self):
		h = s.sign_request(self.priv, "k1", "POST", "/p", b"a", now=1000)
		for method, path in (("GET", "/p"), ("POST", "/q")):
			with self.assertRaises(s.SignatureError):
				self._verify(method, path, b"a", dict(h), now=1000)

	def test_replay_rejected(self):
		h = s.sign_request(self.priv, "k1", "POST", "/p", b"a", now=1000)
		self._verify("POST", "/p", b"a", h, now=1000)
		with self.assertRaises(s.SignatureError) as cm:
			self._verify("POST", "/p", b"a", h, now=1001)
		self.assertEqual(cm.exception.code, "replayed")

	def test_bad_signature_does_not_consume_request_id(self):
		h = s.sign_request(self.priv, "k1", "POST", "/p", b"a", now=1000)
		bad = dict(h)
		bad[s.H_SIGNATURE] = bad[s.H_SIGNATURE][:-2] + "AA"
		with self.assertRaises(s.SignatureError):
			self._verify("POST", "/p", b"a", bad, now=1000)
		self.assertEqual(self.seen, set())

	def test_clock_skew(self):
		h = s.sign_request(self.priv, "k1", "POST", "/p", b"a", now=1000)
		with self.assertRaises(s.SignatureError):
			self._verify("POST", "/p", b"a", h, now=1000 + s.MAX_SKEW_SECONDS + 1)

	def test_unknown_or_revoked_key(self):
		h = s.sign_request(self.priv, "k1", "POST", "/p", b"a", now=1000)
		with self.assertRaises(s.SignatureError):
			self._verify("POST", "/p", b"a", h, now=1000, keys={})

	def test_other_sites_key_rejected(self):
		_, other_pub_pem = s.generate_keypair()
		h = s.sign_request(self.priv, "k1", "POST", "/p", b"a", now=1000)
		with self.assertRaises(s.SignatureError):
			self._verify("POST", "/p", b"a", h, now=1000, keys={"k1": s.load_public_key(other_pub_pem)})

	def test_missing_headers(self):
		with self.assertRaises(s.SignatureError):
			self._verify("POST", "/p", b"", {})

	def test_newline_injection_rejected(self):
		with self.assertRaises(s.SignatureError):
			s.sign_request(self.priv, "k1", "POST", "/p\nGET", b"", now=1000)


if __name__ == "__main__":
	unittest.main()
