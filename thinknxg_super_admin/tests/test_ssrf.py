import socket
import unittest

from thinknxg_super_admin.security.ssrf import UnsafeURLError, validate_outbound_url


def fake(ip):
	family = socket.AF_INET6 if ":" in ip else socket.AF_INET
	return lambda host, port, **kw: [(family, socket.SOCK_STREAM, 6, "", (ip, port))]


class TestSSRF(unittest.TestCase):
	def ok(self, url, ip="93.184.216.34", **kw):
		return validate_outbound_url(url, resolver=fake(ip), **kw)

	def bad(self, url, ip="93.184.216.34", **kw):
		with self.assertRaises(UnsafeURLError):
			validate_outbound_url(url, resolver=fake(ip), **kw)

	def test_valid_and_normalized(self):
		self.assertEqual(self.ok("https://Company-A.thinknxg.com/"), "https://company-a.thinknxg.com")
		self.assertEqual(
			self.ok("https://a.example.com:8443", allowed_ports=(443, 8443)), "https://a.example.com:8443"
		)

	def test_scheme_and_shape(self):
		self.bad("http://a.example.com")
		self.bad("https://user:pw@a.example.com")
		self.bad("https://a.example.com/path")
		self.bad("https://a.example.com/?x=1")
		self.bad("https://a.example.com:8443")
		self.bad("https://intranet")

	def test_ip_literals_and_internal_names(self):
		self.bad("https://127.0.0.1")
		self.bad("https://[::1]")
		self.bad("https://localhost.localhost")
		self.bad("https://db.internal")

	def test_private_resolution_blocked(self):
		for ip in (
			"127.0.0.1",
			"10.0.0.5",
			"192.168.1.9",
			"169.254.169.254",
			"::1",
			"fe80::1",
			"::ffff:10.0.0.1",
			"100.64.0.1",
		):
			self.bad("https://a.example.com", ip=ip)

	def test_no_resolve_mode(self):
		self.assertEqual(
			validate_outbound_url("https://a.example.com", resolve=False), "https://a.example.com"
		)


if __name__ == "__main__":
	unittest.main()
