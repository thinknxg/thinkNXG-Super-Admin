"""Pure: real TLS handshakes against a local server prove the pinning behaviour."""

import datetime
import http.server
import ipaddress
import os
import socket
import ssl
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from thinknxg_super_admin.security import pinned_http

HOST = "site.example.test"


def _make_cert(directory: str, names: list[str]):
	key = ec.generate_private_key(ec.SECP256R1())
	name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
	now = datetime.datetime.now(datetime.UTC)
	cert = (
		x509.CertificateBuilder()
		.subject_name(name)
		.issuer_name(name)
		.public_key(key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(now - datetime.timedelta(minutes=5))
		.not_valid_after(now + datetime.timedelta(hours=1))
		.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
		.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
		.sign(key, hashes.SHA256())
	)
	cert_path, key_path = os.path.join(directory, "c.pem"), os.path.join(directory, "k.pem")
	with open(cert_path, "wb") as f:
		f.write(cert.public_bytes(serialization.Encoding.PEM))
	with open(key_path, "wb") as f:
		f.write(
			key.private_bytes(
				serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
			)
		)
	return cert_path, key_path


class _Handler(http.server.BaseHTTPRequestHandler):
	seen: list = []

	def do_GET(self):
		_Handler.seen.append((self.headers.get("Host"), self.path))
		if self.path == "/redirect":
			self.send_response(302)
			self.send_header("Location", "https://169.254.169.254/")
			self.end_headers()
			return
		body = b"x" * 5000 if self.path == "/big" else b'{"message":{"ok":true}}'
		self.send_response(200)
		self.send_header("Content-Length", str(len(body)))
		self.end_headers()
		self.wfile.write(body)

	def log_message(self, *a):
		pass


class PinnedHttpTest(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.tmp = tempfile.TemporaryDirectory()
		cls.cert, key = _make_cert(cls.tmp.name, [HOST])
		cls.wrong_cert, wrong_key = _make_cert(tempfile.mkdtemp(), ["other.example.test"])
		cls.servers = []
		cls.ports = {}
		for label, (c, k) in {"good": (cls.cert, key), "wrong": (cls.wrong_cert, wrong_key)}.items():
			server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
			ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
			ctx.load_cert_chain(c, k)
			server.socket = ctx.wrap_socket(server.socket, server_side=True)
			threading.Thread(target=server.serve_forever, daemon=True).start()
			cls.servers.append(server)
			cls.ports[label] = server.server_address[1]

	@classmethod
	def tearDownClass(cls):
		for s in cls.servers:
			s.shutdown()
		cls.tmp.cleanup()

	def _resolver(self, address="203.0.113.10"):
		# The test resolver reports a public address; _connect_to maps it to the local server.
		return lambda host, port, type=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

	def _call(self, label, path="/", **kw):
		port = self.ports[label]
		real = pinned_http.ssrf.resolve_public_addresses
		pinned_http.ssrf.resolve_public_addresses = lambda h, p, resolver=None: ["127.0.0.1"]
		try:
			return pinned_http.request(
				"GET", f"https://{HOST}:{port}", path, resolver=self._resolver(), allowed_ports=(port,), verify=self.cert, **kw
			)
		finally:
			pinned_http.ssrf.resolve_public_addresses = real

	def test_connects_to_pinned_ip_and_verifies_hostname(self):
		_Handler.seen.clear()
		resp = self._call("good")
		self.assertEqual(resp.status, 200)
		self.assertEqual(_Handler.seen[-1][0], f"{HOST}:{self.ports['good']}")

	def test_certificate_for_another_name_is_rejected(self):
		with self.assertRaises(pinned_http.PinnedError) as ctx:
			self._call("wrong")
		self.assertEqual(ctx.exception.code, "tls_error")

	def test_redirect_is_returned_not_followed(self):
		self.assertEqual(self._call("good", "/redirect").status, 302)

	def test_response_size_cap(self):
		with self.assertRaises(pinned_http.PinnedError) as ctx:
			self._call("good", "/big", max_bytes=1000)
		self.assertEqual(ctx.exception.code, "response_too_large")

	def test_private_resolution_is_refused_before_any_connection(self):
		for address in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "::ffff:10.0.0.1", "192.168.1.1"):
			with self.assertRaises(pinned_http.PinnedError) as ctx:
				pinned_http.request("GET", f"https://{HOST}", "/", resolver=self._resolver(address))
			self.assertEqual(ctx.exception.code, "unsafe_url", address)

	def test_mixed_public_and_private_answer_is_refused(self):
		def resolver(host, port, type=0):
			return [(2, 1, 6, "", ("203.0.113.10", port)), (2, 1, 6, "", ("10.0.0.1", port))]

		with self.assertRaises(pinned_http.PinnedError):
			pinned_http.request("GET", f"https://{HOST}", "/", resolver=resolver)

	def test_ip_literal_and_credentials_refused(self):
		for url in ("https://203.0.113.10", f"https://user:pw@{HOST}", "http://" + HOST, f"https://{HOST}:8443"):
			with self.assertRaises(pinned_http.PinnedError):
				pinned_http.request("GET", url, "/", resolver=self._resolver())

	def test_ipv6_netloc_is_bracketed(self):
		self.assertEqual(pinned_http._netloc("2001:db8::1", 443), "[2001:db8::1]:443")
		self.assertEqual(ipaddress.ip_address("203.0.113.10").version, 4)


if __name__ == "__main__":
	unittest.main()
