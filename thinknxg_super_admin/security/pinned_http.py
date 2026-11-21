"""HTTPS client that connects to a *validated IP* while verifying TLS against the site's host name.

Validating a name and then letting ``requests`` resolve it again leaves a window in which DNS can
return a different (internal) address. Here the name is resolved once through ``ssrf``, every
address must be public, and the connection goes to that address. The URL host is the IP, the
``Host`` header, TLS SNI and certificate check all use the original host name, redirects are never
followed and the body is capped.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter

from thinknxg_super_admin.security import ssrf

TIMEOUT = (3.05, 20)
MAX_BYTES = 256 * 1024


class PinnedError(Exception):
	def __init__(self, code: str, status: int | None = None):
		super().__init__(code)
		self.code = code
		self.status = status


@dataclass
class PinnedResponse:
	status: int
	body: bytes


class _Adapter(HTTPAdapter):
	def __init__(self, hostname: str, ca_bundle: str | None = None, **kwargs):
		self._hostname = hostname
		self._ca_bundle = ca_bundle
		super().__init__(**kwargs)

	def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
		pool_kwargs["server_hostname"] = self._hostname
		pool_kwargs["assert_hostname"] = self._hostname
		super().init_poolmanager(connections, maxsize, block, **pool_kwargs)


def _netloc(ip: str, port: int) -> str:
	return f"[{ip}]:{port}" if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address) else f"{ip}:{port}"


def request(
	method: str,
	site_url: str,
	path: str,
	*,
	headers: dict | None = None,
	body: bytes | None = None,
	timeout=TIMEOUT,
	max_bytes: int = MAX_BYTES,
	resolver=socket.getaddrinfo,
	allowed_ports=(443,),
	verify: bool | str = True,
) -> PinnedResponse:
	"""Send one request. Raises :class:`PinnedError` with a short code on any failure.

	``resolver``, ``allowed_ports`` and ``verify`` exist so tests can use a local server; production
	callers pass none of them.
	"""
	try:
		origin = ssrf.validate_outbound_url(site_url, allowed_ports=allowed_ports, resolver=resolver)
	except ssrf.UnsafeURLError as exc:
		raise PinnedError("unsafe_url") from exc
	parts = urlsplit(origin)
	host, port = parts.hostname, parts.port or 443
	try:
		addresses = ssrf.resolve_public_addresses(host, port, resolver=resolver)
	except ssrf.UnsafeURLError as exc:
		raise PinnedError("unsafe_url") from exc

	last: PinnedError | None = None
	for ip in addresses:
		session = requests.Session()
		session.trust_env = False  # no proxy or netrc surprises from the environment
		session.mount("https://", _Adapter(host))
		send_headers = dict(headers or {})
		send_headers["Host"] = host if port == 443 else f"{host}:{port}"
		try:
			resp = session.request(
				method,
				f"https://{_netloc(ip, port)}{path}",
				data=body or None,
				headers=send_headers,
				timeout=timeout,
				allow_redirects=False,
				stream=True,
				verify=verify,
			)
		except requests.Timeout:
			last = PinnedError("timeout")
			continue
		except requests.exceptions.SSLError:
			last = PinnedError("tls_error")
			continue
		except requests.RequestException:
			last = PinnedError("unreachable")
			continue
		try:
			raw = resp.raw.read(max_bytes + 1, decode_content=True)
			if len(raw) > max_bytes:
				raise PinnedError("response_too_large", resp.status_code)
			return PinnedResponse(resp.status_code, raw)
		finally:
			resp.close()
			session.close()
	raise last or PinnedError("unreachable")
