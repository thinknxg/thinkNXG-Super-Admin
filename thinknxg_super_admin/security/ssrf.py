"""Outbound URL guard (SSRF defence) for Super Admin -> managed site calls.

``validate_outbound_url`` is used when a site is registered or its URL changes, and
``resolve_public_addresses`` must be used again immediately before every outbound call.
``pinned_http.request`` (Phase 8) connects to a *validated IP* (with the Host header and TLS SNI set
to the site name) so DNS rebinding between check and use cannot redirect the request.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

Resolver = Callable[..., list]


class UnsafeURLError(ValueError):
	pass


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
	if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
		ip = ip.ipv4_mapped
	return ip.is_global and not (ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_reserved)


def resolve_public_addresses(
	hostname: str, port: int = 443, *, resolver: Resolver = socket.getaddrinfo
) -> list[str]:
	try:
		infos = resolver(hostname, port, type=socket.SOCK_STREAM)
	except OSError as e:
		raise UnsafeURLError(f"cannot resolve {hostname}") from e
	addresses = []
	for info in infos:
		raw = info[4][0].split("%")[0]
		try:
			ip = ipaddress.ip_address(raw)
		except ValueError as e:
			raise UnsafeURLError(f"bad address for {hostname}") from e
		if not _is_public(ip):
			raise UnsafeURLError(f"{hostname} resolves to a non-public address")
		addresses.append(str(ip))
	if not addresses:
		raise UnsafeURLError(f"{hostname} has no addresses")
	return sorted(set(addresses))


def validate_outbound_url(
	url: str,
	*,
	allowed_ports: Iterable[int] = (443,),
	resolver: Resolver = socket.getaddrinfo,
	resolve: bool = True,
) -> str:
	"""Return the normalized origin (``https://host[:port]``) or raise :class:`UnsafeURLError`."""
	parts = urlsplit(url.strip())
	if parts.scheme != "https":
		raise UnsafeURLError("only https URLs are allowed")
	if parts.username or parts.password:
		raise UnsafeURLError("credentials in URL are not allowed")
	if parts.query or parts.fragment:
		raise UnsafeURLError("query or fragment not allowed in a site URL")
	if parts.path not in ("", "/"):
		raise UnsafeURLError("site URL must be an origin without a path")
	host = (parts.hostname or "").lower().rstrip(".")
	if not host or "." not in host:
		raise UnsafeURLError("a fully qualified host name is required")
	try:
		ipaddress.ip_address(host)
	except ValueError:
		pass
	else:
		raise UnsafeURLError("IP literals are not allowed")
	if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan")):
		raise UnsafeURLError("internal host names are not allowed")
	try:
		port = parts.port or 443
	except ValueError as e:
		raise UnsafeURLError("invalid port") from e
	if port not in set(allowed_ports):
		raise UnsafeURLError(f"port {port} is not allowed")
	if resolve:
		resolve_public_addresses(host, port, resolver=resolver)
	return f"https://{host}" + ("" if port == 443 else f":{port}")
