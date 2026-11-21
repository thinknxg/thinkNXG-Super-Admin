"""Ed25519 request signing shared by Super Admin (signer) and the site agent (verifier).

Pure Python: no ``frappe`` import, so it is unit-testable without a bench. This file is
intentionally duplicated in both apps (the agent must not depend on the central app).
Keep the two copies byte-identical; ``tests/test_signing.py`` guards the wire format.

Wire format
-----------
Headers: X-TNXG-Key-Id, X-TNXG-Timestamp (unix seconds), X-TNXG-Request-Id, X-TNXG-Signature.
Signed bytes (UTF-8, newline separated)::

    TNXG1
    <METHOD upper>
    <path including raw query string>
    <sha256 hex of body>
    <timestamp>
    <request id>
    <key id>

Signature = base64url(Ed25519(private_key, signed_bytes)), no padding.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

VERSION_TAG = "TNXG1"
MAX_SKEW_SECONDS = 120
REPLAY_TTL_SECONDS = MAX_SKEW_SECONDS * 2 + 5
MAX_BODY_BYTES = 1_048_576

H_KEY_ID = "X-TNXG-Key-Id"
H_TIMESTAMP = "X-TNXG-Timestamp"
H_REQUEST_ID = "X-TNXG-Request-Id"
H_SIGNATURE = "X-TNXG-Signature"


class SignatureError(Exception):
	"""Raised for any verification failure. ``code`` is a stable machine code."""

	def __init__(self, code: str, message: str):
		super().__init__(message)
		self.code = code
		self.message = message


def _b64e(raw: bytes) -> str:
	return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
	pad = "=" * (-len(text) % 4)
	return base64.urlsafe_b64decode(text + pad)


def body_digest(body: bytes | None) -> str:
	return hashlib.sha256(body or b"").hexdigest()


def canonical_bytes(
	method: str, path_with_query: str, body: bytes | None, timestamp: int | str, request_id: str, key_id: str
) -> bytes:
	parts = [
		VERSION_TAG,
		method.upper(),
		path_with_query,
		body_digest(body),
		str(timestamp),
		request_id,
		key_id,
	]
	for part in parts:
		if "\n" in part:
			raise SignatureError("signature_invalid", "newline in signed field")
	return "\n".join(parts).encode("utf-8")


def generate_keypair() -> tuple[str, str]:
	"""Return (private_pem, public_pem). The private PEM must go to a secret store."""
	key = Ed25519PrivateKey.generate()
	private_pem = key.private_bytes(
		serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
	).decode("ascii")
	public_pem = (
		key.public_key()
		.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
		.decode("ascii")
	)
	return private_pem, public_pem


def load_private_key(pem: str) -> Ed25519PrivateKey:
	key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
	if not isinstance(key, Ed25519PrivateKey):
		raise SignatureError("signature_invalid", "not an Ed25519 private key")
	return key


def load_public_key(pem: str) -> Ed25519PublicKey:
	key = serialization.load_pem_public_key(pem.encode("ascii"))
	if not isinstance(key, Ed25519PublicKey):
		raise SignatureError("signature_invalid", "not an Ed25519 public key")
	return key


def sign_request(
	private_key: Ed25519PrivateKey,
	key_id: str,
	method: str,
	path_with_query: str,
	body: bytes | None,
	*,
	now: int | None = None,
	request_id: str | None = None,
) -> dict[str, str]:
	ts = int(now if now is not None else time.time())
	rid = request_id or secrets.token_urlsafe(18)
	sig = private_key.sign(canonical_bytes(method, path_with_query, body, ts, rid, key_id))
	return {H_KEY_ID: key_id, H_TIMESTAMP: str(ts), H_REQUEST_ID: rid, H_SIGNATURE: _b64e(sig)}


@dataclass(frozen=True)
class VerifiedRequest:
	key_id: str
	request_id: str
	timestamp: int


def _header(headers: Mapping[str, str], name: str) -> str:
	lowered = name.lower()
	for k, v in headers.items():
		if k.lower() == lowered:
			return v
	return ""


def verify_request(
	method: str,
	path_with_query: str,
	body: bytes | None,
	headers: Mapping[str, str],
	*,
	public_key_loader: Callable[[str], Ed25519PublicKey | None],
	claim_request_id: Callable[[str, int], bool],
	now: int | None = None,
) -> VerifiedRequest:
	"""Verify a signed request or raise :class:`SignatureError`.

	``public_key_loader(key_id)`` returns the active public key or ``None`` (unknown or revoked).
	``claim_request_id(request_id, ttl_seconds)`` must atomically record the id and return True
	only the first time it is seen. It is called **after** the signature checks out, so
	unauthenticated callers cannot fill the replay cache.
	"""
	if body is not None and len(body) > MAX_BODY_BYTES:
		raise SignatureError("validation_failed", "request body too large")

	key_id = _header(headers, H_KEY_ID)
	ts_raw = _header(headers, H_TIMESTAMP)
	request_id = _header(headers, H_REQUEST_ID)
	sig_raw = _header(headers, H_SIGNATURE)
	if not (key_id and ts_raw and request_id and sig_raw):
		raise SignatureError("signature_invalid", "missing signature headers")
	if len(key_id) > 140 or len(request_id) > 140:
		raise SignatureError("signature_invalid", "header too long")

	try:
		ts = int(ts_raw)
	except ValueError:
		raise SignatureError("signature_invalid", "bad timestamp") from None

	current = int(now if now is not None else time.time())
	if abs(current - ts) > MAX_SKEW_SECONDS:
		raise SignatureError("signature_invalid", "timestamp outside allowed window")

	public_key = public_key_loader(key_id)
	if public_key is None:
		raise SignatureError("signature_invalid", "unknown or revoked key")

	try:
		signature = _b64d(sig_raw)
		public_key.verify(signature, canonical_bytes(method, path_with_query, body, ts, request_id, key_id))
	except (InvalidSignature, ValueError):
		raise SignatureError("signature_invalid", "signature mismatch") from None

	if not claim_request_id(f"{key_id}:{request_id}", REPLAY_TTL_SECONDS):
		raise SignatureError("replayed", "request id already used")

	return VerifiedRequest(key_id=key_id, request_id=request_id, timestamp=ts)
