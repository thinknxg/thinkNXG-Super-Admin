"""Pure key-set helpers for rotation with overlap. Identical copy in both apps; no Frappe imports.

During a rotation a verifier accepts two keys at once (the current key and the next/previous one),
so neither side has a moment where its peer's signatures are rejected.
"""

import hmac
import re
from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class KeyringError(ValueError):
	def __init__(self, code: str):
		super().__init__(code)
		self.code = code


@dataclass(frozen=True)
class KeyEntry:
	key_id: str | None
	public_pem: str | None
	not_after: datetime | None = None  # None means no expiry


def raw_public_bytes(pem: str) -> bytes:
	try:
		key = serialization.load_pem_public_key((pem or "").encode())
	except Exception as exc:
		raise KeyringError("bad_public_key") from exc
	if not isinstance(key, Ed25519PublicKey):
		raise KeyringError("not_ed25519")
	return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def find(entries: list[KeyEntry], key_id: str, now: datetime) -> str | None:
	"""Return the PEM for ``key_id`` if an unexpired entry has it. Constant-time id comparison."""
	found = None
	for entry in entries:
		if not entry.key_id or not entry.public_pem:
			continue
		if hmac.compare_digest(entry.key_id.encode(), (key_id or "").encode()):
			if entry.not_after is None or now < entry.not_after:
				found = entry.public_pem
	return found


def validate_new_key(new_id: str, new_pem: str, existing: list[KeyEntry]) -> bytes:
	"""Check a proposed key. It must be well formed, use a fresh id and be a different key."""
	if not isinstance(new_id, str) or not KEY_ID_RE.match(new_id):
		raise KeyringError("bad_key_id")
	raw = raw_public_bytes(new_pem)
	for entry in existing:
		if not entry.key_id:
			continue
		if entry.key_id == new_id:
			raise KeyringError("key_id_reused")
		if entry.public_pem and hmac.compare_digest(raw_public_bytes(entry.public_pem), raw):
			raise KeyringError("key_reused")
	return raw


def rotation_status(next_id: str | None, acked: dict[str, str | None]) -> tuple[bool, list[str]]:
	"""``acked`` maps site name to the newest central key id it has staged. Returns (ready, pending)."""
	if not next_id:
		return False, []
	pending = sorted(site for site, key_id in acked.items() if key_id != next_id)
	return not pending, pending
