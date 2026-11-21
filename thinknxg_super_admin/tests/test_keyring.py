import unittest
from datetime import datetime, timedelta

from thinknxg_super_admin.security import keyring, signing

NOW = datetime(2026, 11, 21, 12, 0, 0)


def _pub():
	return signing.generate_keypair()[1]


class KeyringTest(unittest.TestCase):
	def test_find_current_and_overlap(self):
		a, b = _pub(), _pub()
		entries = [keyring.KeyEntry("key-aaaaaaaa", a), keyring.KeyEntry("key-bbbbbbbb", b, NOW + timedelta(hours=1))]
		self.assertEqual(keyring.find(entries, "key-aaaaaaaa", NOW), a)
		self.assertEqual(keyring.find(entries, "key-bbbbbbbb", NOW), b)

	def test_expired_entry_is_rejected(self):
		entries = [keyring.KeyEntry("key-bbbbbbbb", _pub(), NOW)]
		self.assertIsNone(keyring.find(entries, "key-bbbbbbbb", NOW))
		self.assertIsNone(keyring.find(entries, "key-bbbbbbbb", NOW + timedelta(seconds=1)))

	def test_unknown_and_empty_ids(self):
		entries = [keyring.KeyEntry(None, None), keyring.KeyEntry("key-aaaaaaaa", _pub())]
		self.assertIsNone(keyring.find(entries, "", NOW))
		self.assertIsNone(keyring.find(entries, "key-zzzzzzzz", NOW))

	def test_validate_new_key_accepts_fresh(self):
		current = keyring.KeyEntry("key-aaaaaaaa", _pub())
		self.assertEqual(len(keyring.validate_new_key("key-bbbbbbbb", _pub(), [current])), 32)

	def test_validate_new_key_refusals(self):
		pem = _pub()
		current = keyring.KeyEntry("key-aaaaaaaa", pem)
		cases = [
			(("bad id!", _pub()), "bad_key_id"),
			(("short", _pub()), "bad_key_id"),
			(("key-aaaaaaaa", _pub()), "key_id_reused"),
			(("key-bbbbbbbb", pem), "key_reused"),
			(("key-bbbbbbbb", "not a pem"), "bad_public_key"),
			(("key-bbbbbbbb", ""), "bad_public_key"),
		]
		for args, code in cases:
			with self.assertRaises(keyring.KeyringError) as ctx:
				keyring.validate_new_key(*args, [current])
			self.assertEqual(ctx.exception.code, code, args[0])

	def test_non_ed25519_key_refused(self):
		from cryptography.hazmat.primitives import serialization
		from cryptography.hazmat.primitives.asymmetric import ec

		pem = (
			ec.generate_private_key(ec.SECP256R1())
			.public_key()
			.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
			.decode()
		)
		with self.assertRaises(keyring.KeyringError) as ctx:
			keyring.validate_new_key("key-bbbbbbbb", pem, [])
		self.assertEqual(ctx.exception.code, "not_ed25519")

	def test_rotation_status(self):
		self.assertEqual(keyring.rotation_status(None, {"a": "x"}), (False, []))
		self.assertEqual(keyring.rotation_status("n1", {"a": "n1", "b": "n1"}), (True, []))
		self.assertEqual(keyring.rotation_status("n1", {"a": "n1", "b": "old", "c": None}), (False, ["b", "c"]))
		self.assertEqual(keyring.rotation_status("n1", {}), (True, []))
