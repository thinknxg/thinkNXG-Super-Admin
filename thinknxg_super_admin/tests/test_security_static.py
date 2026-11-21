"""Static security checks over this app's source. Pure: parses code, imports nothing from Frappe."""

import ast
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
GUEST_AUTH_MARKERS = ("verify_site_request", "verify_central_request")
# Guest endpoints that authenticate some other way, each with the reason.
GUEST_ALLOWLIST = {
	"ops.healthz": "returns only ok / not ok for an external monitor; rate limited",
	"agent_in.pair": "authenticated by single-use pairing code and per-site attempt limit",
}
FORBIDDEN_PATTERNS = {
	r"verify\s*=\s*False": "TLS verification disabled",
	r"shell\s*=\s*True": "shell=True",
	r"\beval\(|\bexec\(": "eval/exec",
	r"pickle\.loads?\(": "pickle",
	r"yaml\.load\(": "unsafe yaml.load",
	r"allow_redirects\s*=\s*True": "following redirects",
	r"frappe\.db\.sql\(\s*f[\"']": "f-string SQL",
	r"\.format\([^)]*\)\s*,?\s*\)?\s*$(?<=sql)": "formatted SQL",
}


_PEP758 = re.compile(r"except ([^()\n:]+,[^()\n:]+):")


def _parse(text):
	"""Python 3.14 allows ``except A, B:``; make it parseable on older interpreters too."""
	return ast.parse(_PEP758.sub(r"except (\1):", text))


def _sources():
	for path in sorted(ROOT.rglob("*.py")):
		if "tests" in path.parts or "patches" in path.parts:
			continue
		yield path, path.read_text()


def _whitelisted():
	for path, text in _sources():
		tree = _parse(text)
		for node in ast.walk(tree):
			if not isinstance(node, ast.FunctionDef):
				continue
			for dec in node.decorator_list:
				call = dec if isinstance(dec, ast.Call) else None
				name = ast.unparse(call.func if call else dec)
				if name == "frappe.whitelist":
					kw = {k.arg: k.value for k in (call.keywords if call else [])}
					yield path, node, kw, ast.get_source_segment(text, node) or ""


class SecurityStaticTest(unittest.TestCase):
	def test_every_whitelisted_endpoint_restricts_methods(self):
		bad = [f"{p.name}:{n.name}" for p, n, kw, _ in _whitelisted() if "methods" not in kw]
		self.assertEqual(bad, [], "whitelisted endpoints must set methods=[...]")

	def test_guest_endpoints_authenticate_or_are_allowlisted(self):
		bad = []
		for path, node, kw, source in _whitelisted():
			guest = kw.get("allow_guest")
			if not (isinstance(guest, ast.Constant) and guest.value is True):
				continue
			key = f"{path.stem}.{node.name}"
			if key in GUEST_ALLOWLIST:
				continue
			if not any(m in source for m in GUEST_AUTH_MARKERS):
				bad.append(key)
		self.assertEqual(bad, [], "guest endpoint without request authentication")

	def test_guest_endpoints_are_rate_limited(self):
		bad = []
		for path, node, kw, _ in _whitelisted():
			guest = kw.get("allow_guest")
			if isinstance(guest, ast.Constant) and guest.value is True:
				if not any("rate_limit" in ast.unparse(d) for d in node.decorator_list):
					bad.append(f"{path.stem}.{node.name}")
		self.assertEqual(bad, [], "guest endpoints must be rate limited")

	def test_allowlist_has_no_stale_entries(self):
		present = set()
		for path, node, kw, _ in _whitelisted():
			guest = kw.get("allow_guest")
			if isinstance(guest, ast.Constant) and guest.value is True:
				present.add(f"{path.stem}.{node.name}")
		self.assertEqual(sorted(set(GUEST_ALLOWLIST) - present), [])

	def test_forbidden_constructs_absent(self):
		hits = []
		for path, text in _sources():
			for pattern, label in FORBIDDEN_PATTERNS.items():
				if re.search(pattern, text, re.M):
					hits.append(f"{path.relative_to(ROOT)}: {label}")
		self.assertEqual(hits, [])

	def test_no_hardcoded_secrets(self):
		pattern = re.compile(r"(secret|password|token|private_key)\w*\s*=\s*[\"'][^\"'\s]{12,}[\"']", re.I)
		hits = []
		for path, text in _sources():
			for line in text.splitlines():
				if pattern.search(line) and "get_password" not in line and "# nosec" not in line:
					hits.append(f"{path.relative_to(ROOT)}: {line.strip()[:80]}")
		self.assertEqual(hits, [])

	def test_secrets_are_not_logged_or_thrown(self):
		# Flags a secret-named *value* interpolated into a log or an error, not a message that merely names it.
		pattern = re.compile(
			r"(log_error|logger\([^)]*\)\.\w+|frappe\.throw)\(.*(\{[^}]*(secret|password|private_key|id_token)[^}]*\}|,\s*\w*(secret|password|private_key|id_token)\w*\s*\))",
			re.I,
		)
		hits = []
		for path, text in _sources():
			for line in text.splitlines():
				if pattern.search(line):
					hits.append(f"{path.relative_to(ROOT)}: {line.strip()[:80]}")
		self.assertEqual(hits, [])
