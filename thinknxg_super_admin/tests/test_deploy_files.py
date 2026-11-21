"""Guards on the deployment kit. Pure; skipped when the kit is not present (for example in a site install)."""

import json
import pathlib
import re
import shutil
import subprocess
import unittest

DEPLOY = pathlib.Path(__file__).resolve().parents[2] / "deploy"


@unittest.skipUnless(DEPLOY.is_dir(), "deploy kit not present")
class DeployKitTest(unittest.TestCase):
	def test_shell_scripts_parse_and_are_executable(self):
		bash = shutil.which("bash")
		for script in sorted(DEPLOY.rglob("*.sh")):
			self.assertTrue(script.stat().st_mode & 0o111, f"{script.name} is not executable")
			if bash:
				result = subprocess.run([bash, "-n", str(script)], capture_output=True, text=True)
				self.assertEqual(result.returncode, 0, f"{script.name}: {result.stderr}")

	def test_scripts_fail_fast(self):
		for script in sorted(DEPLOY.rglob("*.sh")):
			self.assertIn("set -", script.read_text(), f"{script.name} lacks set -e/-u")

	def test_backup_never_ships_the_encryption_key(self):
		text = (DEPLOY / "backup" / "backup.sh").read_text()
		self.assertIn("site_config_backup.json", text)
		self.assertIn("-delete", text)
		self.assertIn("grep -rIlF", text)
		self.assertIn("--with-files", text)
		self.assertIn("age -R", text)
		self.assertNotIn("--backup-path-conf", text)

	def test_restore_does_not_put_secrets_on_the_command_line(self):
		text = (DEPLOY / "backup" / "restore.sh").read_text()
		self.assertNotIn("--db-root-password", text)
		self.assertNotIn("--force", text)  # the downgrade warning must stay visible
		self.assertLess(
			text.index("encryption_key"), text.index('restore "$DB"'), "key is restored before the data"
		)

	def test_escrow_script_refuses_to_print_to_pipes(self):
		self.assertIn("[ -t 1 ]", (DEPLOY / "backup" / "escrow_key.sh").read_text())

	def test_compose_exposes_nothing_but_loopback_and_pins_versions(self):
		text = (DEPLOY / "keycloak" / "docker-compose.prod.yml").read_text()
		self.assertIn('"127.0.0.1:8080:8080"', text)
		self.assertNotIn("9000", re.sub(r"#.*", "", text))
		self.assertNotIn("start-dev", text)
		self.assertNotIn(":latest", text)
		self.assertIn("${KEYCLOAK_VERSION:?", text)
		self.assertIn("${POSTGRES_VERSION:?", text)
		self.assertNotRegex(text, r"(?m)^\s+- \"?(0\.0\.0\.0:)?5432")

	def test_keycloak_proxy_blocks_unneeded_paths(self):
		text = (DEPLOY / "nginx" / "keycloak.conf").read_text()
		self.assertIn("location / { return 404; }", text)
		for path in ("/realms/master/", "/admin/"):
			block = text[text.index(f"location ^~ {path}" if "master" in path else f"location {path}") :]
			self.assertIn("deny all;", block.split("}")[0], path)
		self.assertNotIn("9000", re.sub(r"#.*", "", text))
		self.assertIn('proxy_set_header Forwarded "";', text)
		self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", text)

	def test_site_snippet_blocks_dotfiles_and_limits_sensitive_paths(self):
		text = (DEPLOY / "nginx" / "tnxg-site.conf").read_text()
		for needle in (
			"limit_req zone=tnxg_sensitive",
			"limit_req zone=tnxg_pair",
			"$tnxg_desk_denied",
			"deny all",
		):
			self.assertIn(needle, text)

	def test_example_site_config_is_safe(self):
		config = json.loads((DEPLOY / "ops" / "site_config.production.example.json").read_text())
		self.assertEqual(config["developer_mode"], 0)
		self.assertIs(config["server_script_enabled"], False)
		for forbidden in ("allow_cors", "ignore_csrf", "allowed_referrers", "encryption_key", "db_password"):
			self.assertNotIn(forbidden, config)

	def test_no_secrets_in_the_kit(self):
		pattern = re.compile(r"(password|secret|key)\s*[=:]\s*['\"]?[A-Za-z0-9+/_\-]{16,}", re.I)
		for path in DEPLOY.rglob("*"):
			if path.is_file() and path.suffix in {".sh", ".yml", ".conf", ".json", ".md", ".example"}:
				for line in path.read_text().splitlines():
					if pattern.search(line) and "${" not in line and "$(" not in line:
						self.fail(f"{path.name}: possible secret: {line.strip()[:80]}")
