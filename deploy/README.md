# thinkNXG Super Admin: production deployment kit

Everything here was written and exercised in a sandbox (nginx configs under `nginx -t` with live requests,
backup/restore scripts with a fake bench and real `age`, compose file under `docker compose config`).
**None of it has run on your servers, a real bench or a real Keycloak.** Do the first deployment on a
staging copy and keep `GO_LIVE_CHECKLIST.md` open.

## Topology (three roles, kept apart)

| Role | Runs | Reachable from |
|---|---|---|
| **Central** | One Frappe v16 bench: Super Admin only (no ERP, no other apps), MariaDB/Postgres and Redis on the same host or private network, nginx | Internet on 443: managed sites and Keycloak call `agent_in.*`; Desk only from your admin networks |
| **IdP** | Keycloak + PostgreSQL (docker compose), nginx in front | Internet on 443 for `/realms/` and `/resources/`; `/admin/` only from Central and your admin networks |
| **Managed sites** | Your existing benches with `thinknxg_site_agent` installed | Internet on 443; Central polls them |

Central and the IdP may share a host in a small setup, but give them separate nginx server blocks, databases and backups.

What fails when something is down:
* **Central down:** users with an account on a site keep signing in (the OIDC flow is site to Keycloak). Provisioning, first-login auto-create, health polling and alerts pause. `ops.healthz` (below) is how you find out.
* **Keycloak down:** no SSO sign-in anywhere; existing sessions continue until they expire. This is why Administrator and the break-glass users stay able to sign in locally on each site.

## 1. Keycloak host

1. Install Docker and nginx. Copy `keycloak/` to `/opt/thinknxg-idp`, create `.env` from `.env.example` (`chmod 600`). Set `KEYCLOAK_VERSION` to the version you validated with `tools/keycloak/smoke_test.py`.
2. `docker compose -f docker-compose.prod.yml up -d`. Postgres has no published port; Keycloak listens on `127.0.0.1:8080` only and its management port 9000 is not published.
3. Get a certificate (`certbot certonly --webroot -w /var/www/certbot -d sso.example.com`). Copy `nginx/keycloak.conf` to `/etc/nginx/conf.d/`, set the host name and certificate paths, and copy `nginx/tnxg-sso-admin-ips.conf` to `/etc/nginx/` with **the Central host's public IP** and your admin networks. `nginx -t && systemctl reload nginx`.
4. Configure the realm following `KEYCLOAK_REALM.md`, then replace the bootstrap admin.
5. Schedule `keycloak/backup_keycloak.sh` (cron, daily or more often).

Proxy settings follow Keycloak's reverse-proxy guide: `KC_PROXY_HEADERS` set to `xforwarded`, and `KC_PROXY_TRUSTED_ADDRESSES` limited to the proxy's addresses, since headers from other sources are ignored. nginx reaches the container through the Docker bridge, so the trusted range is the compose subnet (`172.29.0.0/24`). After the first start, check that `iss` in `https://sso.example.com/realms/<realm>/.well-known/openid-configuration` is the https public URL; if it shows `http://` or an internal address, the trusted range is wrong.

## 2. Central host

```bash
# as the frappe user; bench v16 prerequisites (Python 3.14, Node, MariaDB or Postgres, Redis) already installed
bench init --frappe-branch version-16 frappe-bench && cd frappe-bench
bench new-site admin.example.com            # prompts for passwords; keep them out of shell history
bench get-app <your git URL for thinknxg_super_admin>
bench --site admin.example.com install-app thinknxg_super_admin
bench --site admin.example.com enable-scheduler
sudo bench setup production frappe          # supervisor + nginx for the bench
```
1. Merge `ops/site_config.production.example.json` into `sites/admin.example.com/site_config.json`. Keys used: `host_name` (the site URL including protocol, required for background jobs and print), `developer_mode: 0`, `server_script_enabled: false` (Super Admin needs no Server Scripts), `max_file_size`, `keep_backups_for_hours`. Do **not** set `allow_cors`, `ignore_csrf` or `allowed_referrers`.
2. TLS: `sudo bench setup lets-encrypt admin.example.com` or your own certificate.
3. nginx hardening: `BENCH_NGINX_CONF=$PWD/config/nginx.conf sudo -E nginx/apply_nginx.sh` (path to this kit's `nginx/` directory). It installs rate limits, security headers, dotfile blocking and the Desk allow-list, adds one `include` to the bench-generated config, runs `nginx -t` and reloads. Re-run it after every `bench setup nginx`.
4. Desk allow-list: edit `/etc/nginx/tnxg-admin-ips.conf`: `default 0;` plus one line per admin network (`203.0.113.0/24 1;`). It ships open so the first deployment cannot lock you out; closing it is a go-live item.
5. Host firewall: `ADMIN_SSH_CIDR=... sudo ops/harden_host.sh`.
6. Outgoing email: add an Email Account for outgoing mail and send a test. Alerts depend on it.
7. Application setup (in Desk): Identity Provider (Keycloak URL, realm, service-account client), SSO Configuration, Alert Settings, first Organization, Super Admin users with 2FA. The app READMEs describe each form.
8. Encryption key: run `BENCH_DIR=... SITE=... backup/escrow_key.sh show --i-understand` **in a terminal** and store the key in your password vault, in a different system from the backups. Record `escrow_key.sh fingerprint` in your runbook (it is not secret).
9. Backups: create an age identity on an admin workstation (`age-keygen -o identity.txt`), keep `identity.txt` offline, and put only its public key on the host in `/etc/thinknxg/backup-recipients.txt`. Cron example (every 6 hours; the database is small):
   `0 */6 * * * BENCH_DIR=/home/frappe/frappe-bench SITE=admin.example.com BACKUP_DIR=/var/backups/thinknxg AGE_RECIPIENT_FILE=/etc/thinknxg/backup-recipients.txt KEY_FINGERPRINT_FILE=/etc/thinknxg/key.fingerprint RCLONE_REMOTE=... /opt/thinknxg/backup/backup.sh`
10. Monitoring from outside: poll `https://admin.example.com/api/method/thinknxg_super_admin.api.ops.healthz` every minute. It answers 200 `{"ok": true}` only when the database responds and the alert evaluator finished within 15 minutes, so a dead scheduler (which would silently stop all alerts) is caught. Alert on any non-200.
11. Run `ops/smoke_test.sh` from a machine outside your admin network with `EXPECT_DESK_BLOCKED=1`.

## 3. Managed sites

Install `thinknxg_site_agent`, then pair with the code from Super Admin (see the agent README). Afterwards on each site: set the report-key rotation age, decide on *Disable Local Sign-in*, and run `tools/security/probe.py --agent https://site --central https://admin...`.

## 4. Backups: what is and is not in them

* Shipped (age-encrypted): database dump, public and private files.
* Never shipped: `encryption_key`. The key encrypts stored passwords and must be restored with the site to use existing passwords, so it is escrowed separately and put back before restoring. Without it the central signing key, IdP client secrets and mail passwords are unreadable.
* `bench backup` also writes a copy of the site config; its path is set by `--backup-path-conf` and the documentation does not say what it contains, so `backup.sh` deletes it unconditionally and refuses to continue if the key appears in any remaining text file.
* The script refuses to back up if the site's key no longer matches the escrowed fingerprint, so you never keep a "good" backup of data you cannot decrypt.

### Restore (and the monthly drill)
```bash
bench new-site admin-restore.example.com      # scratch site on a staging bench, same app versions as the backup
BENCH_DIR=... SITE=admin-restore.example.com AGE_IDENTITY_FILE=/secure/identity.txt \
ENCRYPTION_KEY_FILE=/secure/encryption_key EXPECT_KEY_FINGERPRINT=<fingerprint> \
  backup/restore.sh /path/admin.example.com-STAMP.tar.age
```
It verifies the checksum, puts the escrowed key into the site config, runs `bench restore` with public and private files, migrates, and then runs `thinknxg_super_admin.setup.verify.verify_secrets`, failing loudly if any stored secret is unreadable. Frappe does not support restoring onto older code (downgrades), so restore onto the same or a newer version, and keep the previous release tag until the upgrade has proven itself. Do the drill monthly and write down the time it took: that is your real recovery time.

## 5. Upgrades
1. `backup/backup.sh`, then confirm the new archive exists. Note the current git tag of every app.
2. `bench --site admin.example.com set-maintenance-mode on`
3. Check out the new tags, `bench --site admin.example.com migrate`, `bench build`, `sudo supervisorctl restart all`.
4. `bench --site admin.example.com execute thinknxg_super_admin.setup.verify.verify_secrets` must print `"ok": true`.
5. `set-maintenance-mode off`, run `ops/smoke_test.sh` (with `PROBE=1`).
6. Roll back by restoring the pre-upgrade backup onto the previous tag (see the downgrade note above), not by checking out old code over a migrated database.

## Sources
Frappe site config: https://docs.frappe.io/framework/user/en/basics/site_config · bench backup: https://docs.frappe.io/framework/user/en/bench/reference/backup · bench restore: https://docs.frappe.io/framework/user/en/bench/reference/restore · Keycloak reverse proxy: https://www.keycloak.org/server/reverseproxy
