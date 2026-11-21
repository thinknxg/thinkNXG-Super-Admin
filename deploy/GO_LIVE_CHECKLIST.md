# Go-live checklist

Tick every line on staging first, then on production. A failed item blocks the go-live.

## Before
- [ ] Staging ran the full path: pair a site, first login auto-create, assignment with a privileged-role second approval, disable a user (Keycloak logout and back-channel logout hit the site), alert opened, emailed, in-app notified, resolved
- [ ] Phase 8 items run on staging: central key rotation (with one site offline), site key rotation, SSO-only mode with a break-glass user, `tools/security/probe.py` clean
- [ ] `bench run-tests` passes for both apps
- [ ] Versions pinned: Frappe tag, app tags, Keycloak, PostgreSQL

## Central host
- [ ] `developer_mode` 0, `server_script_enabled` false, no `allow_cors`, `ignore_csrf`, `allowed_referrers`
- [ ] Super Admin on its own bench; database and Redis not reachable from the network (`ufw status`)
- [ ] 2FA on every Super Admin and Org Admin; Administrator password in the vault
- [ ] nginx kit applied; `tnxg-admin-ips.conf` is `default 0;` plus your networks; `nginx -t` clean
- [ ] Outgoing email works; a forced test alert reached an inbox and the in-app bell
- [ ] External monitor on `ops.healthz`, paging a human; tested by stopping the scheduler
- [ ] `ops/smoke_test.sh` passes from outside the admin network with `EXPECT_DESK_BLOCKED=1 PROBE=1`

## Keys and backups
- [ ] `encryption_key` stored in the vault; its fingerprint recorded in the runbook; `KEY_FINGERPRINT_FILE` set in the backup cron
- [ ] age identity kept offline by two people; only the public recipient is on the host
- [ ] Offsite copy configured and a file seen there
- [ ] **A restore drill succeeded** (`restore.sh` on a scratch site, `verify_secrets` ok), and the elapsed time is written down
- [ ] Keycloak database backup scheduled and restored once

## Keycloak
- [ ] `KEYCLOAK_REALM.md` fully ticked; `/admin`, `/realms/master`, `/metrics`, `/health` not reachable from the internet (smoke test)
- [ ] Discovery `issuer` is the public https URL

## Managed sites
- [ ] Each site paired; health Online; report-key rotation age set
- [ ] SSO-only mode decided per site; break-glass users listed; an Administrator network restriction or 2FA in place

## After
- [ ] Day 1: read the first 24 hours of alerts and the access-denied counts; adjust Alert Settings thresholds
- [ ] Day 7: confirm a backup older than 24 hours exists offsite and restores
- [ ] Calendar: monthly restore drill, quarterly central key rotation, upgrade window
