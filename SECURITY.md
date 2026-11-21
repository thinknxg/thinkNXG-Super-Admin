# thinkNXG Super Admin: security model, runbooks and hardening

Status of the code behind this document: the pure logic is unit tested; everything that needs Frappe
(controllers, endpoints, jobs, hooks) and Keycloak has **not** been run. Treat the checklists below as
the acceptance test for a first staging deployment.

## 1. Trust boundaries

| Boundary | Protected by |
|---|---|
| Browser to site | OIDC Authorization Code + PKCE, browser-bound single-use state, nonce, RS256-pinned ID token validation, exact redirect URIs, `safe_next_path` |
| Site to Super Admin, Super Admin to site | Ed25519 request signatures over method, path, body hash, timestamp (120 s) and request id (replay claim), per-key identity |
| Super Admin to site network path | Public-address check on every resolution, connection pinned to the validated IP, TLS verified against the host name, no redirects, response size caps |
| IdP to site (logout) | Back-channel logout token validation (signature, issuer, audience, `events`, no nonce, `jti` replay) |
| Compromised managed site | Holds only its own agent key and its own OIDC client. It cannot read other sites, cannot create central users, cannot approve privileged roles, and can only report logins and links for itself |
| Compromised Super Admin | Out of scope for the sites' own admins: sites never adopt local accounts, never grant System Manager without an approval recorded centrally, and local break-glass accounts remain |

## 2. Controls added in Phase 8

1. **DNS pinning** (`security/pinned_http.py`). Closes the gap between "validate the name" and "connect".
   Tested against real TLS servers: hostname mismatch, redirects, size cap, mixed public/private DNS answers.
2. **Key rotation with overlap**, both directions.
   * Central key (`security/rotation.py`, `api/key_rotation.py`): `begin` stages the new public key on every
     active site (signed with the current key); `complete` switches signing once all sites staged it, or
     once you name the sites to leave behind. Sites accept both keys until the first request signed with
     the new one, then drop the old one.
   * Site key (`thinknxg_site_agent.rotation`): the site generates the new key, sends only the public key
     signed with the old key, and keeps the pending key until the answer arrives. Central keeps the old key
     for 24 hours **for this one endpoint, and only to confirm** a rotation, never to start one.
   * Automatic: sites rotate their key every `report_key_max_age_days` (default 90, 0 disables).
3. **SSO-only mode** (`disable_local_login` in Agent Settings): an `on_login` hook refuses every session not
   created by the SSO flow. Always allowed: Administrator, Guest, listed break-glass users, an
   Administrator impersonating a user. API keys and tokens do not create login sessions and are not covered.
4. **Linking an existing local account** is approved *on the managed site* by its System Manager, never from
   central (`thinknxg_site_agent.provisioning.linking.link_local_account`). Refused: Administrator, Guest,
   disabled users, already-linked users, identities in use, and any account holding System Manager.
5. **Static security tests** in both apps: every whitelisted endpoint restricts HTTP methods, every guest
   endpoint authenticates its request (or is on a reviewed allowlist) and is rate limited, no TLS
   verification off, no `shell=True`, `eval`, `pickle`, f-string SQL or redirect following, no hard-coded
   secrets, no secrets interpolated into logs or errors.
6. **Black-box probes** (`tools/security/probe.py`) for a deployed pair.

## 3. Runbooks

### Rotate the central signing key
1. Super Admin: `thinknxg_super_admin.api.key_rotation.begin` (POST). Read the per-site result.
2. Fix sites reporting anything other than `staged` (unreachable, `unsafe_url`, `tls_error`) and call `begin` again; it only re-stages the missing ones.
3. `thinknxg_super_admin.api.key_rotation.complete`. If a site cannot be reached, either wait or pass `accept_pending=["site"]`; that site will show Offline after cutover and must be paired again.
4. Within one polling cycle (5 min) each site's agent promotes the new key and forgets the old one.
5. `cancel` at any point before `complete` discards the staged key.

### Rotate a site's key now
`bench --site SITE execute thinknxg_site_agent.rotation.rotate_report_key`. Repeat the command if it errors; it resumes with the same pending key.

### Enforce SSO-only on a site
1. Confirm at least one SSO login works for a site administrator.
2. Put break-glass users in *Local Sign-in Exempt Users* (Administrator is always exempt; restrict it by network or 2FA).
3. Tick *Disable Local Sign-in*. Test a password login for a normal user: it must fail with "Local sign-in is disabled".
4. To undo: untick it from the Administrator account, or `bench --site SITE set-config` is not needed because the setting lives in Agent Settings.

### Resolve `link_required`
1. On the managed site, verify the person owns the local account.
2. `thinknxg_site_agent.provisioning.linking.link_local_account(user, central_uid)` as System Manager (Desk console or API).
3. In Super Admin retry the provisioning request.

### Suspected key compromise
* Site key: rotate it (above); if the attacker may hold the old key, disconnect the site in Super Admin first. The 24 h grace only accepts the rotation-confirm call.
* Central key: `begin` and `complete` with no `accept_pending` if every site is reachable; otherwise disconnect unreachable sites, then re-pair them.
* IdP client secret: rotate it in Keycloak and re-run the site's pairing or update Agent Settings.

## 4. Hardening checklist for production (Phase 9 builds on this)

- [ ] Super Admin on its own bench/host, not shared with any managed site; its database not reachable from them.
- [ ] Only HTTPS, HSTS, TLS 1.2+ at the proxy; proxy strips `X-Forwarded-*` from clients and sets them itself.
- [ ] Redis not exposed; separate Redis password; Frappe `encryption_key` backed up offline, **never** with database dumps.
- [ ] 2FA enforced for all Super Admin and Org Admin users; Administrator password in a vault.
- [ ] Rate limits at the proxy as well (the app limits are per-IP/user and per-endpoint only).
- [ ] Keycloak: realm export reviewed; brute-force detection on; client secrets unique per site; back-channel logout URL reachable from Keycloak only.
- [ ] Email (SMTP) configured on central so alerts reach people; test with a forced alert.
- [ ] Probes: `tools/security/probe.py` clean against staging, then after every upgrade.
- [ ] Backup and restore tested for Super Admin, including the encrypted password store.

## 5. Known limits

* Never executed against a live bench or Keycloak. Expect small Frappe API mismatches.
* SSO-only mode relies on the `on_login` hook (verified in Frappe's `auth.py`); sessions created some other way (API keys, `frappe.set_user` in custom code) are not blocked.
* An agent whose `report_key_rotated_at` was never set starts its 90-day clock the first day the job runs.
* Audit log rows are append-only by permission and code, not hash-chained; a database administrator can still alter them.
* Time: signatures tolerate 120 s of skew; large clock drift shows as an alert, not a silent failure.
* Health and agent responses are size-capped but still parsed as JSON in-process.
* No automated penetration test was run; `probe.py` is a regression aid, not an audit.
