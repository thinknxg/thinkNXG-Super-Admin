# thinkNXG Super Admin

Central control plane for many independent thinkNXG ERP / Frappe v16 sites: site registry,
central users, role templates, provisioning, audit and dashboards. Authentication is delegated
to a dedicated OIDC provider (Keycloak). Business data never leaves the managed sites.

Install on a **dedicated** central site only. Managed sites install `thinknxg_site_agent`.

    bench get-app thinknxg_super_admin <repo-url>
    bench --site admin.example.com install-app thinknxg_super_admin

Status: Phase 3 (DocTypes). Authentication arrives in Phase 4, provisioning in Phase 6.
See the architecture document for the design. Requires Python 3.14 and Frappe v16.

## Phase 4: SSO login

`api.sites.launch` (central user -> site agent), `api.agent_in.authorize_login` (signed, called by site agents),
`authentication.keycloak` (client and user builders plus Admin API client). A Keycloak dev stack and smoke test live in `tools/keycloak/`.

## Phase 5: site management

1. Create the Managed Site (Draft) and the Keycloak admin client credentials on the Identity Provider; select it in SSO Configuration.
2. `site_admin.create_pairing_code(site)` returns a code once. Run the pairing command on the site (see the agent README).
3. Pairing creates the site's Keycloak client and records the agent public key. Health polls run every 5 minutes; once the site is Online it can be set Active.
4. Redirect-URI edits sync to Keycloak in the background. `site_admin.disconnect(site)` is terminal and disables the client.

The central Ed25519 signing key is created on install/migrate. Note: the Identity Provider form requires an https server URL, so a plain-http dev Keycloak needs an https front (for example Caddy or mkcert) when used with the central site.

## Phase 6: provisioning

Assignments and central-user changes create Provisioning Requests (idempotent by key). The executor runs two steps per request: the
Keycloak account, then the signed call to the site. Failures back off 1m, 5m, 30m, 2h, 12h; `link_required` and `conflict` stop in
Needs Review. The reconciler (every 5 min) requeues due, lost and stuck requests. Suspending or deactivating a central user blocks the
Keycloak account, logs it out everywhere (Keycloak back-channel logout) and disables the user on every site. Reactivation reverses it.
Assignments expire daily; stale Active assignments are re-synced daily; role catalogues refresh daily.
Operator actions: `api.provisioning.retry` and `.cancel`.

## Phase 8: security hardening

See `SECURITY.md` for the trust model, runbooks (key rotation, SSO-only mode, linking local accounts) and the production checklist.

* `security/pinned_http.py`: health polls and agent calls connect to the validated IP; TLS is verified against the host name.
* `security/keyring.py` (identical in the agent), `security/rotation.py`, `api/key_rotation.py`: central key rotation with overlap.
* `api/agent_in.rotate_agent_key`: site key rotation; the previous key is honoured for 24 h to confirm a rotation only.
* `tests/test_security_static.py`, `tests/test_pinned_http.py` (real TLS), `tests/test_keyring.py` run without a bench.
* `tools/security/probe.py`: black-box probes for a deployed pair.

## Phase 9: production deployment

`deploy/` holds the deployment kit: nginx hardening (rate limits, headers, Desk allow-list) and a Keycloak
reverse-proxy config, a production Keycloak + PostgreSQL compose file, encrypted backup and restore with the
Frappe `encryption_key` escrowed separately, a post-restore secret check
(`thinknxg_super_admin.setup.verify.verify_secrets`), a smoke test, a go-live checklist and a production realm
checklist. Start with `deploy/README.md`. `api.ops.healthz` is a liveness endpoint for an external monitor; it
fails when the database is down or the alert evaluator has not completed a run in 15 minutes.
