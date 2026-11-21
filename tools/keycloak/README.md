# Keycloak development stack (DEVELOPMENT ONLY)

Plain http, fixed secrets, `start-dev`. Never use in production.

```bash
cd tools/keycloak
docker compose up -d                # Keycloak 26.0 on http://localhost:8080, realm "thinknxg" imported
```

Admin console: http://localhost:8080 (admin / admin). Realm contents:

| Item | Value |
| --- | --- |
| Test user | `alice@example.test` / `Passw0rd!dev`, attribute `central_uid` = `6f1c2a52-3d0b-4c43-9a6b-2f6a1d0e8c11` |
| Site client | `tnxg-site-demo`, secret `dev-only-secret-change-me`, redirect `http://localhost:8000/api/method/thinknxg_site_agent.api.v1.auth.callback` |
| Admin client | `thinknxg-super-admin` (service account, realm-management roles), secret `dev-only-admin-secret-change-me` |

## 1. Check Keycloak and the validation code, no bench needed

```bash
pip install requests "pyjwt[crypto]"
PYTHONPATH=../../../thinknxg_site_agent python3 smoke_test.py
```

It performs the real authorization-code + PKCE flow, validates the ID token with the agent's own code, proves wrong nonce, audience and issuer are rejected on live tokens, and checks the code is single use. Tokens live in memory only.

## 2. Check the whole login on a bench

On the managed site (`site_config.json`): `"host_name": "http://localhost:8000"` and `"developer_mode": 1` (the latter allows plain http to localhost only).
In **ThinkNXG Agent Settings**: enabled, issuer `http://localhost:8080/realms/thinknxg`, client id `tnxg-site-demo`, the client secret above, `auto_create_on_first_login` off for the first run.

1. Create a User on the site, then set `thinknxg_central_uid` to the sample uuid from the console (`bench console`: `frappe.db.set_value("User", "alice@example.test", {"thinknxg_central_uid": "6f1c2a52-3d0b-4c43-9a6b-2f6a1d0e8c11", "thinknxg_managed": 1})`).
2. Open `http://localhost:8000/api/method/thinknxg_site_agent.api.v1.auth.start?next=/app`, sign in as alice, and expect to land in `/app`.
3. Sign out of Keycloak (account console, "Sign out of all devices") and confirm the Desk session ends via back-channel logout.
4. Negative checks: repeat the callback URL (state is single use), open `start` in one browser and paste the callback into another (rejected by the browser binding).

Auto-create needs a signed call to Super Admin (`agent_in.authorize_login`) and therefore a registered Managed Site with agent keys; test it once Phase 5 gives you a way to register sites.
