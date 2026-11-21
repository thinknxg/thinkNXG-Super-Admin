# Production realm checklist (Keycloak)

Start from the structure in `tools/keycloak/realm-thinknxg.json` but **do not import it**: it is a development
file with `sslRequired: none`, fixed secrets and a localhost back-channel URL. Create the realm and set:

**Realm**
- [ ] SSL required: external requests (or all)
- [ ] Brute-force detection on, with a temporary lockout that fits your support desk
- [ ] Password policy (length, not-username, history) and email verification on
- [ ] User registration off; "forgot password" only if you have outgoing email configured for the realm
- [ ] Required action: configure OTP for all users (MFA is enforced at the IdP; sites do not see it)
- [ ] Events: login and admin events enabled, retention set, shipped to your log store
- [ ] SSO session idle/max and access-token lifespan at or below the values in Super Admin's SSO Configuration (short access tokens; the agents validate and discard them)

**User profile**
- [ ] Attribute `central_uid` (max 36), view/edit by admin only, never by the user. Without it no one can sign in to a site: the agents refuse a token with no UUIDv4 `central_uid`.

**Clients** (Super Admin creates one confidential client per managed site; check the result for the first site)
- [ ] Standard flow on, **direct access grants off**, implicit off, PKCE S256 required
- [ ] Exact redirect URI `https://<site>/api/method/thinknxg_site_agent.api.v1.auth.callback`; no wildcards
- [ ] Back-channel logout URL `https://<site>/api/method/thinknxg_site_agent.api.v1.auth.backchannel_logout`, session required on
- [ ] Protocol mapper puts `central_uid` in the ID token

**Super Admin's service account** (`KeycloakAdmin` in the app uses client credentials in this realm, not the master realm)
- [ ] A confidential client with service account on and no browser flows
- [ ] Only the `realm-management` roles it needs. As written the app finds users, creates and updates them, logs them out, and creates, enables, disables and deletes clients, so start with the user and client manage/view/query roles and tighten after the staging run. Which roles are strictly required has not been verified against a live Keycloak.
- [ ] Its secret is stored only in Super Admin's Identity Provider record (encrypted)

**Operators**
- [ ] Replace the bootstrap admin with named admins who have OTP; remove `KC_BOOTSTRAP_ADMIN_*` from `.env` and recreate the container
- [ ] The master realm is reachable only from the networks in `tnxg-sso-admin-ips.conf`
