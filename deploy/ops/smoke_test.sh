#!/usr/bin/env bash
# Post-deploy smoke test of the public surface. Read-only. Exit status 1 if any check fails.
#
#   CENTRAL_URL=https://admin.example.com SSO_URL=https://sso.example.com SSO_REALM=thinknxg \
#   EXPECT_DESK_BLOCKED=1 deploy/ops/smoke_test.sh
#
# Run it from OUTSIDE the admin network (a laptop on mobile data) to prove the allow-list works.
# CURL_OPTS lets a test pass extra curl flags (for example --resolve and -k against a staging box).
# SKIP_HTTP_REDIRECT=1 skips the port-80 check. PROBE=1 also runs tools/security/probe.py.
set -uo pipefail
: "${CENTRAL_URL:?}"
CENTRAL_URL="${CENTRAL_URL%/}"
read -r -a CURL <<< "curl -sS -m 15 ${CURL_OPTS:-}"
FAILED=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1${2:+  -> $2}"; FAILED=$((FAILED + 1)); }
status() { local c; c="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$@" 2>/dev/null)" || true; echo "${c:-000}"; }
expect_status() { local want="$1" name="$2"; shift 2; local got; got="$(status "$@")"; [[ " $want " == *" $got "* ]] && pass "$name" || fail "$name" "got $got, want $want"; }

HOST="${CENTRAL_URL#https://}"
if [ "${SKIP_HTTP_REDIRECT:-0}" != "1" ]; then
	expect_status "301 308" "http redirects to https" "http://${HOST}/"
fi
expect_status "200" "ping" "${CENTRAL_URL}/api/method/ping"
HEADERS="$("${CURL[@]}" -D - -o /dev/null "${CENTRAL_URL}/api/method/ping" 2>/dev/null)"
grep -qi '^strict-transport-security:' <<< "$HEADERS" && pass "HSTS present" || fail "HSTS present"
grep -qi '^x-content-type-options: *nosniff' <<< "$HEADERS" && pass "nosniff present" || fail "nosniff present"
grep -Eiq '^server: *nginx/[0-9]' <<< "$HEADERS" && fail "nginx version hidden" "Server header shows a version" || pass "nginx version hidden"
BODY="$("${CURL[@]}" "${CENTRAL_URL}/api/method/thinknxg_super_admin.api.ops.healthz" 2>/dev/null)"
grep -Eq '"ok": *true' <<< "$BODY" && pass "healthz ok (database + alert scheduler)" || fail "healthz ok" "$BODY"
if [ "${EXPECT_DESK_BLOCKED:-0}" = "1" ]; then
	expect_status "403" "Desk blocked from this network" "${CENTRAL_URL}/app"
	expect_status "403" "login blocked from this network" "${CENTRAL_URL}/login"
else
	echo "SKIP  Desk allow-list (set EXPECT_DESK_BLOCKED=1 when running from outside the admin network)"
fi
expect_status "401 403 405" "agent endpoint rejects unsigned calls" -X POST "${CENTRAL_URL}/api/method/thinknxg_super_admin.api.agent_in.report_login"
expect_status "403 404" "dotfiles are not served" "${CENTRAL_URL}/.env"

if [ -n "${SSO_URL:-}" ]; then
	SSO_URL="${SSO_URL%/}"
	DISC="$("${CURL[@]}" "${SSO_URL}/realms/${SSO_REALM:?}/.well-known/openid-configuration" 2>/dev/null)"
	grep -q "\"issuer\": *\"${SSO_URL}/realms/${SSO_REALM}\"" <<< "$DISC" && pass "OIDC discovery issuer is the public https URL" || fail "OIDC discovery issuer" "${DISC:0:120}"
	for path in / /metrics /health /health/ready /admin/ /realms/master/; do
		expect_status "403 404" "Keycloak ${path} not public" "${SSO_URL}${path}"
	done
fi

if [ "${PROBE:-0}" = "1" ]; then
	HERE="$(cd "$(dirname "$0")" && pwd)"
	python3 "${HERE}/../../tools/security/probe.py" --central "$CENTRAL_URL" --skip-rate-limit && pass "probe.py" || fail "probe.py"
fi

echo; [ "$FAILED" -eq 0 ] && echo "smoke test passed" || echo "$FAILED check(s) failed"
exit $(( FAILED > 0 ))
