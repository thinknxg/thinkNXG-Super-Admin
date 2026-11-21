#!/usr/bin/env python3
"""Black-box security probes for a deployed Super Admin and site agent. Not part of the app.

Run only against systems you own. The unauthenticated probes need nothing; the signed probes need a
*test* central key (never a production one) and are skipped without it.

    python tools/security/probe.py --central https://admin.example.com --agent https://site1.example.com \
        [--central-key-id ID --central-key-file key.pem]   # key trusted by the agent under test

Exit status is 1 if any probe fails.
"""

import argparse
import json
import pathlib
import sys
import time

import requests

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from thinknxg_super_admin.security import signing

REJECTED = {401, 403, 405}
RESULTS: list[tuple[bool, str]] = []
S = requests.Session()
S.max_redirects = 0


def check(ok: bool, name: str, detail: str = ""):
	RESULTS.append((ok, name))
	print(f"{'PASS' if ok else 'FAIL'}  {name}{('  -> ' + detail) if detail and not ok else ''}")


def call(method, url, **kw):
	kw.setdefault("timeout", 15)
	kw.setdefault("allow_redirects", False)
	return S.request(method, url, **kw)


def api(base, dotted):
	return f"{base.rstrip('/')}/api/method/{dotted}"


def unauthenticated(central, agent):
	targets = []
	if central:
		for name in ("authorize_login", "report_linked", "report_login", "rotate_agent_key"):
			targets.append(("POST", api(central, f"thinknxg_super_admin.api.agent_in.{name}")))
	if agent:
		targets += [
			("GET", api(agent, "thinknxg_site_agent.api.v1.health.status")),
			("POST", api(agent, "thinknxg_site_agent.api.v1.provision.apply")),
			("GET", api(agent, "thinknxg_site_agent.api.v1.roles.catalogue")),
			("POST", api(agent, "thinknxg_site_agent.api.v1.keys.stage_central_key")),
		]
	forged = {
		"X-TNXG-Key-Id": "forged-key-0001",
		"X-TNXG-Timestamp": str(int(time.time())),
		"X-TNXG-Request-Id": "r" * 24,
		"X-TNXG-Signature": "A" * 86,
	}
	for method, url in targets:
		short = url.split("/api/method/")[1]
		r = call(method, url, data=b"{}" if method == "POST" else None)
		check(r.status_code in REJECTED, f"no signature rejected: {short}", str(r.status_code))
		r = call(method, url, headers=forged, data=b"{}" if method == "POST" else None)
		check(r.status_code in REJECTED, f"forged signature rejected: {short}", str(r.status_code))
		r = call(method, url, headers={**forged, "X-TNXG-Timestamp": "0"})
		check(r.status_code in REJECTED, f"epoch timestamp rejected: {short}", str(r.status_code))


def oidc(agent):
	r = call(
		"GET", api(agent, "thinknxg_site_agent.api.v1.auth.callback"), params={"code": "x", "state": "y"}
	)
	check(
		"sid=" not in r.headers.get("Set-Cookie", "").lower()
		or "sid=guest" in r.headers.get("Set-Cookie", "").lower(),
		"callback with forged state creates no session",
		r.headers.get("Set-Cookie", "")[:80],
	)
	check(r.status_code != 500, "callback with forged state does not error", str(r.status_code))
	for evil in ("https://evil.example/", "//evil.example", "/\\evil.example", "javascript:alert(1)"):
		r = call("GET", api(agent, "thinknxg_site_agent.api.v1.auth.start"), params={"next": evil})
		loc = r.headers.get("Location", "")
		check(
			"evil.example" not in loc and "javascript:" not in loc,
			f"start ignores hostile next {evil!r}",
			loc[:100],
		)
	r = call("GET", api(agent, "thinknxg_site_agent.api.v1.auth.start"))
	cookie = r.headers.get("Set-Cookie", "")
	if cookie:
		low = cookie.lower()
		check(
			"httponly" in low and "secure" in low and "samesite" in low,
			"flow binding cookie is HttpOnly, Secure, SameSite",
			cookie[:120],
		)
	r = call(
		"POST",
		api(agent, "thinknxg_site_agent.api.v1.auth.backchannel_logout"),
		data={"logout_token": "garbage"},
	)
	check(400 <= r.status_code < 500, "back-channel logout rejects a garbage token", str(r.status_code))
	r = call(
		"POST",
		api(agent, "thinknxg_site_agent.api.v1.auth.backchannel_logout"),
		data={"logout_token": "a.b.c"},
	)
	check(400 <= r.status_code < 500, "back-channel logout rejects a malformed JWT", str(r.status_code))


def pairing_rate_limit(central):
	url = api(central, "thinknxg_super_admin.api.agent_in.pair")
	codes = [
		call(
			"POST", url, json={"site_name": "probe", "code": f"TNXG-{i:030d}", "agent_public_key": "x"}
		).status_code
		for i in range(15)
	]
	check(429 in codes, "pairing endpoint is rate limited", str(codes))
	check(200 not in codes, "pairing never succeeds with guessed codes", str(codes))


def signed(agent, key_id, key_file):
	key = signing.load_private_key(pathlib.Path(key_file).read_text())
	path = "/api/method/thinknxg_site_agent.api.v1.health.status"
	url = agent.rstrip("/") + path

	def get(**kw):
		return call("GET", url, headers=signing.sign_request(key, key_id, "GET", path, b"", **kw))

	check(get().status_code == 200, "valid signed request is accepted")
	headers = signing.sign_request(key, key_id, "GET", path, b"")
	first, second = call("GET", url, headers=headers), call("GET", url, headers=headers)
	check(
		first.status_code == 200 and second.status_code in REJECTED,
		"replayed request id is rejected",
		f"{first.status_code}/{second.status_code}",
	)
	for label, skew in (("stale", -3600), ("future", 3600)):
		check(get(now=int(time.time()) + skew).status_code in REJECTED, f"{label} timestamp is rejected")
	other = "/api/method/thinknxg_site_agent.api.v1.roles.catalogue"
	h = signing.sign_request(key, key_id, "GET", other, b"")
	check(call("GET", url, headers=h).status_code in REJECTED, "signature for another path is rejected")
	body = json.dumps({"a": 1}).encode()
	apply_path = "/api/method/thinknxg_site_agent.api.v1.provision.apply"
	h = signing.sign_request(key, key_id, "POST", apply_path, body)
	r = call(
		"POST",
		agent.rstrip("/") + apply_path,
		headers={**h, "Content-Type": "application/json"},
		data=b'{"a":2}',
	)
	check(r.status_code in REJECTED, "tampered body is rejected", str(r.status_code))
	h = signing.sign_request(key, key_id, "GET", path, b"")
	h["X-TNXG-Key-Id"] = key_id + "x"
	check(call("GET", url, headers=h).status_code in REJECTED, "swapped key id is rejected")


def main():
	ap = argparse.ArgumentParser()
	ap.add_argument("--central")
	ap.add_argument("--agent")
	ap.add_argument("--central-key-id")
	ap.add_argument("--central-key-file")
	ap.add_argument(
		"--skip-rate-limit", action="store_true", help="the pairing probe burns 15 attempts of the limit"
	)
	a = ap.parse_args()
	if not (a.central or a.agent):
		ap.error("give --central and/or --agent")
	unauthenticated(a.central, a.agent)
	if a.agent:
		oidc(a.agent)
	if a.central and not a.skip_rate_limit:
		pairing_rate_limit(a.central)
	if a.agent and a.central_key_id and a.central_key_file:
		signed(a.agent, a.central_key_id, a.central_key_file)
	elif a.agent:
		print("SKIP  signed probes (no --central-key-id/--central-key-file)")
	failed = [n for ok, n in RESULTS if not ok]
	print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} probes passed")
	sys.exit(1 if failed else 0)


if __name__ == "__main__":
	main()
