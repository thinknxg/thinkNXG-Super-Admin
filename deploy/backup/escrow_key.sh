#!/usr/bin/env bash
# Handle the Frappe encryption_key without ever writing it to backups or logs.
#
#   escrow_key.sh fingerprint               print sha256 of the key (safe to record in your runbook)
#   escrow_key.sh verify <fingerprint>      exit 0 if the site's key matches
#   escrow_key.sh show --i-understand       print the key once, to copy into your password vault
#
# BENCH_DIR and SITE select the site. Without the key, every stored secret (the central signing key,
# IdP client secrets, mail passwords) is unreadable after a restore.
set -euo pipefail
: "${BENCH_DIR:?}" "${SITE:?}"
CONFIG="${BENCH_DIR}/sites/${SITE}/site_config.json"
KEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("encryption_key",""))' "$CONFIG")"
[ -n "$KEY" ] || { echo "no encryption_key in $CONFIG" >&2; exit 1; }

case "${1:-}" in
	fingerprint) printf '%s' "$KEY" | sha256sum | cut -d' ' -f1 ;;
	verify)
		[ "$(printf '%s' "$KEY" | sha256sum | cut -d' ' -f1)" = "${2:?fingerprint}" ] && echo "match" || { echo "MISMATCH" >&2; exit 1; } ;;
	show)
		[ "${2:-}" = "--i-understand" ] || { echo "refusing: pass --i-understand" >&2; exit 1; }
		[ -t 1 ] || { echo "refusing to print the key to a pipe or file" >&2; exit 1; }
		printf '%s\n' "$KEY" ;;
	*) echo "usage: $0 fingerprint | verify <sha256> | show --i-understand" >&2; exit 2 ;;
esac
