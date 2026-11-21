#!/usr/bin/env bash
# Encrypted backup of the Super Admin site. The Frappe encryption_key is NEVER included.
#
#   BENCH_DIR=/home/frappe/frappe-bench SITE=admin.example.com BACKUP_DIR=/var/backups/thinknxg \
#   AGE_RECIPIENT_FILE=/etc/thinknxg/backup-recipients.txt  deploy/backup/backup.sh
#
# Optional: KEEP_DAYS (14), RCLONE_REMOTE (e.g. s3:bucket/thinknxg), KEY_FINGERPRINT_FILE
# (abort if the site's key no longer matches the one you escrowed), BENCH_CMD (default "bench").
# Recipients are age *public* keys. The matching identity (private key) is kept off this host.
set -euo pipefail
umask 077

: "${BENCH_DIR:?}" "${SITE:?}" "${BACKUP_DIR:?}" "${AGE_RECIPIENT_FILE:?}"
BENCH_CMD="${BENCH_CMD:-bench}"
KEEP_DAYS="${KEEP_DAYS:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${BACKUP_DIR}/${SITE}-${STAMP}.tar.age"
HERE="$(cd "$(dirname "$0")" && pwd)"

fail() { echo "backup: $*" >&2; exit 1; }

[ -s "$AGE_RECIPIENT_FILE" ] || fail "recipient file is empty or missing"
install -d -m 0700 "$BACKUP_DIR"
STAGE="$(mktemp -d "${BACKUP_DIR}/.stage.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

CONFIG="${BENCH_DIR}/sites/${SITE}/site_config.json"
[ -f "$CONFIG" ] || fail "no such site config: $CONFIG"
KEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("encryption_key",""))' "$CONFIG")"
[ -n "$KEY" ] || fail "site has no encryption_key"

if [ -n "${KEY_FINGERPRINT_FILE:-}" ]; then
	[ "$("${HERE}/escrow_key.sh" fingerprint)" = "$(tr -d '[:space:]' < "$KEY_FINGERPRINT_FILE")" ] \
		|| fail "encryption_key does not match the escrowed fingerprint; refusing to back up data that may be unreadable"
fi

( cd "$BENCH_DIR" && $BENCH_CMD --site "$SITE" backup --with-files --compress --backup-path "$STAGE" )

# bench writes a copy of site_config next to the dump; it holds secrets, so it is never shipped.
find "$STAGE" -name '*site_config_backup.json' -delete

[ "$(find "$STAGE" -name '*database.sql.gz' | wc -l)" -eq 1 ] || fail "expected exactly one database dump"
# Belt and braces: the key must not appear in any remaining text file.
if grep -rIlF -- "$KEY" "$STAGE" >/dev/null 2>&1; then
	fail "encryption_key found in backup output; aborting"
fi

tar -C "$STAGE" -cf - . | age -R "$AGE_RECIPIENT_FILE" -o "$OUT"
[ -s "$OUT" ] || fail "encrypted archive is empty"
( cd "$BACKUP_DIR" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )

# Retention.
find "$BACKUP_DIR" -maxdepth 1 -name "${SITE}-*.tar.age*" -mtime "+${KEEP_DAYS}" -delete

if [ -n "${RCLONE_REMOTE:-}" ]; then
	rclone copy --immutable "$OUT" "$RCLONE_REMOTE/" && rclone copy "$OUT.sha256" "$RCLONE_REMOTE/"
fi
echo "backup: wrote $OUT"
