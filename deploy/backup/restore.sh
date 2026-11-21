#!/usr/bin/env bash
# Restore an encrypted backup into a bench site, using the escrowed encryption_key.
#
#   BENCH_DIR=... SITE=... AGE_IDENTITY_FILE=/secure/age-identity.txt \
#   ENCRYPTION_KEY_FILE=/secure/encryption_key  deploy/backup/restore.sh /path/site-STAMP.tar.age
#
# The site must already exist (bench new-site) and be the target you intend to overwrite.
# Optional: EXPECT_KEY_FINGERPRINT (abort if the key file does not match), RESTORE_DRY_RUN=1,
# bench asks for the database root password itself; it is never taken from an argument or variable here.
set -euo pipefail
umask 077
ARCHIVE="${1:?usage: restore.sh ARCHIVE.tar.age}"
: "${BENCH_DIR:?}" "${SITE:?}" "${AGE_IDENTITY_FILE:?}" "${ENCRYPTION_KEY_FILE:?}"
BENCH_CMD="${BENCH_CMD:-bench}"
fail() { echo "restore: $*" >&2; exit 1; }

[ -f "$ARCHIVE" ] || fail "no such archive"
if [ -f "$ARCHIVE.sha256" ]; then
	( cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$ARCHIVE").sha256" >/dev/null ) || fail "checksum mismatch"
fi
KEY="$(tr -d '\n' < "$ENCRYPTION_KEY_FILE")"
[ -n "$KEY" ] || fail "empty key file"
if [ -n "${EXPECT_KEY_FINGERPRINT:-}" ]; then
	[ "$(printf '%s' "$KEY" | sha256sum | cut -d' ' -f1)" = "$EXPECT_KEY_FINGERPRINT" ] || fail "key does not match EXPECT_KEY_FINGERPRINT"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
age -d -i "$AGE_IDENTITY_FILE" "$ARCHIVE" | tar -x -C "$WORK"
DB="$(find "$WORK" -name '*database.sql.gz' | head -n1)"
[ -n "$DB" ] || fail "no database dump in archive"
PUB="$(find "$WORK" -name '*-files.tgz' ! -name '*private*' | head -n1 || true)"
PRIV="$(find "$WORK" -name '*private-files.tgz' | head -n1 || true)"

if [ "${RESTORE_DRY_RUN:-0}" = "1" ]; then
	echo "dry run: would restore $DB ${PUB:+public=$PUB }${PRIV:+private=$PRIV }into $SITE"
	exit 0
fi

# Put the original key back BEFORE the data, so the stored passwords can be read.
python3 - "$BENCH_DIR/sites/$SITE/site_config.json" "$KEY" <<'PY'
import json, sys
path, key = sys.argv[1], sys.argv[2]
cfg = json.load(open(path))
cfg["encryption_key"] = key
json.dump(cfg, open(path, "w"), indent=1)
PY

args=(--site "$SITE" restore "$DB")
[ -n "$PUB" ] && args+=(--with-public-files "$PUB")
[ -n "$PRIV" ] && args+=(--with-private-files "$PRIV")
( cd "$BENCH_DIR" && $BENCH_CMD "${args[@]}" && $BENCH_CMD --site "$SITE" migrate )

RESULT="$(cd "$BENCH_DIR" && $BENCH_CMD --site "$SITE" execute thinknxg_super_admin.setup.verify.verify_secrets)"
echo "$RESULT"
echo "$RESULT" | grep -Eq "\"ok\": *true|'ok': *True" || fail "secrets are NOT readable after restore: wrong encryption_key?"
echo "restore: complete and secrets verified"
