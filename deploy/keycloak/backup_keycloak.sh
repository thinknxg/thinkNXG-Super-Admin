#!/usr/bin/env bash
# Encrypted dump of the Keycloak database (users, clients, realm settings, sessions excluded by design).
#   COMPOSE_DIR=/opt/thinknxg-idp BACKUP_DIR=/var/backups/thinknxg-idp AGE_RECIPIENT_FILE=... backup_keycloak.sh
set -euo pipefail
umask 077
: "${COMPOSE_DIR:?}" "${BACKUP_DIR:?}" "${AGE_RECIPIENT_FILE:?}"
KEEP_DAYS="${KEEP_DAYS:-14}"
[ -s "$AGE_RECIPIENT_FILE" ] || { echo "recipient file empty" >&2; exit 1; }
install -d -m 0700 "$BACKUP_DIR"
OUT="${BACKUP_DIR}/keycloak-$(date -u +%Y%m%dT%H%M%SZ).sql.age"
cd "$COMPOSE_DIR"
# The variables are expanded inside the container, so the password never appears on a command line.
docker compose -f docker-compose.prod.yml exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner' \
	| age -R "$AGE_RECIPIENT_FILE" -o "$OUT"
[ -s "$OUT" ] || { echo "empty backup" >&2; rm -f "$OUT"; exit 1; }
( cd "$BACKUP_DIR" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )
find "$BACKUP_DIR" -maxdepth 1 -name 'keycloak-*.sql.age*' -mtime "+${KEEP_DAYS}" -delete
echo "keycloak backup: $OUT"
