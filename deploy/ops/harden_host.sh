#!/usr/bin/env bash
# Minimal host firewall for the Super Admin host. Idempotent. Run as root.
#   ADMIN_SSH_CIDR=203.0.113.0/24 deploy/ops/harden_host.sh
# Opens 80/443 to everyone (managed sites and Keycloak browsers need them) and SSH to ADMIN_SSH_CIDR only.
# MariaDB/Postgres (3306/5432) and Redis (6379, 11000, 12000, 13000) stay closed to the network.
set -euo pipefail
: "${ADMIN_SSH_CIDR:?set ADMIN_SSH_CIDR, otherwise you can lock yourself out}"
command -v ufw >/dev/null || { echo "install ufw first" >&2; exit 1; }
ufw default deny incoming
ufw default allow outgoing
ufw allow from "$ADMIN_SSH_CIDR" to any port 22 proto tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
ufw status verbose
