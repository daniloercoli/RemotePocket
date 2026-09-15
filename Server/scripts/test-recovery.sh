#!/usr/bin/env bash
# Disposable recovery drill. Never uses the production Compose project or volumes.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
backup_file="${1:?Usage: test-recovery.sh /absolute/path/backup.sql.gz}"
[ -f "$backup_file" ] || { echo 'Backup file not found' >&2; exit 1; }
gzip -t "$backup_file"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/mydesk-recovery.XXXXXX")
project="mydesk-recovery-$(basename "$test_dir" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
compose=(docker compose --env-file /dev/null -p "$project" -f "$test_dir/compose.yml")
cleanup() {
    status=$?
    trap - EXIT
    "${compose[@]}" down --volumes --remove-orphans || status=1
    rm -rf "$test_dir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# No published ports, no production secrets, no named/external volumes.
cat > "$test_dir/compose.yml" <<'YAML'
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: mydesk_recovery
      POSTGRES_USER: mydesk_user
      POSTGRES_HOST_AUTH_METHOD: trust
    tmpfs:
      - /var/lib/postgresql/data
    networks: [recovery]
    healthcheck:
      test: [CMD-SHELL, 'pg_isready -U mydesk_user -d mydesk_recovery']
      interval: 1s
      timeout: 3s
      retries: 30
networks:
  recovery:
    internal: true
YAML
"${compose[@]}" up -d --wait --wait-timeout 60 postgres
gunzip -c "$backup_file" | "${compose[@]}" exec -T postgres \
    psql -X -v ON_ERROR_STOP=1 --single-transaction -U mydesk_user -d mydesk_recovery
"${compose[@]}" exec -T postgres psql -X -v ON_ERROR_STOP=1 -U mydesk_user -d mydesk_recovery \
    -c 'SELECT count(*) FROM users; SELECT count(*) FROM devices; SELECT count(*) FROM sessions;'
echo 'Recovery test passed: schema and data restored into an isolated database.'
