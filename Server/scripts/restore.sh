#!/usr/bin/env bash
# Restore a plain SQL dump into an EMPTY production database. Never drops user data.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
backup_file="${1:?Usage: restore.sh /absolute/path/backup.sql.gz (empty destination required)}"
[ -f "$backup_file" ] || { echo 'Backup file not found' >&2; exit 1; }
gzip -t "$backup_file"
compose=(docker compose -f docker-compose.prod.yml)
# Leave the app stopped on failure: it must not serve a failed or partial restore.
"${compose[@]}" stop app
relation_count=$("${compose[@]}" exec -T postgres psql -X -v ON_ERROR_STOP=1 -At \
    -U mydesk_user -d mydesk_prod -c "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','v','m','S','f');")
if [ "$relation_count" != 0 ]; then
    echo 'Restore refused: destination must be empty. App remains stopped.' >&2
    exit 1
fi
gunzip -c "$backup_file" | "${compose[@]}" exec -T postgres \
    psql -X -v ON_ERROR_STOP=1 --single-transaction -U mydesk_user -d mydesk_prod
"${compose[@]}" exec -T postgres psql -X -v ON_ERROR_STOP=1 -U mydesk_user -d mydesk_prod \
    -c 'SELECT count(*) FROM users; SELECT count(*) FROM devices; SELECT count(*) FROM sessions;'
"${compose[@]}" up -d --wait --wait-timeout 120 app
echo 'Restore completed and application healthy.'
