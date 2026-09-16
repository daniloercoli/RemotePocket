#!/usr/bin/env bash
# Full logical dumps; retain daily and weekly recovery points independently.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
backup_dir="${1:-./backups}"
retention_daily_days="${MYDESK_BACKUP_DAILY_DAYS:-7}"
retention_weekly_days="${MYDESK_BACKUP_WEEKLY_DAYS:-28}"
lock_dir="$backup_dir/.backup-lock"
lock_owned=false
partial_file=""
backup_file=""
notify() {
    if [ -n "${BACKUP_NOTIFICATION_WEBHOOK:-}" ]; then
        curl --fail --silent --show-error --connect-timeout 5 --max-time 15 \
            -X POST "$BACKUP_NOTIFICATION_WEBHOOK" -H 'Content-Type: application/json' \
            -d "{\"service\":\"mydesk-backup\",\"status\":\"$1\"}" || echo 'Backup notification failed' >&2
    fi
}
cleanup() {
    status=$?
    trap - EXIT
    [ -z "$partial_file" ] || rm -f "$partial_file"
    if [ "$lock_owned" = true ]; then rmdir "$lock_dir"; fi
    if [ "$status" -eq 0 ]; then notify success; else notify failure; fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for value in "$retention_daily_days" "$retention_weekly_days"; do
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || { echo 'Retention must be a positive number of days' >&2; exit 1; }
done
command -v age >/dev/null || { echo 'Install age to encrypt backups' >&2; exit 1; }
[ -n "${MYDESK_BACKUP_AGE_RECIPIENT:-}" ] || { echo 'Set the public age backup recipient' >&2; exit 1; }
# Validate the recipient before contacting the database or pruning backups.
age --encrypt --recipient "$MYDESK_BACKUP_AGE_RECIPIENT" /dev/null >/dev/null
mkdir -p "$backup_dir"
# mkdir is an atomic, portable lock; overlapping scheduler runs must not prune each other.
mkdir "$lock_dir" 2>/dev/null || { echo 'Another backup is running (or a stale lock needs inspection)' >&2; exit 1; }
lock_owned=true
kind=daily
# At least one weekly point per seven days, regardless of which day the timer runs.
recent_weekly=$(find "$backup_dir" -type f -name 'mydesk_backup_*_weekly.sql.gz.age' -mtime -7 -print)
[ -n "$recent_weekly" ] || kind=weekly
backup_file="$backup_dir/mydesk_backup_$(date -u +%Y%m%d_%H%M%S)_$$_${kind}.sql.gz.age"
partial_file="$backup_file.partial"
docker compose -f docker-compose.prod.yml exec -T postgres \
    pg_dump --no-owner --no-privileges -U mydesk_user -d mydesk_prod | gzip | age --encrypt --recipient "$MYDESK_BACKUP_AGE_RECIPIENT" > "$partial_file"
mv "$partial_file" "$backup_file"
# An optional recovery drill must pass before retention removes any older points.
if [ "${MYDESK_BACKUP_TEST_RECOVERY:-false}" = true ]; then
    bash scripts/test-recovery.sh "$backup_file"
fi
find "$backup_dir" -type f -name 'mydesk_backup_*_daily.sql.gz.age' -mtime +"$retention_daily_days" -delete
find "$backup_dir" -type f -name 'mydesk_backup_*_weekly.sql.gz.age' -mtime +"$retention_weekly_days" -delete
echo "Backup created: $backup_file"
