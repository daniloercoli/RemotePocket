#!/usr/bin/env bash
# Sourced by restore tools; authenticate the whole archive before database operations.
prepare_backup() {
    command -v age >/dev/null || { echo 'Install age to decrypt backups' >&2; return 1; }
    [ -n "${MYDESK_BACKUP_AGE_IDENTITY_FILE:-}" ] || { echo 'Set the private age backup identity file' >&2; return 1; }
    [ -f "$backup_file" ] || { echo 'Backup file not found' >&2; return 1; }
    decrypted_dir=$(mktemp -d "${TMPDIR:-/tmp}/mydesk-decrypt.XXXXXX")
    decrypted_backup="$decrypted_dir/backup.sql.gz"
    age --decrypt --identity "$MYDESK_BACKUP_AGE_IDENTITY_FILE" "$backup_file" > "$decrypted_backup" || return 1
    gzip -t "$decrypted_backup"
}
