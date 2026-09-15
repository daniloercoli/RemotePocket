#!/usr/bin/env bash
# No online verification: detected credentials never leave this machine.
set -euo pipefail
cd "$(dirname "$0")/../.."
report_dir=$(mktemp -d "${TMPDIR:-/tmp}/mydesk-secrets.XXXXXX")
trap 'rm -rf "$report_dir"' EXIT
scanner=trufflesecurity/trufflehog:3.90.0@sha256:ff537136de0b4dc34c8403c0a5eba2b1bf972edc8d9eb40f91bde0b79cc894b3
docker run --rm --network none -v "$PWD:/src:ro" "$scanner" \
  git file:///src --no-update --no-verification --results=unverified --json > "$report_dir/history.jsonl"
docker run --rm --network none -v "$PWD:/src:ro" "$scanner" \
  filesystem /src --exclude-paths /src/Server/scripts/secret-scan-excludes.txt \
  --no-update --no-verification --results=unverified --json > "$report_dir/files.jsonl"
python3 Server/scripts/check-secret-results.py "$report_dir/history.jsonl" "$report_dir/files.jsonl"
