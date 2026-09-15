#!/usr/bin/env bash
# Run inside the development virtualenv: ./scripts/security-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p security-reports
result=0
python -m bandit -r app -ll -f json -o security-reports/bandit.json || result=1
python -m pip_audit -r requirements.lock --no-deps --disable-pip \
  --progress-spinner off -f json -o security-reports/pip-audit.json || result=1
exit "$result"
