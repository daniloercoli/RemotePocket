#!/usr/bin/env bash
# Run inside the development virtualenv: ./scripts/security-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p security-reports
# A failed tool invocation must not leave an older report looking current.
rm -f security-reports/bandit.json security-reports/pip-audit.json
result=0
python -m bandit -r app -ll -f json -o security-reports/bandit.json || result=1
python -m pip_audit -r requirements.lock --require-hashes --disable-pip --strict \
  --progress-spinner off -f json -o security-reports/pip-audit.json || result=1

# Keep the JSON artifact and also show actionable findings in the CI log.
python - <<'PY' || result=1
import json
from pathlib import Path

report = Path("security-reports/pip-audit.json")
if not report.is_file():
    raise SystemExit("pip-audit did not produce a report; see the errors above.")
data = json.loads(report.read_text())
for dependency in data["dependencies"]:
    for vulnerability in dependency.get("vulns", []):
        fixes = ", ".join(vulnerability.get("fix_versions", [])) or "none available"
        print(
            f"{dependency['name']}=={dependency['version']}: "
            f"{vulnerability['id']} (fixed versions: {fixes})"
        )
PY
exit "$result"
