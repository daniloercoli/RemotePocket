"""Check that audit failures remain fatal and appear in the CI output."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


@pytest.fixture
def audit_checkout(tmp_path):
    server = tmp_path / "Server"
    scripts = server / "scripts"
    scripts.mkdir(parents=True)
    shutil.copyfile(
        Path(__file__).resolve().parents[1] / "scripts" / "security-check.sh",
        scripts / "security-check.sh",
    )
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    python = binary_dir / "python"
    python.write_text(
        f"#!{sys.executable}\n"
        + '''import json, os, sys
from pathlib import Path
if sys.argv[1] != "-m":
    os.execv(sys.executable, [sys.executable, *sys.argv[1:]])
module = sys.argv[2]
with open(os.environ["AUDIT_CALLS"], "a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\\n")
status = int(os.environ.get("BANDIT_EXIT" if module == "bandit" else "AUDIT_EXIT", "0"))
report = Path(sys.argv[sys.argv.index("-o") + 1])
if module == "bandit":
    report.write_text('{"results": []}')
elif not os.environ.get("AUDIT_NO_REPORT"):
    vulnerability = {"id": "TEST-ADVISORY", "fix_versions": ["2.0"]}
    report.write_text(json.dumps({"dependencies": [{
        "name": "example", "version": "1.0", "vulns": [vulnerability] if status else []
    }]}))
sys.exit(status)
'''
    )
    python.chmod(0o700)
    env = {
        **os.environ,
        "PATH": f"{binary_dir}:{os.environ['PATH']}",
        "AUDIT_CALLS": str(tmp_path / "calls.jsonl"),
    }
    return server, env


def run_audit(server, env):
    return subprocess.run(
        ["bash", str(server / "scripts" / "security-check.sh")],
        cwd=server.parent,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.parametrize(
    ("bandit_exit", "audit_exit", "expected"),
    [(0, 0, 0), (1, 0, 1), (0, 1, 1), (1, 1, 1), (0, 2, 1)],
)
def test_security_gate_preserves_tool_failures(
    audit_checkout, bandit_exit, audit_exit, expected
):
    server, env = audit_checkout
    result = run_audit(
        server, {**env, "BANDIT_EXIT": str(bandit_exit), "AUDIT_EXIT": str(audit_exit)}
    )
    assert result.returncode == expected, result.stderr
    calls = [json.loads(line) for line in Path(env["AUDIT_CALLS"]).read_text().splitlines()]
    assert [call[1] for call in calls] == ["bandit", "pip_audit"]
    assert "--require-hashes" in calls[1] and "--strict" in calls[1]
    assert "--no-deps" not in calls[1]
    if audit_exit:
        assert "example==1.0: TEST-ADVISORY (fixed versions: 2.0)" in result.stdout
    assert (server / "security-reports" / "pip-audit.json").is_file()


def test_failed_audit_cannot_reuse_a_previous_report(audit_checkout):
    server, env = audit_checkout
    reports = server / "security-reports"
    reports.mkdir()
    stale = reports / "pip-audit.json"
    stale.write_text('{"dependencies": []}')
    result = run_audit(server, {**env, "AUDIT_EXIT": "2", "AUDIT_NO_REPORT": "1"})
    assert result.returncode == 1
    assert not stale.exists()
    assert "pip-audit did not produce a report" in result.stderr
