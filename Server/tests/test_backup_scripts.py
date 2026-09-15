"""Execute the real shell scripts with Docker replaced by a recording process."""

import gzip
import json
import os
from pathlib import Path
import subprocess
import time

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


@pytest.fixture
def shell_env(tmp_path):
    executable = tmp_path / "bin"
    executable.mkdir()
    docker = executable / "docker"
    docker.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ["DOCKER_RECORD"], "a") as output:
    output.write(json.dumps(args) + "\\n")
if "pg_dump" in args:
    print("CREATE TABLE users(id int); CREATE TABLE devices(id int); CREATE TABLE sessions(id int);")
    sys.exit(int(os.environ.get("FAIL_DUMP", "0")))
if "psql" in args:
    if "-c" in args:
        if "pg_class" in args[-1]:
            print(os.environ.get("DESTINATION_RELATIONS", "0"))
    else:
        sys.stdin.read()
        sys.exit(int(os.environ.get("FAIL_SQL", "0")))
if "-f" in args:
    config = Path(args[args.index("-f") + 1])
    if config.is_absolute() and config.exists():
        Path(os.environ["RECOVERY_CONFIG"]).write_text(config.read_text())
""")
    docker.chmod(0o700)
    # The scripts cannot reach the real Docker executable during a regression test.
    env = {
        **os.environ,
        "PATH": f"{executable}:{os.environ['PATH']}",
        "DOCKER_RECORD": str(tmp_path / "docker.jsonl"),
        "RECOVERY_CONFIG": str(tmp_path / "recovery.yml"),
    }
    env.pop("BACKUP_NOTIFICATION_WEBHOOK", None)
    env.pop("MYDESK_BACKUP_TEST_RECOVERY", None)
    return env


def run_script(name, argument, env):
    return subprocess.run(
        ["bash", str(SCRIPTS / name), str(argument)],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )


def calls(env):
    path = Path(env["DOCKER_RECORD"])
    return (
        [json.loads(line) for line in path.read_text().splitlines()]
        if path.exists()
        else []
    )


def dump(path):
    path.write_bytes(gzip.compress(b"SELECT 1;\n"))
    return path


def test_backup_retains_weekly_points_independently(tmp_path, shell_env):
    directory = tmp_path / "backups"
    directory.mkdir()
    for kind, days in (("daily", 10), ("weekly", 10), ("weekly", 40), ("weekly", 2)):
        path = dump(directory / f"mydesk_backup_old{days}_{kind}.sql.gz")
        stamp = time.time() - days * 86400
        os.utime(path, (stamp, stamp))
    result = run_script("backup.sh", directory, shell_env)
    assert result.returncode == 0, result.stderr
    assert not (directory / "mydesk_backup_old10_daily.sql.gz").exists()
    assert (directory / "mydesk_backup_old10_weekly.sql.gz").exists()
    assert not (directory / "mydesk_backup_old40_weekly.sql.gz").exists()
    assert len(list(directory.glob("*_daily.sql.gz"))) == 1
    assert not (directory / ".backup-lock").exists()


def test_failed_dump_keeps_old_backups_and_does_not_publish_partial_file(
    tmp_path, shell_env
):
    directory = tmp_path / "backups"
    directory.mkdir()
    old = dump(directory / "mydesk_backup_old_daily.sql.gz")
    stamp = time.time() - 40 * 86400
    os.utime(old, (stamp, stamp))
    result = run_script("backup.sh", directory, {**shell_env, "FAIL_DUMP": "7"})
    assert result.returncode != 0
    assert list(directory.iterdir()) == [old]


def test_recovery_is_isolated_and_propagates_sql_failure(tmp_path, shell_env):
    backup = dump(tmp_path / "dump.sql.gz")
    result = run_script("test-recovery.sh", backup, {**shell_env, "FAIL_SQL": "2"})
    assert result.returncode != 0
    assert "Recovery test passed" not in result.stdout
    commands = calls(shell_env)
    assert commands
    projects = {args[args.index("-p") + 1] for args in commands}
    assert len(projects) == 1 and next(iter(projects)).startswith("mydesk-recovery-")
    assert all("docker-compose.prod.yml" not in args for args in commands)
    assert any("down" in args for args in commands)
    restore = next(args for args in commands if "psql" in args)
    assert "ON_ERROR_STOP=1" in restore and "--single-transaction" in restore
    config = Path(shell_env["RECOVERY_CONFIG"]).read_text()
    assert "ports:" not in config and "external:" not in config


def test_restore_refuses_nonempty_database_without_restarting_app(tmp_path, shell_env):
    result = run_script(
        "restore.sh",
        dump(tmp_path / "dump.sql.gz"),
        {**shell_env, "DESTINATION_RELATIONS": "3"},
    )
    assert result.returncode != 0
    commands = calls(shell_env)
    assert not any("up" in args for args in commands)
    assert not any("psql" in args and "-c" not in args for args in commands)


def test_restore_sql_failure_does_not_restart_app(tmp_path, shell_env):
    result = run_script(
        "restore.sh", dump(tmp_path / "dump.sql.gz"), {**shell_env, "FAIL_SQL": "2"}
    )
    assert result.returncode != 0
    commands = calls(shell_env)
    assert not any("up" in args for args in commands)
    restore = next(args for args in commands if "psql" in args and "-c" not in args)
    assert (
        "-X" in restore
        and "ON_ERROR_STOP=1" in restore
        and "--single-transaction" in restore
    )


def test_corrupt_backup_does_not_stop_or_create_containers(tmp_path, shell_env):
    invalid = tmp_path / "invalid.sql.gz"
    invalid.write_text("not gzip")
    for script in ("restore.sh", "test-recovery.sh"):
        assert run_script(script, invalid, shell_env).returncode != 0
    assert calls(shell_env) == []
