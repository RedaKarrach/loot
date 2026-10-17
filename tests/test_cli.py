from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from loot.cli import cli, main

from conftest import AKIA, STRIPE, DB_PASSWORD


def test_scan_json(home: Path):
    r = CliRunner().invoke(cli, ["scan", "--home", str(home), "--system", "linux", "--json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.stdout)
    assert data["grade"] == "F" and data["score"] == 0
    assert data["counts"]["critical"] >= 2
    assert data["errors"] == {}
    blob = r.stdout
    for s in (AKIA, STRIPE, DB_PASSWORD):
        assert s not in blob


def test_scan_text(home: Path):
    r = CliRunner().invoke(cli, ["scan", "--home", str(home), "--system", "linux"], env={"COLUMNS": "160"})
    assert r.exit_code == 0, r.output
    assert "Grade F" in r.output
    assert "Fix these first" in r.output
    assert "Long-lived AWS access key" in r.output
    assert "AKIA…MPLE" in r.output and AKIA not in r.output
    assert "positive note" in r.output  # hidden unless --all


def test_default_command_is_scan(home: Path):
    r = CliRunner().invoke(cli, ["--home", str(home)] if False else ["scan", "--home", str(home), "--only", "ssh"], env={"COLUMNS": "160"})
    assert r.exit_code == 0 and "SSH" in r.output
    r2 = CliRunner().invoke(cli, [], env={"COLUMNS": "160"})
    assert r2.exit_code == 0 and "Grade" in r2.output


def test_fail_on(home: Path):
    r = CliRunner().invoke(cli, ["scan", "--home", str(home), "--fail-on", "critical", "--json"])
    assert r.exit_code == 1
    r = CliRunner().invoke(cli, ["scan", "--home", str(home), "--only", "browsers", "--fail-on", "high", "--json"])
    assert r.exit_code == 0


def test_paths():
    r = CliRunner().invoke(cli, ["paths"], env={"COLUMNS": "160"})
    assert r.exit_code == 0 and "~/.aws/credentials" in r.output and "never opened" in r.output


def test_unexpected_error_is_short(monkeypatch, capsys):
    import loot.cli as c

    def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(c, "scan", boom)
    with pytest.raises(SystemExit) as info:
        main(["scan"])
    assert info.value.code == 3
    err = capsys.readouterr().err
    assert "kaboom" in err and "Traceback" not in err
