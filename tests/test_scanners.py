from __future__ import annotations

import json
from pathlib import Path

from loot import scanners
from loot.findings import mask, score
from loot.machine import Machine
from loot.scanners import key_is_encrypted, looks_like_secret_name, scan

from conftest import AKIA, ASIA, DB_PASSWORD, GHP, NPM_TOKEN, OPENAI, PYPI_TOKEN, SLACK, STRIPE, openssh_key

ALL_SECRETS = [AKIA, ASIA, GHP, NPM_TOKEN, PYPI_TOKEN, STRIPE, OPENAI, DB_PASSWORD, SLACK, "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY", "hunter2hunter2"]


def by_id(result, fid):
    return [f for f in result.findings if f.id == fid]


def test_everything_planted_is_found(machine: Machine):
    r = scan(machine)
    assert r.errors == {}
    ids = {f.id for f in r.findings}
    expected = {
        "aws.long_lived_key", "aws.temporary_key", "aws.sso", "aws.sso_token", "gcp.adc", "azure.cache", "cloud.token",
        "ssh.key_no_passphrase", "ssh.key_protected", "ssh.config",
        "git.credentials_store", "git.helper_store", "gh.token", "netrc.password",
        "registry.token", "docker.plain_auth", "kube.client_key", "kube.token",
        "history.secret", "env.secret_in_file", "env.private_key_file", "env.secret",
        "browser.passwords", "browser.cookies", "wallet.metamask", "wallet.data",
    }
    missing = expected - ids
    assert not missing, f"not found: {missing}"


def test_no_secret_is_ever_printed(machine: Machine):
    r = scan(machine)
    blob = json.dumps([f.to_dict() for f in r.findings], ensure_ascii=False)
    for s in ALL_SECRETS:
        assert s not in blob, f"secret leaked into output: {s[:6]}..."
    # but masked evidence is there
    assert mask(AKIA) in blob
    assert mask(AKIA) == "AKIA…MPLE"


def test_severities_make_sense(machine: Machine):
    r = scan(machine)
    assert by_id(r, "aws.long_lived_key")[0].severity == "critical"
    assert by_id(r, "aws.temporary_key")[0].severity == "medium"
    assert by_id(r, "ssh.key_no_passphrase")[0].severity == "high"
    assert by_id(r, "ssh.key_protected")[0].severity == "low"
    assert by_id(r, "browser.passwords")[0].severity == "low"
    stripe_env = [f for f in by_id(r, "env.secret_in_file") if "STRIPE" in f.title]
    assert stripe_env and stripe_env[0].severity == "critical"  # token pattern beats the generic name rule
    points, grade = score(r.findings)
    assert grade == "F" and points == 0


def test_ssh_passphrase_detection(machine: Machine):
    r = scan(machine, only=["ssh"])
    titles = {f.title for f in r.findings}
    assert "SSH private key without a passphrase (id_ed25519)" in titles
    assert "SSH private key, passphrase protected (work)" in titles
    assert "SSH private key without a passphrase (legacy.pem)" in titles  # PEM without Proc-Type is unencrypted
    assert "SSH config lists 2 hosts" in titles  # Host * is not a host
    assert key_is_encrypted(openssh_key(True)) is True
    assert key_is_encrypted(openssh_key(False)) is False
    assert key_is_encrypted("-----BEGIN OPENSSH PRIVATE KEY-----\nnot base64 !!!\n-----END OPENSSH PRIVATE KEY-----") is None
    assert key_is_encrypted("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n...") is True


def test_env_files_skip_examples_and_node_modules(machine: Machine):
    r = scan(machine, only=["env-files"])
    paths = {f.display_path for f in r.findings}
    assert "~/Projects/shop/.env" in paths
    assert "~/Projects/infra/certs/server.key" in paths
    assert not any(".env.example" in p for p in paths)
    assert not any("node_modules" in p for p in paths)
    keys = {f.title for f in r.findings if f.id == "env.secret_in_file"}
    assert any("DATABASE_URL" in k for k in keys) is False  # URL suffix is not treated as a secret name...
    assert any("STRIPE_SECRET_KEY" in k for k in keys)
    assert any("OPENAI_API_KEY" in k for k in keys)
    assert any("SLACK_BOT_TOKEN" in k for k in keys)
    assert not any("SECRET_KEY" in k and "STRIPE" not in k for k in keys)  # changeme is a placeholder
    assert not any("KEY_PATH" in k for k in keys)
    wheres = [f.where for f in r.findings]
    assert len(wheres) == len(set(wheres)), "a file reachable from two roots was reported twice"


def test_history_patterns(machine: Machine):
    r = scan(machine, only=["history"])
    titles = sorted(f.title for f in r.findings)
    assert "AWS access key in shell history" in titles
    assert "Secret exported in the shell in shell history" in titles
    assert "Database password on the command line in shell history" in titles
    assert "Basic auth in curl in shell history" in titles
    assert "GitHub token in shell history" in titles  # bearer line matches the token pattern first
    assert "Stripe live key in shell history" in titles  # zsh extended-history prefix stripped
    for f in r.findings:
        assert DB_PASSWORD not in f.evidence and GHP not in f.evidence and STRIPE not in f.evidence


def test_environment_variables_without_false_positives(machine: Machine):
    r = scan(machine, only=["environment"])
    names = sorted(f.title for f in r.findings)
    assert names == ["Secret in an environment variable (GITHUB_TOKEN)"]
    assert looks_like_secret_name("MYSQL_PWD") and looks_like_secret_name("AWS_SECRET_ACCESS_KEY") and looks_like_secret_name("STRIPE_API_KEY")
    for bad in ["OLDPWD", "PWD", "CLAUDE_CODE_OAUTH_SCOPES", "KEY_PATH", "AUTHOR", "SORT_KEY", "AUTH_TYPE", "PUBLIC_KEY", "TOKEN_TTL"]:
        assert not looks_like_secret_name(bad), bad


def test_docker_and_kube(machine: Machine):
    r = scan(machine, only=["containers"])
    d = by_id(r, "docker.plain_auth")[0]
    assert "ghcr.io" in d.title and d.evidence.startswith("demo:") and DB_PASSWORD not in d.evidence
    assert "Kubernetes client key embedded in kubeconfig (1)" in {f.title for f in r.findings}
    assert "Kubernetes bearer token in kubeconfig (1)" in {f.title for f in r.findings}


def test_git_findings(machine: Machine):
    r = scan(machine, only=["git"])
    g = by_id(r, "git.credentials_store")[0]
    assert "github.com" in g.title and g.evidence == f"demo:{mask(GHP)}" and g.line == 1
    assert by_id(r, "gh.token")[0].severity == "high"
    assert "api.heroku.com" in by_id(r, "netrc.password")[0].title


def test_windows_layout(tmp_path: Path):
    home = tmp_path / "win"
    (home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine").mkdir(parents=True)
    (home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt").write_text(f"aws configure set aws_access_key_id {AKIA}\n")
    (home / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default").mkdir(parents=True)
    (home / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Login Data").write_bytes(b"SQLite")
    (home / "AppData" / "Roaming" / "GitHub CLI").mkdir(parents=True)
    (home / "AppData" / "Roaming" / "GitHub CLI" / "hosts.yml").write_text(f"github.com:\n    oauth_token: {GHP}\n")
    m = Machine.fake(home, system="windows")
    r = scan(m)
    ids = {f.id for f in r.findings}
    assert {"history.secret", "browser.passwords", "gh.token"} <= ids
    assert r.errors == {}


def test_empty_home_is_clean(tmp_path: Path):
    m = Machine.fake(tmp_path / "empty", system="linux")
    (tmp_path / "empty").mkdir()
    r = scan(m)
    assert r.findings == [] and r.errors == {}
    assert score(r.findings) == (100, "A")


def test_scanner_failure_is_recorded_not_fatal(machine: Machine, monkeypatch):
    def boom(m):
        raise RuntimeError("disk on fire")
    monkeypatch.setitem(dict(), "x", 1)
    monkeypatch.setattr(scanners, "SCANNERS", [("boom", boom), ("aws", scanners.scan_aws)])
    r = scan(machine)
    assert r.errors == {"boom": "RuntimeError: disk on fire"}
    assert by_id(r, "aws.long_lived_key")


def test_mask():
    assert mask("short") == "••••••"
    assert mask("12345678") == "••••••"
    assert mask("abcdefghijkl") == "ab…kl"
    assert mask("AKIAIOSFODNN7EXAMPLE") == "AKIA…MPLE"
    assert mask("") == "••••••"
