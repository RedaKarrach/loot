"""A fake home folder planted with everything a stealer hopes to find.

Every value is a documented example or an obviously fake string. Nothing here is real.
"""

from __future__ import annotations

import base64
import json
import struct
from pathlib import Path

import pytest

from loot.machine import Machine

AKIA = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"  # the AWS documentation example, split so no file holds it whole
ASIA = "ASIAIOSFODNN7EXAMPLE"
GHP = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
NPM_TOKEN = "npm_" + "a1b2c3d4e5f6" * 3
PYPI_TOKEN = "pypi-" + "AgEIcHlwaS5vcmc" * 4
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
OPENAI = "sk-" + "proj-" + "A" * 40
DB_PASSWORD = "Tr0ub4dor&3-not-real"
SLACK = "xoxb-" + "123456789012-" + "ABCDEFGHIJKLMNOPQRSTUVWX"


def openssh_key(encrypted: bool) -> str:
    """A syntactically valid OpenSSH private key header with the given cipher. Not a real key."""
    cipher = b"aes256-ctr" if encrypted else b"none"
    kdf = b"bcrypt" if encrypted else b"none"
    payload = b"openssh-key-v1\x00" + struct.pack(">I", len(cipher)) + cipher + struct.pack(">I", len(kdf)) + kdf + b"\x00" * 64
    body = base64.b64encode(payload).decode()
    lines = [body[i:i + 70] for i in range(0, len(body), 70)]
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END OPENSSH PRIVATE KEY-----\n"


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def plant(home: Path) -> None:
    # cloud
    write(home / ".aws" / "credentials", f"[default]\naws_access_key_id = {AKIA}\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\n[temp]\naws_access_key_id = {ASIA}\naws_secret_access_key = x\naws_session_token = y\n")
    write(home / ".aws" / "config", "[profile sso]\nsso_start_url = https://example.awsapps.com/start\n")
    write(home / ".aws" / "sso" / "cache" / "abc.json", json.dumps({"accessToken": "eyJ" + "x" * 40, "expiresAt": "2026-10-17T20:00:00Z"}))
    write(home / ".config" / "gcloud" / "application_default_credentials.json", json.dumps({"client_id": "x", "refresh_token": "1//0g" + "x" * 50, "type": "authorized_user"}))
    write(home / ".azure" / "msal_token_cache.json", "{}")
    write(home / ".terraform.d" / "credentials.tfrc.json", json.dumps({"credentials": {"app.terraform.io": {"token": "atlasv1." + "x" * 60}}}))
    write(home / ".vault-token", "hvs." + "y" * 24 + "\n")
    # ssh
    write(home / ".ssh" / "id_ed25519", openssh_key(encrypted=False))
    write(home / ".ssh" / "id_ed25519.pub", "ssh-ed25519 AAAA... demo")
    write(home / ".ssh" / "work", openssh_key(encrypted=True))
    write(home / ".ssh" / "legacy.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n")
    write(home / ".ssh" / "config", "Host bastion\n  HostName 10.0.0.1\nHost prod-db\n  HostName 10.0.0.2\nHost *\n  AddKeysToAgent yes\n")
    # git
    write(home / ".git-credentials", f"https://demo:{GHP}@github.com\n")
    write(home / ".gitconfig", "[credential]\n\thelper = store\n")
    write(home / ".config" / "gh" / "hosts.yml", f"github.com:\n    oauth_token: gho_{'z' * 36}\n    user: demo\n")
    write(home / ".netrc", f"machine api.heroku.com\n  login demo@example.com\n  password {'h' * 32}\n")
    # registries
    write(home / ".npmrc", f"//registry.npmjs.org/:_authToken={NPM_TOKEN}\n")
    write(home / ".pypirc", f"[pypi]\nusername = __token__\npassword = {PYPI_TOKEN}\n")
    write(home / ".cargo" / "credentials.toml", '[registry]\ntoken = "cio' + "q" * 30 + '"\n')
    # containers
    auth = base64.b64encode(b"demo:" + DB_PASSWORD.encode()).decode()
    write(home / ".docker" / "config.json", json.dumps({"auths": {"ghcr.io": {"auth": auth}}}))
    write(home / ".kube" / "config", "apiVersion: v1\nusers:\n- name: admin\n  user:\n    client-certificate-data: LS0t\n    client-key-data: LS0tQk\n- name: sa\n  user:\n    token: eyJhbGciOiJSUzI1NiJ9.e30.sig\n")
    # history
    write(home / ".bash_history", "\n".join([
        "ls -la",
        f"export AWS_SECRET_ACCESS_KEY={AWS_SECRET}",
        f"aws configure set aws_access_key_id {AKIA}",
        f"mysql -u root -p{DB_PASSWORD} shop",
        "curl -u admin:hunter2hunter2 https://jenkins.example/api",
        f"curl -H 'Authorization: Bearer {GHP}' https://api.github.com/user",
        "git status",
    ]) + "\n")
    write(home / ".zsh_history", f": 1700000000:0;export STRIPE_SECRET_KEY={STRIPE}\n: 1700000001:0;echo hi\n")
    # projects
    write(home / "Projects" / "shop" / ".env", f"DEBUG=true\nDATABASE_URL=postgres://shop:{DB_PASSWORD}@localhost/shop\nSTRIPE_SECRET_KEY={STRIPE}\nOPENAI_API_KEY={OPENAI}\nSLACK_BOT_TOKEN={SLACK}\nSECRET_KEY=changeme\nAPP_NAME=shop\nKEY_PATH=/etc/keys\n")
    write(home / "Projects" / "shop" / ".env.example", "STRIPE_SECRET_KEY=sk_live_your_key_here\n")
    write(home / "Projects" / "shop" / "node_modules" / "pkg" / ".env", f"SECRET_KEY={STRIPE}\n")  # must be skipped
    write(home / "Projects" / "infra" / "certs" / "server.key", "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n")
    # browsers (linux layout) and wallets: presence only
    write(home / ".config" / "google-chrome" / "Default" / "Login Data", "SQLite format 3\x00")
    write(home / ".config" / "google-chrome" / "Default" / "Network" / "Cookies", "SQLite format 3\x00")
    (home / ".config" / "google-chrome" / "Default" / "Local Extension Settings" / "nkbihfbeogaeaoehlefnkodbefgpgknn").mkdir(parents=True)
    write(home / ".mozilla" / "firefox" / "abc.default" / "logins.json", "{}")
    (home / ".electrum").mkdir()


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    plant(h)
    return h


@pytest.fixture
def machine(home: Path) -> Machine:
    return Machine.fake(home, system="linux", env={
        "GITHUB_TOKEN": GHP,
        "OLDPWD": "/home/demo/somewhere",
        "PWD": "/home/demo",
        "CLAUDE_CODE_OAUTH_SCOPES": "user:inference user:profile",
        "KEY_PATH": "/etc/keys",
        "AUTHOR": "demo person",
        "DATABASE_PASSWORD": "changeme",
        "PATH": "/usr/bin:/bin",
    })
