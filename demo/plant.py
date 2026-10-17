"""Plant a fake home folder so you can try loot without scanning your own machine.

    python demo/plant.py /tmp/demo-home
    loot scan --home /tmp/demo-home --system linux

Every value below is an official documentation example or an obviously made-up string.
Nothing here works anywhere. The folder it creates is just text files.
"""

from __future__ import annotations

import base64
import json
import struct
import sys
from pathlib import Path

AKIA = "AKIAIOSFODNN7EXAMPLE"  # the key id AWS uses in its own documentation
SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"  # the AWS documentation example
GHP = "ghp_" + "Q7r8S9t0U1v2W3x4Y5z6A7b8C9d0E1f2G3h4"
GHO = "gho_" + "H5i6J7k8L9m0N1o2P3q4R5s6T7u8V9w0X1y2"
NPM = "npm_" + "K2m4N6p8R0t2V4x6Z8b0D2f4H6j8L0n2P4r6"
PYPI = "pypi-AgEIcHlwaS5vcmcCJGY3ZjQ4ZTA5LTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMAACKlszLCJmYWtlIl0"
STRIPE = "sk_" + "live_" + "51Hq0Zl" + "Fake" * 5 + "0001"  # built from parts so it never sits in a file as one string
OPENAI = "sk-" + "proj-" + "Fake" * 9 + "0001"
SLACK = "xoxb-" + "123456789012-1234567890123-" + "Fake" * 6
DBPASS = "Pr0d-Postgres-2024!"


def openssh_key(encrypted: bool) -> str:
    cipher = b"aes256-ctr" if encrypted else b"none"
    kdf = b"bcrypt" if encrypted else b"none"
    payload = b"openssh-key-v1\x00" + struct.pack(">I", len(cipher)) + cipher + struct.pack(">I", len(kdf)) + kdf + b"\x00" * 96
    body = base64.b64encode(payload).decode()
    lines = [body[i:i + 70] for i in range(0, len(body), 70)]
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END OPENSSH PRIVATE KEY-----\n"


def w(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def plant(home: Path) -> None:
    w(home / ".aws" / "credentials", f"[default]\naws_access_key_id = {AKIA}\naws_secret_access_key = {SECRET}\n")
    w(home / ".aws" / "config", "[default]\nregion = eu-west-1\n")
    w(home / ".ssh" / "id_ed25519", openssh_key(encrypted=False))
    w(home / ".ssh" / "id_ed25519.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake jdoe@laptop\n")
    w(home / ".ssh" / "work_rsa", openssh_key(encrypted=True))
    w(home / ".ssh" / "config", "Host bastion\n  HostName bastion.corp.example\n  User jdoe\nHost prod-db\n  HostName 10.20.0.14\n  ProxyJump bastion\nHost git.corp.example\n  IdentityFile ~/.ssh/work_rsa\n")
    w(home / ".git-credentials", f"https://jdoe:{GHP}@github.com\n")
    w(home / ".gitconfig", "[user]\n\tname = J Doe\n[credential]\n\thelper = store\n")
    w(home / ".config" / "gh" / "hosts.yml", f"github.com:\n    oauth_token: {GHO}\n    user: jdoe\n    git_protocol: https\n")
    w(home / ".npmrc", f"//registry.npmjs.org/:_authToken={NPM}\n")
    w(home / ".pypirc", f"[pypi]\nusername = __token__\npassword = {PYPI}\n")
    auth = base64.b64encode(f"jdoe:{DBPASS}".encode()).decode()
    w(home / ".docker" / "config.json", json.dumps({"auths": {"ghcr.io": {"auth": auth}}}, indent=2))
    w(home / ".kube" / "config", "apiVersion: v1\nclusters:\n- name: prod\ncontexts:\n- name: prod\nusers:\n- name: prod-admin\n  user:\n    client-certificate-data: LS0tLS1CRUdJTi...\n    client-key-data: LS0tLS1CRUdJTi...\n")
    w(home / ".bash_history", "\n".join([
        "cd Projects/shop",
        "docker compose up -d",
        f"export AWS_SECRET_ACCESS_KEY={SECRET}",
        f"psql postgres://shop:{DBPASS}@db.internal/shop",
        f"curl -H 'Authorization: Bearer {GHP}' https://api.github.com/user/repos",
        "git push",
        "npm publish",
    ]) + "\n")
    w(home / "Projects" / "shop" / ".env", f"NODE_ENV=production\nDATABASE_URL=postgres://shop:{DBPASS}@db.internal/shop\nSTRIPE_SECRET_KEY={STRIPE}\nOPENAI_API_KEY={OPENAI}\nSLACK_BOT_TOKEN={SLACK}\nSESSION_SECRET=9f8e7d6c5b4a39281706f5e4d3c2b1a0\nPORT=3000\n")
    w(home / "Projects" / "shop" / ".env.example", "STRIPE_SECRET_KEY=sk_live_your_key_here\n")
    w(home / "Projects" / "infra" / "certs" / "vpn-client.key", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ...\n-----END PRIVATE KEY-----\n")
    # browsers and wallets: presence only, never opened by loot
    w(home / ".config" / "google-chrome" / "Default" / "Login Data", "SQLite format 3\x00")
    w(home / ".config" / "google-chrome" / "Default" / "Network" / "Cookies", "SQLite format 3\x00")
    w(home / ".mozilla" / "firefox" / "k3z9.default-release" / "logins.json", "{}")
    (home / ".electrum").mkdir(parents=True, exist_ok=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python demo/plant.py <empty folder>")
        sys.exit(2)
    target = Path(sys.argv[1])
    target.mkdir(parents=True, exist_ok=True)
    if any(target.iterdir()):
        print(f"{target} is not empty; refusing to write into it.")
        sys.exit(2)
    plant(target)
    print(f"planted a fake home in {target}")
    print(f"now run:  loot scan --home {target} --system linux")
