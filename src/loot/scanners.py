"""The places an infostealer looks, and what it finds there.

Each scanner takes a Machine and returns Findings. Every scanner only reads, caps how
much it reads, masks before it records anything, and is wrapped so one failure never
stops the rest. Browser databases are never opened, only noticed.
"""

from __future__ import annotations

import base64
import binascii
import configparser
import json
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlsplit

from .findings import Finding, looks_like_placeholder, mask
from .machine import Machine

MAX_FILE_BYTES = 2_000_000
MAX_HISTORY_LINES = 20_000
MAX_ENV_FILES = 400
MAX_DIRS = 6_000
MAX_PER_FILE = 25

SECRET_TOKENS = {"SECRET", "SECRETS", "TOKEN", "TOKENS", "PASSWORD", "PASSWD", "PWD", "PASS", "APIKEY", "CREDENTIAL", "CREDENTIALS", "AUTH"}
# KEY on its own is too common (SORT_KEY, KEY_PATH). It counts next to one of these.
KEY_QUALIFIERS = {"API", "ACCESS", "PRIVATE", "SECRET", "SIGNING", "ENCRYPTION", "APP", "SERVICE", "AWS", "STRIPE", "SENDGRID", "OPENAI"}
NOT_SECRET_TOKENS = {"FILE", "PATH", "DIR", "URL", "HOST", "PORT", "NAME", "ID", "TTL", "TIMEOUT", "ENABLED", "PUBLIC", "SCOPES", "SCOPE", "TYPE", "VERSION", "LENGTH", "EXPIRY", "EXPIRES"}
NOT_SECRET_NAMES = {"PWD", "OLDPWD", "AUTH_TYPE", "AUTHOR"}


def looks_like_secret_name(name: str) -> bool:
    """SECRET_KEY, MYSQL_PWD, GH_TOKEN: yes. OLDPWD, OAUTH_SCOPES, KEY_PATH, AUTHOR: no."""
    n = name.strip().upper()
    if n in NOT_SECRET_NAMES:
        return False
    tokens = [t for t in re.split(r"[^A-Z0-9]+", n) if t]
    if not tokens or tokens[-1] in NOT_SECRET_TOKENS:
        return False
    if any(t in SECRET_TOKENS for t in tokens):
        return True
    if "KEY" in tokens and any(t in KEY_QUALIFIERS for t in tokens):
        return True
    return False

# label, regex, severity. Used on shell history and .env values.
TOKEN_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("AWS temporary key", re.compile(r"\bASIA[0-9A-Z]{16}\b"), "medium"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "high"),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "high"),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"), "critical"),
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "medium"),
    ("JSON web token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium"),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"), "high"),
]

HISTORY_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("secret exported in the shell", re.compile(r"export\s+[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|ACCESS_KEY)[A-Z0-9_]*=\S{6,}"), "medium"),
    ("password on the command line", re.compile(r"(?:--password[= ]|PGPASSWORD=|MYSQL_PWD=|REDISCLI_AUTH=)\S{4,}"), "medium"),
    ("database password on the command line", re.compile(r"\b(?:mysql|mysqldump|mariadb|psql|mongosh?|redis-cli)\b[^|\n]*\s-p\s*\S{4,}"), "medium"),
    ("basic auth in curl", re.compile(r"\bcurl\b[^|\n]*\s-u\s+\S+:\S+"), "medium"),
    ("bearer token on the command line", re.compile(r"Authorization:\s*Bearer\s+\S{10,}"), "high"),
]

ENV_IGNORED_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".schema")
SKIP_DIRS = {
    "node_modules", ".git", "venv", ".venv", "env", ".env.d", "__pycache__", "site-packages", "Library", "AppData",
    ".cache", ".npm", ".cargo", ".rustup", "target", "build", "dist", "vendor", ".terraform", ".idea", ".vscode",
    "Pictures", "Music", "Videos", "Downloads", "Applications", ".local", ".Trash",
}


# ---------------------------------------------------------------------------------
# helpers


def read_text(path: Path, limit: int = MAX_FILE_BYTES) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > limit:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def world_readable(path: Path, m: Machine) -> bool:
    # Only meaningful on a POSIX host; Windows reports 0o666 for everything.
    if m.is_windows or os.name == "nt":
        return False
    try:
        return bool(path.stat().st_mode & 0o044)
    except OSError:
        return False


def key_is_encrypted(text: str) -> bool | None:
    """True if a private key needs a passphrase, False if not, None if unreadable."""
    if "BEGIN OPENSSH PRIVATE KEY" in text:
        body = "".join(line.strip() for line in text.splitlines() if line and "-----" not in line)
        try:
            data = base64.b64decode(body, validate=False)
        except (binascii.Error, ValueError):
            return None
        magic = b"openssh-key-v1\x00"
        if not data.startswith(magic) or len(data) < len(magic) + 4:
            return None
        off = len(magic)
        (n,) = struct.unpack(">I", data[off:off + 4])
        cipher = data[off + 4:off + 4 + n]
        return cipher != b"none"
    if "BEGIN ENCRYPTED PRIVATE KEY" in text or "Proc-Type: 4,ENCRYPTED" in text:
        return True
    if "PRIVATE KEY-----" in text:
        return False
    return None


def _f(m: Machine, path: Path | None, **kw) -> Finding:
    disp = kw.pop("display_path", None)
    if disp is None:
        disp = m.display(path) if path else ""
    return Finding(path=path, display_path=disp, **kw)


# ---------------------------------------------------------------------------------
# scanners


def scan_environment(m: Machine) -> list[Finding]:
    out: list[Finding] = []
    for name, value in sorted(m.env.items()):
        if not looks_like_secret_name(name):
            continue
        if not value or len(value) < 8 or looks_like_placeholder(value):
            continue
        if ("/" in value or "\\" in value) and " " not in value and len(value) < 120:
            continue  # a path, not a secret
        out.append(_f(m, None, display_path="(this shell's environment)", id="env.secret", category="Environment variables",
                      severity="medium", title=f"Secret in an environment variable ({name})",
                      evidence=f"{name}={mask(value)}",
                      unlocks="Whatever that service is. Stealers dump the environment of every process they can see.",
                      fix="Load secrets per project and per session (direnv, a password manager's CLI) instead of a global shell profile."))
    return out


def scan_aws(m: Machine) -> list[Finding]:
    out: list[Finding] = []
    creds = m.h(".aws", "credentials")
    text = read_text(creds)
    if text:
        cp = configparser.ConfigParser(strict=False, interpolation=None, allow_no_value=True)
        try:
            cp.read_string(text)
        except configparser.Error:
            cp = None
        if cp:
            for section in cp.sections():
                key = (cp.get(section, "aws_access_key_id", fallback="") or "").strip()
                if not key:
                    continue
                notes = ["readable by other users on this machine"] if world_readable(creds, m) else []
                if key.startswith("AKIA"):
                    out.append(_f(m, creds, id="aws.long_lived_key", category="Cloud", severity="critical",
                                  title=f"Long-lived AWS access key (profile {section})", evidence=mask(key), notes=notes,
                                  unlocks="Your AWS account as that user, from anywhere, until someone deactivates the key. This is how the crypto-mining bills happen.",
                                  fix="Move to IAM Identity Center (`aws configure sso`) or short-lived role credentials. Until then: rotate it, and alarm on keys older than 90 days."))
                elif key.startswith("ASIA"):
                    out.append(_f(m, creds, id="aws.temporary_key", category="Cloud", severity="medium",
                                  title=f"Temporary AWS credentials (profile {section})", evidence=mask(key), notes=notes,
                                  unlocks="Your AWS account for the next few hours, then nothing.",
                                  fix="These expire on their own. Fine, as long as nothing writes them back as long-lived keys."))
                else:
                    out.append(_f(m, creds, id="aws.other_key", category="Cloud", severity="high",
                                  title=f"AWS credential (profile {section})", evidence=mask(key), notes=notes,
                                  unlocks="Your AWS account, scope unknown.", fix="Check what it is and rotate it."))
    config = read_text(m.h(".aws", "config"))
    if config and "sso_start_url" in config:
        out.append(_f(m, m.h(".aws", "config"), id="aws.sso", category="Cloud", severity="info", title="AWS SSO is configured",
                      unlocks="Nothing on its own: SSO logins expire.", fix="Good. Prefer this over long-lived keys for everything."))
    sso_cache = m.h(".aws", "sso", "cache")
    if sso_cache.is_dir():
        hits = [p for p in sso_cache.glob("*.json") if (read_text(p, 200_000) or "").find('"accessToken"') != -1]
        if hits:
            out.append(_f(m, sso_cache, id="aws.sso_token", category="Cloud", severity="medium",
                          title=f"Cached AWS SSO access token ({len(hits)} file{'s' if len(hits) > 1 else ''})",
                          unlocks="Your AWS accounts for up to 8 hours.", fix="`aws sso logout` when you finish for the day."))
    return out


def scan_ssh(m: Machine) -> list[Finding]:
    out: list[Finding] = []
    d = m.h(".ssh")
    if not d.is_dir():
        return out
    skip = {"config", "known_hosts", "known_hosts.old", "authorized_keys", "environment", "rc"}
    for p in sorted(d.iterdir()):
        if not p.is_file() or p.name in skip or p.name.endswith(".pub"):
            continue
        text = read_text(p, 64_000)
        if not text or "PRIVATE KEY-----" not in text:
            continue
        enc = key_is_encrypted(text)
        notes = ["readable by other users on this machine"] if world_readable(p, m) else []
        if enc is False:
            out.append(_f(m, p, id="ssh.key_no_passphrase", category="SSH", severity="high",
                          title=f"SSH private key without a passphrase ({p.name})", notes=notes,
                          unlocks="Every server, Git host and jump box that trusts this key, as you. Copy the file, done.",
                          fix=f"Add a passphrase: `ssh-keygen -p -f {m.display(p)}`, then load it once per session with ssh-agent. Better: a hardware-backed key (`ssh-keygen -t ed25519-sk`)."))
        elif enc is True:
            out.append(_f(m, p, id="ssh.key_protected", category="SSH", severity="low",
                          title=f"SSH private key, passphrase protected ({p.name})", notes=notes,
                          unlocks="Nothing without the passphrase. A stealer still takes the file to try offline.",
                          fix="Keep it. A hardware-backed key removes even the offline attempt."))
        else:
            out.append(_f(m, p, id="ssh.key_unknown", category="SSH", severity="medium",
                          title=f"SSH private key, could not tell if protected ({p.name})", notes=notes,
                          unlocks="Possibly every host that trusts it.", fix=f"Check with `ssh-keygen -y -f {m.display(p)}`: if it does not ask for a passphrase, add one."))
    cfg = read_text(d / "config")
    if cfg:
        hosts = len([l for l in cfg.splitlines() if l.strip().lower().startswith("host ") and "*" not in l])
        if hosts:
            out.append(_f(m, d / "config", id="ssh.config", category="SSH", severity="info",
                          title=f"SSH config lists {hosts} host{'s' if hosts != 1 else ''}",
                          unlocks="A map of where your keys work. Travels with the keys.", fix="Nothing to fix. Worth knowing."))
    return out


def scan_git(m: Machine) -> list[Finding]:
    out: list[Finding] = []
    gc = m.h(".git-credentials")
    text = read_text(gc)
    if text:
        for i, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if "@" not in line or "://" not in line:
                continue
            try:
                u = urlsplit(line)
            except ValueError:
                continue
            secret = u.password or u.username or ""
            if not secret:
                continue
            sev = "critical" if any(p.search(secret) for _, p, s in TOKEN_PATTERNS if s == "critical") else "high"
            out.append(_f(m, gc, line=i, id="git.credentials_store", category="Git and GitHub", severity=sev,
                          title=f"Git credential stored in plain text ({u.hostname})", evidence=f"{u.username or ''}:{mask(secret)}",
                          unlocks=f"Push and pull as you on {u.hostname}, and whatever else that token's scopes allow.",
                          fix="Switch to Git Credential Manager or the OS keychain (`git config --global credential.helper manager` / `osxkeychain` / `libsecret`), delete this file, revoke the token."))
    gitconfig = read_text(m.h(".gitconfig"))
    if gitconfig and re.search(r"helper\s*=\s*store\b", gitconfig):
        out.append(_f(m, m.h(".gitconfig"), id="git.helper_store", category="Git and GitHub", severity="high",
                      title="Git is configured to save passwords in plain text (credential.helper = store)",
                      unlocks="Every Git login you type from now on lands in ~/.git-credentials.",
                      fix="`git config --global credential.helper manager` (or osxkeychain / libsecret) and remove ~/.git-credentials."))
    for hosts in (m.h(".config", "gh", "hosts.yml"), (m.appdata / "GitHub CLI" / "hosts.yml") if m.appdata else None):
        if hosts is None:
            continue
        t = read_text(hosts)
        if not t:
            continue
        for i, line in enumerate(t.splitlines(), 1):
            mm = re.search(r"oauth_token:\s*(\S+)", line)
            if mm:
                out.append(_f(m, hosts, line=i, id="gh.token", category="Git and GitHub", severity="high",
                              title="GitHub CLI token on disk", evidence=mask(mm.group(1)),
                              unlocks="Your GitHub account from the command line: repos, Actions, and any secret you can read.",
                              fix="`gh auth logout`, then `gh auth login` again so it stores the token in the OS keyring; or pass GH_TOKEN per session from a password manager."))
    for name in (".netrc", "_netrc"):
        p = m.h(name)
        t = read_text(p)
        if not t:
            continue
        machine = None
        for i, line in enumerate(t.splitlines(), 1):
            toks = line.split()
            for j, tok in enumerate(toks):
                if tok == "machine" and j + 1 < len(toks):
                    machine = toks[j + 1]
                if tok == "password" and j + 1 < len(toks):
                    out.append(_f(m, p, line=i, id="netrc.password", category="Git and GitHub", severity="high",
                                  title=f"Password in {name} ({machine or 'unknown host'})", evidence=mask(toks[j + 1]),
                                  unlocks=f"Log in to {machine or 'that host'} as you. Heroku, PyPI mirrors and Git hosts all read this file.",
                                  fix="Delete the line, rotate the password, and use the service's own keychain-backed login."))
    return out


REGISTRY_FILES: list[tuple[tuple[str, ...], re.Pattern[str], str]] = [
    ((".npmrc",), re.compile(r"(?:_authToken|_auth|_password)\s*=\s*(\S+)"), "npm token"),
    ((".pypirc",), re.compile(r"password\s*[:=]\s*(\S+)"), "PyPI credential"),
    ((".gem", "credentials"), re.compile(r":rubygems_api_key:\s*(\S+)"), "RubyGems API key"),
    ((".cargo", "credentials.toml"), re.compile(r'token\s*=\s*"([^"]+)"'), "crates.io token"),
    ((".cargo", "credentials"), re.compile(r'token\s*=\s*"([^"]+)"'), "crates.io token"),
    ((".config", "composer", "auth.json"), re.compile(r'"(?:github-oauth|gitlab-token|bearer)"\s*:\s*\{[^}]*?"\s*:\s*"([^"]{12,})"'), "Composer token"),
    ((".m2", "settings.xml"), re.compile(r"<password>([^<]+)</password>"), "Maven repository password"),
    ((".nuget", "NuGet", "NuGet.Config"), re.compile(r'ClearTextPassword"\s+value="([^"]+)"'), "NuGet password in clear text"),
    ((".config", "hub",), re.compile(r"oauth_token:\s*(\S+)"), "hub (GitHub) token"),
]


def scan_registries(m: Machine) -> list[Finding]:
    out: list[Finding] = []
    for parts, rx, title in REGISTRY_FILES:
        p = m.h(*parts)
        t = read_text(p)
        if not t:
            continue
        for i, line in enumerate(t.splitlines(), 1):
            for mm in rx.finditer(line):
                val = mm.group(1).strip("'\"")
                if looks_like_placeholder(val) or val.startswith("${"):
                    continue
                out.append(_f(m, p, line=i, id="registry.token", category="Package registries", severity="high",
                              title=f"{title} on disk", evidence=mask(val),
                              unlocks="Publish packages under your name. One poisoned release reaches everyone who installs it.",
                              fix="Revoke it. Create a scoped token with an expiry, keep it in the OS keychain or a secrets manager, and prefer trusted publishing (OIDC) from CI."))
                break
    return out


def scan_containers(m: Machine) -> list[Finding]:
    out: list[Finding] = []
    dc = m.h(".docker", "config.json")
    t = read_text(dc)
    if t:
        try:
            data = json.loads(t)
        except ValueError:
            data = {}
        auths = data.get("auths") or {}
        plain = 0
        for registry, entry in auths.items():
            auth = (entry or {}).get("auth")
            if not auth:
                continue
            plain += 1
            try:
                user, _, pw = base64.b64decode(auth).decode("utf-8", "replace").partition(":")
            except (binascii.Error, ValueError):
                user, pw = "?", auth
            out.append(_f(m, dc, id="docker.plain_auth", category="Containers and clusters", severity="high",
                          title=f"Docker registry password stored as base64 ({registry})", evidence=f"{user}:{mask(pw)}",
                          unlocks=f"Pull private images and push poisoned ones to {registry}.",
                          fix=f"`docker logout {registry}`, install a credential helper (osxkeychain, wincred, pass or secretservice) and set \"credsStore\" in this file, then log in again."))
        if data.get("credsStore") and not plain:
            out.append(_f(m, dc, id="docker.credstore", category="Containers and clusters", severity="info",
                          title=f"Docker uses a credential helper ({data['credsStore']})", unlocks="Nothing from this file.", fix="Good."))
    kc = m.h(".kube", "config")
    t = read_text(kc)
    if t:
        keys = len(re.findall(r"^\s*client-key-data:", t, re.M))
        tokens = len(re.findall(r"^\s*token:\s*\S+", t, re.M))
        execs = len(re.findall(r"^\s*exec:", t, re.M))
        if keys:
            out.append(_f(m, kc, id="kube.client_key", category="Containers and clusters", severity="high",
                          title=f"Kubernetes client key embedded in kubeconfig ({keys})",
                          unlocks="Your clusters, with whatever rights those identities have. Often cluster-admin.",
                          fix="Use exec-based, short-lived auth (`aws eks update-kubeconfig`, `gcloud container clusters get-credentials`, `az aks get-credentials`) and rotate the embedded certificates."))
        if tokens:
            out.append(_f(m, kc, id="kube.token", category="Containers and clusters", severity="high",
                          title=f"Kubernetes bearer token in kubeconfig ({tokens})",
                          unlocks="Your clusters as that service account or user.", fix="Replace with exec-based auth; revoke the token."))
        if execs and not keys and not tokens:
            out.append(_f(m, kc, id="kube.exec", category="Containers and clusters", severity="info",
                          title="kubeconfig uses short-lived exec auth", unlocks="Nothing durable.", fix="Good."))
    return out


def scan_cloud(m: Machine) -> list[Finding]:
    out: list[Finding] = []
    gcloud_dirs = [m.h(".config", "gcloud")] + ([m.appdata / "gcloud"] if m.appdata else [])
    for g in gcloud_dirs:
        adc = g / "application_default_credentials.json"
        if (read_text(adc, 200_000) or "").find("refresh_token") != -1:
            out.append(_f(m, adc, id="gcp.adc", category="Cloud", severity="high", title="Google Cloud application default credentials",
                          unlocks="Your Google Cloud projects as you, for as long as the refresh token lives, which is long.",
                          fix="`gcloud auth application-default revoke` when you are not using it; on servers use workload identity instead."))
        for adc2 in (g / "legacy_credentials").glob("*/adc.json") if (g / "legacy_credentials").is_dir() else []:
            out.append(_f(m, adc2, id="gcp.legacy", category="Cloud", severity="high", title=f"Google Cloud credentials ({adc2.parent.name})",
                          unlocks="Your Google Cloud projects as that account.", fix="`gcloud auth revoke` and log in again only when needed."))
        if (g / "access_tokens.db").is_file():
            out.append(_f(m, g / "access_tokens.db", id="gcp.tokens", category="Cloud", severity="medium", title="Google Cloud access token cache",
                          unlocks="Your projects for about an hour.", fix="Expires on its own. `gcloud auth revoke` clears it."))
    az = m.h(".azure")
    if (az / "msal_token_cache.json").is_file():
        out.append(_f(m, az / "msal_token_cache.json", id="azure.cache", category="Cloud", severity="high", title="Azure CLI token cache in plain text",
                      unlocks="Your Azure subscriptions as you until the refresh token expires (up to 90 days).",
                      fix="`az logout` when done, and `az config set core.encrypt_token_cache=true` where supported."))
    if (az / "msal_token_cache.bin").is_file():
        out.append(_f(m, az / "msal_token_cache.bin", id="azure.cache_enc", category="Cloud", severity="low", title="Azure CLI token cache (encrypted with your Windows login)",
                      unlocks="Your Azure subscriptions, but only to malware running as you on this machine.", fix="`az logout` when done."))
    if (az / "accessTokens.json").is_file():
        out.append(_f(m, az / "accessTokens.json", id="azure.legacy", category="Cloud", severity="high", title="Old Azure CLI token file (accessTokens.json)",
                      unlocks="Your Azure subscriptions.", fix="Delete it and `az login` again with a current CLI."))
    for p, rx, title, unlocks, fix in [
        (m.h(".terraform.d", "credentials.tfrc.json"), re.compile(r'"token"\s*:\s*"([^"]+)"'), "Terraform Cloud API token", "Your Terraform workspaces and the state files in them, which usually hold other secrets.", "`terraform logout`, revoke the token, create one with an expiry."),
        (m.h(".terraformrc"), re.compile(r'token\s*=\s*"([^"]+)"'), "Terraform Cloud API token", "Your Terraform workspaces and the state files in them, which usually hold other secrets.", "Remove it from the file, revoke the token, use `terraform login` with an expiring token."),
        (m.h(".vault-token"), re.compile(r"^\s*(\S+)\s*$"), "HashiCorp Vault token", "Everything that token can read in Vault, which is often everything.", "`vault token revoke -self`; log in with a short TTL when you need it."),
        (m.h(".config", "doctl", "config.yaml"), re.compile(r"access-token:\s*(\S+)"), "DigitalOcean API token", "Your droplets, databases and DNS.", "Revoke it in the DigitalOcean console; create one with an expiry."),
        (m.h(".databrickscfg"), re.compile(r"^\s*token\s*=\s*(\S+)", re.M), "Databricks token", "Your workspaces and the data in them.", "Revoke it; use OAuth (`databricks auth login`) instead."),
    ]:
        t = read_text(p)
        if not t:
            continue
        mm = rx.search(t)
        if mm and not looks_like_placeholder(mm.group(1)):
            out.append(_f(m, p, id="cloud.token", category="Cloud", severity="high", title=title, evidence=mask(mm.group(1)), unlocks=unlocks, fix=fix))
    for p in (m.h(".config", "ngrok", "ngrok.yml"), m.h(".ngrok2", "ngrok.yml")):
        t = read_text(p)
        mm = re.search(r"authtoken:\s*(\S+)", t or "")
        if mm:
            out.append(_f(m, p, id="ngrok.token", category="Other tokens", severity="medium", title="ngrok auth token", evidence=mask(mm.group(1)),
                          unlocks="Tunnels into your machine under your account.", fix="Rotate it in the ngrok dashboard."))
    return out


def _history_files(m: Machine) -> list[Path]:
    files = [m.h(".bash_history"), m.h(".zsh_history"), m.h(".history"), m.h(".local", "share", "fish", "fish_history"), m.h(".sh_history")]
    if m.appdata:
        files.append(m.appdata / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt")
    return [p for p in files if p.is_file()]


def scan_history(m: Machine) -> list[Finding]:
    out: list[Finding] = []
    for p in _history_files(m):
        text = read_text(p, 20_000_000)
        if not text:
            continue
        lines = text.splitlines()[-MAX_HISTORY_LINES:]
        seen: set[tuple[str, str]] = set()
        n = 0
        for i, raw in enumerate(lines, 1):
            line = re.sub(r"^: \d+:\d+;", "", raw).strip()  # zsh extended history prefix
            if line.startswith("- cmd: "):
                line = line[7:]  # fish
            hit: tuple[str, str, str] | None = None
            for label, rx, sev in TOKEN_PATTERNS:
                mm = rx.search(line)
                if mm:
                    hit = (label, mm.group(0), "high" if sev == "critical" else sev)
                    break
            if not hit:
                for label, rx, sev in HISTORY_PATTERNS:
                    mm = rx.search(line)
                    if mm:
                        hit = (label, mm.group(0), sev)
                        break
            if not hit:
                continue
            label, value, sev = hit
            key = (label, mask(value))
            if key in seen:
                continue
            seen.add(key)
            n += 1
            if n > MAX_PER_FILE:
                out.append(_f(m, p, id="history.more", category="Shell history", severity="low", title=f"... and more in {p.name}",
                              unlocks="See above.", fix="Clear the file after rotating what is in it."))
                break
            out.append(_f(m, p, line=i, id="history.secret", category="Shell history", severity=sev,
                          title=f"{label[0].upper() + label[1:]} in shell history", evidence=_mask_in(line, value),
                          unlocks="Whatever that credential opens. History files are the first thing stealers grab after the browser.",
                          fix="Rotate it, then remove the line (`history -d N`, or edit the file). Prevent: start secret commands with a space (`HISTCONTROL=ignorespace` / `setopt HIST_IGNORE_SPACE`)."))
    return out


def _mask_in(line: str, value: str) -> str:
    shown = line.replace(value, mask(value))
    return shown if len(shown) <= 64 else shown[:61] + "..."


def _iter_env_files(m: Machine) -> Iterable[Path]:
    count = 0
    dirs = 0
    seen: set[Path] = set()
    for root in m.dev_roots():
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            dirs += 1
            if dirs > MAX_DIRS:
                return
            depth = len(Path(dirpath).parts) - base_depth
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".") or d in {".env.d"}] if depth < 3 else []
            for fn in filenames:
                if fn == ".env" or (fn.startswith(".env.") and not fn.endswith(ENV_IGNORED_SUFFIXES)) or fn.endswith((".pem", ".key", ".p12", ".pfx")):
                    p = Path(dirpath) / fn
                    try:
                        rp = p.resolve()
                    except OSError:
                        rp = p
                    if rp in seen:
                        continue  # ~/ and ~/Projects both reach the same file
                    seen.add(rp)
                    count += 1
                    if count > MAX_ENV_FILES:
                        return
                    yield p


def scan_env_files(m: Machine) -> list[Finding]:
    out: list[Finding] = []
    for p in _iter_env_files(m):
        text = read_text(p, 300_000)
        if text is None:
            continue
        if p.suffix in (".pem", ".key") or p.suffix in (".p12", ".pfx"):
            if "PRIVATE KEY-----" in text or p.suffix in (".p12", ".pfx"):
                out.append(_f(m, p, id="env.private_key_file", category="Project .env files", severity="high",
                              title=f"Private key file in a project folder ({p.name})",
                              unlocks="Whatever that certificate or key authenticates: a server, a signing identity, a VPN.",
                              fix="Move it out of the project tree into the OS keychain or a secrets manager; make sure it was never committed."))
            continue
        n = 0
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            key, _, val = s.partition("=")
            key = key.replace("export ", "").strip()
            val = val.strip().strip("'\"")
            if not val or looks_like_placeholder(val) or val.startswith("${"):
                continue
            sev = None
            label = None
            for lbl, rx, s_ in TOKEN_PATTERNS:
                if rx.search(val):
                    sev, label = s_, lbl
                    break
            if sev is None and looks_like_secret_name(key) and len(val) >= 8:
                sev, label = "high", None
            if sev is None:
                continue
            n += 1
            if n > MAX_PER_FILE:
                break
            out.append(_f(m, p, line=i, id="env.secret_in_file", category="Project .env files", severity=sev,
                          title=f"Secret in {p.name} ({key})" + (f", {label}" if label else ""), evidence=f"{key}={mask(val)}",
                          unlocks="Whatever that project talks to: databases, payment providers, cloud accounts, email.",
                          fix="Keep .env files out of git and out of synced folders; load secrets per session (direnv, 1Password CLI, Doppler) and rotate anything that was ever committed."))
    return out


def _browser_locations(m: Machine) -> list[tuple[str, Path]]:
    locs: list[tuple[str, Path]] = []
    if m.is_windows and m.localappdata:
        locs += [("Chrome", m.localappdata / "Google" / "Chrome" / "User Data"), ("Edge", m.localappdata / "Microsoft" / "Edge" / "User Data"), ("Brave", m.localappdata / "BraveSoftware" / "Brave-Browser" / "User Data")]
        if m.appdata:
            locs.append(("Firefox", m.appdata / "Mozilla" / "Firefox" / "Profiles"))
    elif m.is_mac:
        s = m.h("Library", "Application Support")
        locs += [("Chrome", s / "Google" / "Chrome"), ("Edge", s / "Microsoft Edge"), ("Brave", s / "BraveSoftware" / "Brave-Browser"), ("Firefox", s / "Firefox" / "Profiles")]
    else:
        c = m.h(".config")
        locs += [("Chrome", c / "google-chrome"), ("Chromium", c / "chromium"), ("Edge", c / "microsoft-edge"), ("Brave", c / "BraveSoftware" / "Brave-Browser"), ("Firefox", m.h(".mozilla", "firefox"))]
    return locs


def scan_browsers(m: Machine) -> list[Finding]:
    out: list[Finding] = []
    for name, base in _browser_locations(m):
        if not base.is_dir():
            continue
        logins = list(base.glob("*/Login Data")) + list(base.glob("*/logins.json"))
        cookies = list(base.glob("*/Cookies")) + list(base.glob("*/Network/Cookies")) + list(base.glob("*/cookies.sqlite"))
        if logins:
            out.append(_f(m, logins[0].parent, id="browser.passwords", category="Browser and wallets", severity="low",
                          title=f"Saved browser passwords present ({name}, {len(logins)} profile{'s' if len(logins) != 1 else ''})",
                          unlocks="Every site you saved a password for. This is the number one target of every infostealer.",
                          fix="Use a password manager with its own master password instead of the browser store, and keep the browser updated (Chrome's app-bound encryption on Windows makes the file useless off-device)."))
        if cookies:
            out.append(_f(m, cookies[0].parent, id="browser.cookies", category="Browser and wallets", severity="low",
                          title=f"Browser session cookies present ({name})",
                          unlocks="Every site you are logged into right now, without the password and without MFA. Session hijacking.",
                          fix="Log out of sensitive sites instead of staying signed in for months; prefer short sessions for email, cloud consoles and banking."))
        ext = base / "Default" / "Local Extension Settings" / "nkbihfbeogaeaoehlefnkodbefgpgknn"
        if ext.is_dir():
            out.append(_f(m, ext, id="wallet.metamask", category="Browser and wallets", severity="low", title=f"MetaMask wallet data present ({name})",
                          unlocks="Your wallet, if the password is weak or reused.", fix="A long unique wallet password, and a hardware wallet for anything that matters."))
    wallets = [("Exodus", m.appdata / "Exodus" if m.appdata else None), ("Exodus", m.h(".config", "Exodus")), ("Exodus", m.h("Library", "Application Support", "Exodus")),
               ("Electrum", m.h(".electrum")), ("Electrum", m.appdata / "Electrum" if m.appdata else None)]
    seen: set[str] = set()
    for name, p in wallets:
        if p is not None and p.is_dir() and name not in seen:
            seen.add(name)
            out.append(_f(m, p, id="wallet.data", category="Browser and wallets", severity="low", title=f"Crypto wallet data present ({name})",
                          unlocks="Your funds, if the wallet password can be guessed.", fix="Long unique password; hardware wallet for real money."))
    return out


SCANNERS: list[tuple[str, Callable[[Machine], list[Finding]]]] = [
    ("environment", scan_environment),
    ("aws", scan_aws),
    ("cloud", scan_cloud),
    ("ssh", scan_ssh),
    ("git", scan_git),
    ("registries", scan_registries),
    ("containers", scan_containers),
    ("history", scan_history),
    ("env-files", scan_env_files),
    ("browsers", scan_browsers),
]


@dataclass
class ScanResult:
    machine: Machine
    findings: list[Finding] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    ran: list[str] = field(default_factory=list)


def scan(m: Machine, only: Iterable[str] | None = None) -> ScanResult:
    """Run every scanner. A scanner that blows up is recorded, not fatal."""
    wanted = set(only) if only else None
    result = ScanResult(machine=m)
    for name, fn in SCANNERS:
        if wanted and name not in wanted:
            continue
        result.ran.append(name)
        try:
            result.findings.extend(fn(m))
        except Exception as exc:  # noqa: BLE001 - one bad file must not stop the scan
            result.errors[name] = f"{type(exc).__name__}: {exc}"
    return result


# What `loot paths` prints: where stealers look, in plain words.
TARGETS: list[tuple[str, str, str]] = [
    ("Cloud", "~/.aws/credentials, ~/.aws/sso/cache/", "Long-lived AWS keys; cached SSO tokens"),
    ("Cloud", "~/.config/gcloud/, ~/.azure/", "Google Cloud refresh tokens; Azure CLI token cache"),
    ("Cloud", "~/.terraform.d/, ~/.vault-token, ~/.config/doctl/, ~/.databrickscfg", "API tokens for Terraform Cloud, Vault, DigitalOcean, Databricks"),
    ("SSH", "~/.ssh/", "Private keys (with or without a passphrase), config = map of hosts"),
    ("Git and GitHub", "~/.git-credentials, ~/.gitconfig, ~/.config/gh/hosts.yml, ~/.netrc", "Plain-text Git logins, GitHub CLI tokens, netrc passwords"),
    ("Package registries", "~/.npmrc, ~/.pypirc, ~/.gem/, ~/.cargo/, ~/.m2/, ~/.config/composer/, NuGet.Config", "Publish tokens: the supply-chain attack starter kit"),
    ("Containers and clusters", "~/.docker/config.json, ~/.kube/config", "Registry passwords in base64; embedded cluster keys and tokens"),
    ("Shell history", "~/.bash_history, ~/.zsh_history, fish_history, PowerShell ConsoleHost_history.txt", "Keys and passwords typed on the command line"),
    ("Project .env files", "~/Projects, ~/code, ~/dev, ~/Desktop ... (3 levels deep)", ".env files with live secrets; stray .pem and .key files"),
    ("Environment variables", "this shell", "Secrets exported globally in your profile"),
    ("Browser and wallets", "Chrome, Edge, Brave, Firefox profiles; Exodus, Electrum, MetaMask", "Saved passwords, session cookies, wallet files (noticed, never opened)"),
]
