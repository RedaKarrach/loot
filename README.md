# loot

What would an infostealer take from your laptop?

![loot in a terminal: F before, A after an evening of fixes](docs/assets/demo.gif)

Try it, step by step, with real output: **https://redakarrach.github.io/loot/**

Infostealers are the malware behind many of the big breaches of the last few years.
The Snowflake customer breaches in 2024 started with credentials that stealers had
copied from employees' machines. These programs do nothing clever. They copy files from
a known list of places: cloud credentials, SSH keys, Git logins, package registry
tokens, `.env` files, shell history, browser passwords. Then they leave.

Most developers have never looked at their own machine from that angle. loot does. It
checks the same places a stealer checks, tells you what each find would unlock, grades
the result, and gives you a one-line fix for every item. Run it, fix things, run it
again, watch the grade go up.

It only reads. Nothing leaves your machine. Secrets are never printed in full.

## Install

Python 3.11 or newer.

With [uv](https://docs.astral.sh/uv/):

```bash
uv tool install git+https://github.com/RedaKarrach/loot
```

Or run it once without installing anything:

```bash
uvx --from git+https://github.com/RedaKarrach/loot loot
```

With pipx:

```bash
pipx install git+https://github.com/RedaKarrach/loot
```

## Run

```bash
loot
```

That is the whole thing. It prints a grade, a "fix these first" list, and every
finding grouped by what it unlocks. Run it again after you fix something.

Nervous about pointing it at your own machine first? Plant a fake home folder and scan
that:

```bash
python demo/plant.py /tmp/demo-home
```

```bash
loot scan --home /tmp/demo-home --system linux
```

## What it looks like

A shortened run on the planted demo folder. Every value is fake.

```text
┌───────────────────────────────── loot ─────────────────────────────────┐
│ Grade F  (0/100)                                                       │
│ If an infostealer ran on this machine right now, it would leave with:  │
│     2 critical                                                         │
│    16 high                                                             │
│     1 medium                                                           │
│     5 low                                                              │
│ Scanned: environment, aws, cloud, ssh, git, registries, containers,    │
│ history, env-files, browsers. Nothing left this machine. Values are    │
│ masked.                                                                │
└────────────────────────────────────────────────────────────────────────┘
                              Fix these first

  #   Sev        What                                  Where                    Fix
 ─────────────────────────────────────────────────────────────────────────────────────────────
  1   critical   Long-lived AWS access key (default)   ~/.aws/credentials       Move to IAM Identity Center
                                                                                (`aws configure sso`) ...
  2   critical   Secret in .env (STRIPE_SECRET_KEY)    ~/Projects/shop/.env:3   Keep .env files out of git ...
  3   high       SSH private key without a passphrase  ~/.ssh/id_ed25519        Add a passphrase: `ssh-keygen -p -f ...`
  4   high       Git credential stored in plain text   ~/.git-credentials:1     Switch to Git Credential Manager ...
  5   high       GitHub CLI token on disk              ~/.config/gh/hosts.yml   `gh auth logout`, then `gh auth login` ...
  ...

Cloud
  Sev        Finding                                      Where                 Evidence     What it unlocks
 ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
  critical   Long-lived AWS access key (profile default)  ~/.aws/credentials    AKIA…MPLE    Your AWS account as that user, from
                                                                                             anywhere, until someone deactivates
                                                                                             the key. This is how the crypto-
                                                                                             mining bills happen.
```

## Where it looks

| Category | Paths | What a stealer gets |
| --- | --- | --- |
| Cloud | `~/.aws/credentials`, `~/.aws/sso/cache/`, `~/.config/gcloud/`, `~/.azure/`, `~/.terraform.d/`, `~/.vault-token`, `~/.config/doctl/`, `~/.databrickscfg` | Long-lived cloud keys, refresh tokens, API tokens |
| SSH | `~/.ssh/` | Private keys, and whether they have a passphrase. `config` is the map of where they work |
| Git and GitHub | `~/.git-credentials`, `~/.gitconfig`, `~/.config/gh/hosts.yml`, `~/.netrc` | Plain-text Git logins, GitHub CLI tokens |
| Package registries | `~/.npmrc`, `~/.pypirc`, `~/.gem/`, `~/.cargo/`, `~/.m2/`, Composer, NuGet | Publish tokens. One poisoned release reaches everyone who installs it |
| Containers and clusters | `~/.docker/config.json`, `~/.kube/config` | Registry passwords in base64, embedded cluster keys and tokens |
| Shell history | bash, zsh, fish, PowerShell | Keys and passwords typed on the command line |
| Project .env files | `~/Projects`, `~/code`, `~/dev`, `~/Desktop` and friends, three levels deep | Live secrets in `.env`, stray `.pem` and `.key` files |
| Environment variables | this shell | Secrets exported globally in your profile |
| Browser and wallets | Chrome, Edge, Brave, Firefox profiles; Exodus, Electrum, MetaMask | Saved passwords, session cookies, wallet files. Noticed, never opened |

`loot paths` prints this list.

## How the grade works

Every finding has a severity: critical 25 points, high 10, medium 5, low 1, info 0.
Each category can cost at most 40 points, so forty `.env` secrets cannot hide the one
long-lived cloud key that matters more. 100 minus the damage is your score. 90 and up
is an A, 75 a B, 60 a C, 40 a D, below that an F.

The grade is deliberately harsh. A single long-lived AWS key and an SSH key with no
passphrase is a C. That is the honest answer: those two files are enough for a very
bad week.

## What it does not do

- It does not read browser databases or wallet files. It only notices they exist,
  because stealers take them and because the fix (a password manager, short sessions)
  is the same whatever is inside.
- It does not find secrets everywhere on disk. It looks where stealers look. For a full
  repository scan use gitleaks or trufflehog; they solve a different problem.
- It does not fix anything. Every finding has a one-line fix, and the fixes are yours
  to run.
- It cannot see secrets in your password manager, your keychain or an encrypted disk,
  which is where they should be. If loot finds nothing, that is the goal.

## Safety

- Read-only. loot opens files for reading and never writes outside its own output.
- Nothing leaves your machine. No network calls, no telemetry, no accounts.
- Secrets are masked before they are stored in a finding: `AKIAIOSFODNN7EXAMPLE`
  becomes `AKIA…MPLE`. The tests assert that no planted secret ever appears in the
  output, including `--json`.
- Files are capped at 2 MB and history at 20,000 lines, and every scanner is isolated:
  one unreadable file is reported, not fatal.

## For scripts and CI

```bash
loot scan --json
```

```bash
loot scan --fail-on high
```

The second exits with code 1 when anything high or critical is found. Useful as a
check in a dotfiles repository or a laptop onboarding script.

## Development

```bash
uv sync --extra dev
```

```bash
uv run pytest
```

`uv.lock` pins every dependency; CI installs from it with `uv sync --locked`.

The tests plant a fake home folder with every kind of credential loot knows about and
check that each one is found, graded, and never printed. CI runs the suite on Linux,
macOS and Windows.

## License

MIT.
