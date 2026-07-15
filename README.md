# Keyward

> A terminal UI for managing SSH keys, editing your `~/.ssh/config`, auditing
> security, and keeping encrypted backups — all from one keyboard-driven screen.

[![CI](https://github.com/gateway-of-last-resort/keyward/actions/workflows/ci.yml/badge.svg)](https://github.com/gateway-of-last-resort/keyward/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/gateway-of-last-resort/keyward?sort=semver)](https://github.com/gateway-of-last-resort/keyward/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/gateway-of-last-resort/keyward)](https://goreportcard.com/report/github.com/gateway-of-last-resort/keyward)
[![Go](https://img.shields.io/github/go-mod/go-version/gateway-of-last-resort/keyward)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![Keyward demo](assets/demo.gif)

## Contents

- [Why Keyward?](#why-keyward)
- [Features](#features)
- [Install](#install)
- [Usage](#usage)
- [Command line](#command-line)
- [Security](#security)
- [Stability](#stability)
- [Building from source](#building-from-source)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Why Keyward?

Your SSH setup is usually scattered across a pile of files: keys in `~/.ssh`,
hosts in `~/.ssh/config`, permissions you hope are right, and no easy way to
tell a strong key from a weak one. Keyward puts all of it behind a single
keyboard-driven screen:

- **See everything at once** — every key with its type, size, fingerprint, and
  whether it's passphrase-protected, instead of `ls`-ing a directory and running
  `ssh-keygen -l` by hand.
- **Know if you're safe** — a graded **A–F** security audit flags weak keys,
  missing passphrases, loose file permissions, and risky config directives, each
  with a concrete fix.
- **Edit config without breaking it** — host-by-host editing with validation and
  **byte-identical** round-trip serialization: your comments, spacing, and
  ordering survive untouched, and the last 5 versions are backed up automatically.
- **Encrypted by default** — key metadata (tags, notes) and full `~/.ssh`
  backups are encrypted at rest with a key derived from your master password.

No daemon, no config file to learn, no network calls. Just a single static
binary.

## Features

- **Key management** — discover, inspect, generate, rotate, and delete SSH keys
  (`ed25519` / `rsa`), with fingerprints, comments, and per-key tags & notes.
- **Config editor** — edit `~/.ssh/config` host-by-host with validation, comment
  toggling, and byte-identical round-trip serialization. Automatic backups
  (last 5 kept).
- **Security audit** — graded A–F report covering weak keys, missing
  passphrases, file permissions, and risky config directives, each with a
  concrete `fix:` hint.
- **Known hosts viewer** — browse `~/.ssh/known_hosts` (host, key type,
  fingerprint, `@revoked` / `@cert-authority` markers) and forget a host in
  place; the file is rewritten atomically with its mode preserved.
- **Encrypted backups** — age-encrypted `.tar.age` snapshots of your `~/.ssh`
  directory plus key metadata, restorable from within the TUI.
- **Encrypted metadata vault** — tags and notes are stored encrypted at rest,
  unlocked by your master password.

## Install

### Homebrew

```bash
brew install gateway-of-last-resort/tap/keyward
```

### Download a release binary

Copy-paste this to grab the right archive for your OS/arch from the
[latest release](https://github.com/gateway-of-last-resort/keyward/releases/latest),
extract `keyward`, and put it on your `PATH`:

```bash
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m); case "$ARCH" in x86_64) ARCH=amd64;; aarch64) ARCH=arm64;; esac
VER=$(curl -fsSL https://api.github.com/repos/gateway-of-last-resort/keyward/releases/latest \
      | grep -m1 '"tag_name"' | cut -d'"' -f4)
curl -fsSL "https://github.com/gateway-of-last-resort/keyward/releases/download/${VER}/keyward_${VER#v}_${OS}_${ARCH}.tar.gz" -o keyward.tar.gz
tar -xzf keyward.tar.gz keyward && sudo mv keyward /usr/local/bin/ && keyward --version
```

Prefer to do it by hand? Download the `keyward_<version>_<os>_<arch>.tar.gz` for
your platform, then `tar -xzf` it. Verify the download against the published
`checksums.txt` (and its cosign signature — see [SECURITY.md](SECURITY.md)) if
you like.

> [!NOTE]
> Some browsers (notably Safari) auto-decompress `.gz` downloads, leaving you
> with a plain `keyward_..._.tar`. If you only see a `.tar`, unpack it with
> `tar -xf` (no `z`).

### With Go

```bash
go install github.com/gateway-of-last-resort/keyward/cmd/keyward@latest
```

This installs the `keyward` binary into `$(go env GOPATH)/bin`.

## Usage

Just run it — no arguments launches the interactive TUI:

```bash
keyward
```

On first launch you set a master password; this creates an encrypted vault at
`~/.keyward/master.key`. Subsequent launches unlock with that password.

```
keyward                     launch the interactive TUI
keyward <command> [flags]   run a non-interactive command (see below)
keyward [--version] [--help]
```

### Navigation

| Key | Action |
| --- | --- |
| `Tab` / `Shift+Tab` | Cycle screens: Keys → Audit → Config → Generate → Known Hosts → Backup → Settings |
| `↑/↓` or `j/k` | Move within a list |
| `Enter` | Open / confirm |
| `Esc` | Back / cancel |
| `/` | Search (Keys screen) |
| `i` | Import an external key (Keys screen) |
| `A` | Add the selected key to ssh-agent (Detail screen) |
| `q` | Quit (from the Keys screen) |
| `Ctrl+C` | Quit from anywhere |

Per-screen actions (generate, rotate, delete, copy public key, edit config,
forget a known host, backup/restore, change master password) are shown
contextually in the footer.

> [!WARNING]
> Rotate, delete, and restore modify real files under `~/.ssh`. To experiment
> safely, point Keyward at a throwaway directory — run it under a sandbox `HOME`
> or change the SSH directory in Settings before trying destructive actions.

## Command line

Beyond the TUI, Keyward exposes headless subcommands for scripting, CI, and cron:

![Keyward CLI demo](assets/cli-demo.gif)

| Command | What it does |
| --- | --- |
| `keyward audit [--json] [--fail-on=<sev>]` | Run the security audit; print text or JSON |
| `keyward list [--json]` | List discovered SSH keys (alias: `keys`) |
| `keyward import <path> [--force]` | Copy an external key into `~/.ssh` with `0600` perms |
| `keyward agent add <key> [--passphrase-env VAR]` | Load a key into the running ssh-agent |
| `keyward agent list` | Show which keys are currently loaded in the agent |
| `keyward backup [--out <path>]` | Write an encrypted `~/.ssh` backup |

**Audit in CI.** `--fail-on=<critical\|warning\|info>` makes the audit exit
non-zero when a finding meets that severity, so it can gate a pipeline:

```bash
keyward audit --fail-on=critical      # fail the build only on critical findings
keyward audit --json | jq '.grade'    # machine-readable report
```

**Passwords for scripts.** `keyward backup` reads the master password from
`$KEYWARD_PASSWORD` (or prompts if unset). `keyward agent add` takes the key
passphrase from the variable named by `--passphrase-env` (export it first and
pass the variable **name**, not the passphrase), or prompts when the flag is
omitted:

```bash
export KEYWARD_PASSWORD='…'
keyward backup --out /mnt/usb/ssh-backup.tar.age
```

## Security

Keyward encrypts metadata and backups with a master key derived from your
password (argon2id → ChaCha20-Poly1305 → age identity). For the full threat
model, cryptographic details, release-signature verification, and how to report
a vulnerability, see [SECURITY.md](SECURITY.md).

## Stability

As of **1.0.0**, Keyward follows [semantic versioning](https://semver.org). The
on-disk formats (`master.key`, `metadata.age`, and `.tar.age` backups) and the
command-line interface are stable: a vault created today keeps working across all
`1.x` releases, and any breaking change to a format or flag would require a `2.0`.
The format and migration guarantees are documented in
[SECURITY.md](SECURITY.md#format-stability-and-migration-policy).

## Building from source

```bash
git clone https://github.com/gateway-of-last-resort/keyward
cd keyward
go build ./cmd/keyward
go test ./...
```

Requires Go 1.26+. The security-sensitive core (crypto, config, storage, audit,
key parsing) depends only on [`filippo.io/age`](https://filippo.io/age) and
`golang.org/x/crypto`; the terminal UI layer adds the
[Charm](https://charm.sh) stack (`bubbletea`, `bubbles`, `lipgloss`).

## Roadmap

Ideas being considered for after 1.0 (directions, not commitments):

- `Include` directive support in the config editor (multi-file configs)
- More audit checks: duplicate fingerprints, SSH certificate detection, agent
  socket permissions
- Hardware-backed keys (`sk-ssh-ed25519@openssh.com`, FIDO2) and SSH certificate
  management
- Multiple or custom-location vaults, key-rotation reminders, and incremental
  backups

Feedback and feature requests are welcome via [issues](https://github.com/gateway-of-last-resort/keyward/issues).

## Contributing

Bug reports, feature ideas, and pull requests are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md) for build/test/style conventions and the
branch-and-PR workflow.

## License

[MIT](LICENSE)
</content>
