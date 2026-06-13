# Keyward

> A terminal UI for managing SSH keys, editing your `~/.ssh/config`, auditing
> security, and keeping encrypted backups — all from one keyboard-driven screen.

[![CI](https://github.com/gateway-of-last-resort/keyward/actions/workflows/ci.yml/badge.svg)](https://github.com/gateway-of-last-resort/keyward/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/gateway-of-last-resort/keyward?sort=semver)](https://github.com/gateway-of-last-resort/keyward/releases/latest)
[![Go](https://img.shields.io/github/go-mod/go-version/gateway-of-last-resort/keyward)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

<!-- TODO: записать демо TUI (vhs / asciinema) и вставить сюда:
![Keyward demo](docs/demo.gif)
-->

## Features

- **Key management** — discover, inspect, generate, rotate, and delete SSH keys
  (`ed25519` / `rsa`), with fingerprints, comments, and per-key tags & notes.
- **Config editor** — edit `~/.ssh/config` host-by-host with validation, comment
  toggling, and byte-identical round-trip serialization. Automatic backups
  (last 5 kept).
- **Security audit** — graded A–F report covering weak keys, missing
  passphrases, file permissions, and risky config directives, each with a
  concrete `fix:` hint.
- **Encrypted backups** — age-encrypted `.tar.age` snapshots of your `~/.ssh`
  directory plus key metadata, restorable from within the TUI.
- **Encrypted metadata vault** — tags and notes are stored encrypted at rest,
  unlocked by your master password.

## Install

### Download a release binary (recommended)

Grab the archive for your platform from the
[latest release](https://github.com/gateway-of-last-resort/keyward/releases/latest),
extract it, and put `keyward` on your `PATH`:

```bash
tar -xzf keyward_*_$(uname -s)_$(uname -m).tar.gz
sudo mv keyward /usr/local/bin/
keyward --version
```

Verify the download against the published `checksums.txt` if you like.

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
keyward [--version] [--help]
```

### Navigation

| Key | Action |
| --- | --- |
| `Tab` / `Shift+Tab` | Cycle screens: Keys → Audit → Config → Generate → Backup → Settings |
| `↑/↓` or `j/k` | Move within a list |
| `Enter` | Open / confirm |
| `Esc` | Back / cancel |
| `/` | Search (Keys screen) |
| `q` | Quit (from the Keys screen) |
| `Ctrl+C` | Quit from anywhere |

Per-screen actions (generate, rotate, delete, copy public key, edit config,
backup/restore, change master password) are shown contextually in the footer.

> [!WARNING]
> Rotate, delete, and restore modify real files under `~/.ssh`. To experiment
> safely, point Keyward at a throwaway directory — run it under a sandbox `HOME`
> or change the SSH directory in Settings before trying destructive actions.

## Security

Keyward encrypts metadata and backups with a master key derived from your
password (argon2id → ChaCha20-Poly1305 → age identity). For the full threat
model, cryptographic details, and how to report a vulnerability, see
[SECURITY.md](SECURITY.md).

## Building from source

```bash
git clone https://github.com/gateway-of-last-resort/keyward
cd keyward
go build ./cmd/keyward
go test ./...
```

Requires Go 1.26+. The only direct dependencies are
[`filippo.io/age`](https://filippo.io/age) and `golang.org/x/crypto`.

## License

[MIT](LICENSE)
