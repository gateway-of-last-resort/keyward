# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-13

Initial public release.

### Added

- **Key management** — discover, inspect, generate, rotate, and delete SSH keys
  (`ed25519` / `rsa`) from a keyboard-driven TUI, with fingerprints, comments,
  and per-key tags & notes.
- **SSH config editor** — edit `~/.ssh/config` host-by-host with keyword
  validation, comment toggling, and byte-identical round-trip serialization.
  Automatic config backups (last 5 retained).
- **Security audit** — graded A–F report covering weak keys, missing
  passphrases, file permissions, and risky config directives, each with a
  concrete `fix:` hint.
- **Encrypted backups** — age-encrypted `.tar.age` snapshots of `~/.ssh` plus
  key metadata, with in-app restore.
- **Encrypted metadata vault** — tags and notes encrypted at rest with a master
  key (argon2id → ChaCha20-Poly1305 → age X25519 identity).
- `--version` and `--help` flags.

[Unreleased]: https://github.com/gateway-of-last-resort/keyward/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gateway-of-last-resort/keyward/releases/tag/v0.1.0
