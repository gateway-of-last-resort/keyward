# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.5] - 2026-07-03

Reliability and security hardening from a full code audit. No file formats
changed; upgrading is drop-in.

### Fixed

- Launch with an empty key list when `~/.ssh` doesn't exist yet, instead of
  exiting with an error.
- Parse `Host`/`Match` lines and parameters separated by tabs — previously such
  hosts were invisible to the editor and edits landed in the wrong block.
- Changing the SSH directory no longer blanks the key list or persists an
  invalid path; the new directory is validated first.
- No more false CRITICAL permission findings on Windows, where POSIX mode bits
  don't apply.
- A successful config save is no longer shown in the error style after an
  earlier failure.
- Private keys that can't be parsed are now flagged instead of silently ignored.
- `Host` patterns are matched case-sensitively, consistent with OpenSSH.
- TUI layout: long paths on the generate screen and the config hint bar no
  longer stretch the frame.

### Security

- Ask for confirmation before a backup restore overwrites files in `~/.ssh`.
- Refuse to write generated keys through a symlink (`O_EXCL`/`O_NOFOLLOW`),
  closing a TOCTOU write-through.
- Harden backup restore: clamp restored file permissions, cap archive and
  per-file sizes, and use a robust path-traversal guard.
- Zero key passphrases in memory after use.
- Tighten permissions on a pre-existing vault directory to `0700`.

### Changed

- Durable atomic writes (`fsync` of file and directory) with correct `.bak`
  rollback across metadata, prefs, backups, master key, and config; metadata is
  now recovered from `.bak` when the primary file is corrupt, not only missing.
- Key rotation is crash-safe: the private key never disappears from its live
  name mid-rotation.
- Key generation runs asynchronously with a spinner, so the TUI no longer
  freezes (noticeably for RSA).

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

[Unreleased]: https://github.com/gateway-of-last-resort/keyward/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/gateway-of-last-resort/keyward/compare/v0.1.0...v0.1.5
[0.1.0]: https://github.com/gateway-of-last-resort/keyward/releases/tag/v0.1.0
