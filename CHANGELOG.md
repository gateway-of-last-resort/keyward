# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.2] - 2026-07-26

Fixes found by testing the 1.0.1 build on Windows. Three of them were never
Windows-specific and applied to every platform.

### Fixed

- **A private file that cannot be recognized is no longer left behind on delete.**
  Such a file (junk or a BOM ahead of `-----BEGIN`, or one Keyward cannot read) is
  now tracked, so deleting the key removes it along with the public half. Before,
  only the `.pub` was removed, and since that is what made the pair discoverable,
  the private file then became invisible to Keyward while still sitting on disk.
- **Keys with no usable private key are named** in the key list, the detail
  heading and the search index. They used to render with an empty name, and the
  detail screen showed an empty modification date. The key is now identified by
  its private file where one exists, which also means a key referenced by
  `IdentityFile` is no longer falsely reported as linked to no host.
- **Add-to-agent and rotate refuse a key without a usable private key** instead of
  failing afterwards. Both only checked for a fingerprint, which a public-only key
  has, so `A` reported `open : no such file or directory` and `r` opened a form
  that could only end in an error.
- **Editing a line in a CRLF config keeps the file's line endings.** The rewritten
  line was always written with a bare `\n`, which left a CRLF file mixed. Lines
  that are not edited were already preserved byte-for-byte.
- **Comments render without corrupting the screen.** On a CRLF config the carriage
  return reached the terminal, moving the cursor to the start of the line and
  wiping the row already drawn there, including the host name in the neighbouring
  pane. Control characters are now stripped for display only; the file is untouched.
- **`keyward version` reports the version for `go install` builds.** The version
  was injected only at release time, so anyone installing with `go install` saw
  `dev`. It is now read from the module version the toolchain embeds. Builds from a
  working tree still report `dev`.
- **The audit no longer emits a pathless finding** for a key whose private half
  cannot be parsed. It reported the same file twice, once without a path.
- **The key list order is stable between runs.** Keys without a usable private
  path all compared equal while sorting, so their order followed map iteration.

## [1.0.1] - 2026-07-17

Config-editor fixes found while testing the 1.0.0 build on Linux.

### Fixed

- **Config editor** no longer collapses to a single host and a single parameter
  right after a save. Handling the post-save re-scan rebuilt the editor and the
  key list without restoring their size, so both rendered a one-row window until
  the next tab switch. Nothing was ever written incorrectly — the file on disk
  was always right.
- **Comment attribution** follows the file's layout: a run of comments directly
  above a `Host` describes that host, while a comment left below the last
  parameter — a commented-out setting, say — now stays with the block it was
  written under instead of surfacing under the next one.
- **Comments in the config editor** are legible (they were painted in the frame
  colour, near-invisible against the background) and show the cursor when
  selected, which the `t` toggle needs.

## [1.0.0] - 2026-07-15

First stable release. The on-disk formats (`master.key`, `metadata.age`, and
`.tar.age` backups) and the command-line interface are now covered by semantic
versioning: existing vaults keep working across all `1.x` releases, and a breaking
change to a format or flag would require a `2.0`.

No functional changes over 0.9.0. This milestone declares the stability contract
reached across the 0.5.1–0.9.0 line: a unified TUI, documented and versioned
on-disk formats, a documented Windows permission model, end-to-end and fuzz test
coverage, and a pre-1.0 correctness review.

## [0.9.0] - 2026-07-15

A correctness and robustness pass from a pre-1.0 review: config-parser edge cases,
TUI state bugs, and several vault-safety fixes.

### Fixed

- **Config parser** accepts the `Keyword = value` form (optional whitespace around
  `=`) and `Host=pattern`, and preserves mixed and CRLF line endings byte-for-byte
  on round-trip. Renaming a Match block rewrites its line instead of silently
  diverging from the file, and about 30 more ssh_config keywords are recognised.
- **Backup restore** reloads the in-memory metadata store, so restored tags and
  notes appear immediately and are no longer overwritten by the next save.
- **Key rotation** writes the new public key to the standard path for a
  private-only key (no orphaned temp file), and a weak RSA key can now be rotated
  (its size is clamped up to 4096).
- **Detail screen** shows audit findings for public-only keys, and deleting one
  targets the right key without touching a stray file in the working directory.
- The audit re-runs after a config save, and the Settings footer shows the actual
  build version instead of a hardcoded string.

### Security

- **Master-key recovery.** A crash during a password change could leave only a
  `master.key.bak`; the vault is now recovered from it instead of appearing absent
  and prompting a new identity that would orphan existing metadata and backups.
- The key-rotation `.bak` copy refuses a pre-planted symlink (`O_NOFOLLOW`), and
  the `UserKnownHostsFile /dev/null` audit check is no longer bypassed by extra
  paths or quotes.

### Changed

- The metadata store is snapshotted before the background save, preventing a rare
  concurrent-map crash on fast successive metadata edits.

## [0.8.0] - 2026-07-15

Test-hardening pass before the 1.0 stability sweep: end-to-end, fuzzing, and
full-program TUI coverage. Fuzzing surfaced and fixed a denial-of-service in the
master-key loader.

### Security

- **Bounded the argon2 parameters read from `master.key`.** A crafted or corrupt
  key file could request a huge KDF memory size and make the loader allocate
  gigabytes and hang on unlock. The parameters are now range-checked and an
  out-of-range header is rejected as corrupt. Found by the new fuzzer.

### Added

- End-to-end lifecycle test (init, generate, audit, backup, restore, verify),
  fuzz targets for the config parser and the `master.key` loader, and a
  full-program TUI navigation and render test. Tests only; no new runtime or test
  dependencies.

## [0.7.0] - 2026-07-14

Settles the Windows story on the path to 1.0: one documented model for how
permissions and durability behave where POSIX semantics do not apply.

### Changed

- **Windows permission audit** — the per-file POSIX permission checks (key
  `0600`, `~/.ssh` `0700`, config `0o077`) are consolidated so that on Windows
  they are skipped in favour of a single Info explaining that access is governed
  by NTFS ACLs. The audit now gives a meaningful result there instead of a silent
  skip; on Unix the checks are unchanged.
- **Documented the Windows model** — SECURITY.md gains a Platform notes section
  covering ACLs vs POSIX bits, the skipped directory fsync (writes stay atomic),
  and the no-op `O_NOFOLLOW` symlink guard (`O_EXCL` still applies).

## [0.6.0] - 2026-07-14

Establishes the on-disk format stability contract on the path to 1.0: the formats
are documented and a metadata schema version is now recorded so future changes can
migrate cleanly.

### Added

- **Metadata schema version** — `metadata.age` now records a `SchemaVersion`
  field. Stores written by earlier versions are read unchanged (as version 0), so
  the field is a forward-looking hook for backward-compatible migrations.

### Changed

- **Documented on-disk formats** — SECURITY.md now specifies the `master.key`,
  `metadata.age`, and backup `.tar.age` layouts and states the format-stability
  and migration policy (backward-compatible reads, versioned migrating changes)
  that takes effect from 1.0.

## [0.5.1] - 2026-07-06

Completes the selection-style redesign started in 0.5.0 so every screen shares
the mint accent-bar idiom.

### Changed

- **Detail-screen forms** — rotate, edit-metadata, and add-to-agent now use the
  mint accent-bar selection idiom instead of the old `>` field markers. The note
  editor shows focus by turning its own left strip mint rather than adding a bar.
- **Config editor** — host and parameter add/rename/edit inputs drop the `>`
  markers for the accent bar; the selected parameter's bar shows only while the
  Parameters column is active, and the Hosts list dims when focus is on
  Parameters (the selected host stays highlighted).
- **Unlock and first-run setup** screens — the password fields drop the `>`
  marker for the accent bar, matching the rest of the TUI.

## [0.5.0] - 2026-07-05

Keyward gains a known_hosts viewer and a cohesive pass over the TUI's selection
styling.

### Added

- **Known Hosts screen** — browse `~/.ssh/known_hosts` entries (host, key type,
  SHA256 fingerprint, `@revoked` / `@cert-authority` markers, hashed hosts) and
  forget a host with `d` (two-step confirm). The file is rewritten atomically
  with its original mode preserved and neighbouring lines left byte-for-byte
  unchanged. New tab between Generate and Backup.

### Changed

- **Unified selection style** across the list and form screens: a mint accent
  bar plus a brighter highlight replace the old dim rows and `>` field markers,
  and the "✓ OK" status is now a badge matching the severity pills.
- **SSH directory** is edited inline on the Settings screen (the separate editor
  screen is gone), with a bounded, horizontally-scrolling input so a long path
  never widens the frame.

### Fixed

- The key detail screen no longer renders a duplicated hint line while editing
  metadata, rotating, or adding to the agent; the hint now shows once in the
  status bar.

## [0.4.0] - 2026-07-05

Keyward gains a command-line interface for automation (CI, cron, scripts) and
rounds out the key lifecycle with import and ssh-agent support.

### Added

- **Command-line interface** — headless subcommands that reuse the same engine
  as the TUI:
  - `keyward audit [--json] [--fail-on=critical|warning|info]` — run the audit
    as text or JSON; `--fail-on` exits non-zero when a finding meets the
    threshold, for CI gating.
  - `keyward list [--json]` — list discovered SSH keys (alias `keys`).
  - `keyward import <path> [--force]` — copy an external key into `~/.ssh`.
  - `keyward agent add <key> [--passphrase-env VAR]` / `keyward agent list` —
    load a key into the ssh-agent and see what's loaded.
  - `keyward backup [--out <path>]` — write an encrypted backup; the master
    password comes from `$KEYWARD_PASSWORD` or a prompt.
- **Import keys** — bring an external key under management from the Keys screen
  (`i`) or the CLI; it's copied in with `0600` permissions and a `.pub`.
- **ssh-agent integration** — add a key to the agent from the key detail screen
  (`A`), with a "loaded" indicator; a matching CLI verb.
- **New audit checks** — SSH config file permissions, `ForwardAgent yes`, and
  `UserKnownHostsFile /dev/null`.

### Changed

- Non-fatal error banners auto-dismiss after a few seconds instead of lingering
  until the next keypress.

## [0.3.0] - 2026-07-05

A launch-focused release: a demo, trustworthy installs, and contributor
tooling. No changes to on-disk formats or behavior.

### Added

- A terminal demo GIF in the README, reproducible from a committed `demo.tape`
  and setup script under `assets/`.
- Homebrew install: `brew install gateway-of-last-resort/tap/keyward`.
- Release artifacts: `checksums.txt` is now signed with keyless cosign
  (Sigstore OIDC); see SECURITY.md for verification steps.
- `CONTRIBUTING.md` plus issue and pull-request templates.
- `golangci-lint` runs in CI.

### Fixed

- The release-binary install snippet in the README now resolves the correct
  OS/arch archive name (the old one failed on macOS and non-amd64 hosts).

### Changed

- README overhaul: a "Why Keyward?" section, a table of contents, and an
  accurate dependency description (age + x/crypto at the core; the Charm stack
  for the TUI).

## [0.2.0] - 2026-07-04

Cryptographic hardening and more honest backups. Existing `master.key` files are
upgraded automatically on the next unlock — no action needed.

### Added

- Test suite for the `crypto` package: master-key round-trips, header-parser
  boundary cases, and encrypt/decrypt error paths.

### Security

- The `master.key` header (argon2 parameters, salt, nonce) is now authenticated
  as AEAD associated data, so tampering with the stored KDF parameters is
  detected on unlock. This is format v2; v1 files are read and migrated in place
  automatically on the next successful unlock.
- Reject newlines and other control characters in SSH config values and host
  patterns, closing a potential directive-injection vector.
- Documented the residual memory window where the age identity passes through a
  non-zeroable Go string.

### Changed

- Backups are honest about partial results: `CreateBackup` reports files it
  couldn't read, backup pruning surfaces removal errors, and restore no longer
  swallows rollback failures.

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

[Unreleased]: https://github.com/gateway-of-last-resort/keyward/compare/v1.0.1...HEAD
[1.0.2]: https://github.com/gateway-of-last-resort/keyward/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/gateway-of-last-resort/keyward/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/gateway-of-last-resort/keyward/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/gateway-of-last-resort/keyward/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/gateway-of-last-resort/keyward/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/gateway-of-last-resort/keyward/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/gateway-of-last-resort/keyward/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/gateway-of-last-resort/keyward/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/gateway-of-last-resort/keyward/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/gateway-of-last-resort/keyward/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/gateway-of-last-resort/keyward/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/gateway-of-last-resort/keyward/compare/v0.1.5...v0.2.0
[0.1.5]: https://github.com/gateway-of-last-resort/keyward/compare/v0.1.0...v0.1.5
[0.1.0]: https://github.com/gateway-of-last-resort/keyward/releases/tag/v0.1.0
