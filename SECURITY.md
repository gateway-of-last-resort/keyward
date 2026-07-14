# Security Policy

## Supported versions

Keyward is pre-1.0. Security fixes are applied to the latest released version
only. Please upgrade to the newest release before reporting an issue.

| Version | Supported |
| ------- | --------- |
| latest `0.x` | ✅ |
| older `0.x` | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub Security Advisories
("Security" tab → "Report a vulnerability") on the
[keyward repository](https://github.com/gateway-of-last-resort/keyward/security/advisories/new).

Please include:

- affected version (`keyward --version`) and platform,
- a description of the issue and its impact,
- steps to reproduce or a proof of concept.

You can expect an acknowledgement within **72 hours** and a status update within
**14 days**. Once a fix is released, we are happy to credit you in the release
notes unless you prefer to remain anonymous.

## Threat model

Keyward is a local tool: it runs as your user and operates on files in your home
directory. The protections below assume an attacker who can read the encrypted
artifacts at rest (e.g. a stolen backup, a synced/cloud copy of `~/.keyward`, or
a leaked snapshot) but does **not** have your master password.

**In scope — what we protect**

- **Metadata at rest.** Key tags and notes are stored in `~/.keyward/metadata.age`,
  encrypted; they are unreadable without the master key.
- **Backups at rest.** Backups are age-encrypted `.tar.age` archives under
  `~/.keyward/backups/`, unreadable without the master key.
- **The master key.** The age identity in `~/.keyward/master.key` is encrypted
  with a key derived from your password; the password is never stored.
- **Local file safety.** Sensitive files are written atomically with restrictive
  permissions, and destructive operations keep a rollback copy (see below).

**Out of scope — what we do not (and cannot) protect against**

- An attacker who already knows your **master password**, or who can observe it
  (keylogger, shoulder-surfing).
- A compromised machine: malware running as your user, a hostile root account,
  swap/coredumps capturing process memory, or a malicious terminal.
- The **private SSH keys themselves** under `~/.ssh` – Keyward manages and audits
  them but does not encrypt them at rest beyond their own passphrases (those are
  protected by OpenSSH, not Keyward).
- Weak master passwords. Key derivation is hardened (see below) but cannot
  rescue a trivially guessable password.
- `known_hosts` / `authorized_keys`, which are intentionally excluded from
  backups.

## Cryptography

The master key protects everything else, so its construction matters:

1. **Identity.** On first run, Keyward generates an
   [age](https://filippo.io/age) X25519 identity. This identity is the
   encryption key for all metadata and backups.
2. **Key derivation.** A key-encryption key (KEK) is derived from your password
   with **argon2id** — parameters: time = 3, memory = 64 MiB, threads = 4,
   32-byte output, with a random 32-byte salt.
3. **Identity encryption.** The age identity is encrypted with
   **ChaCha20-Poly1305** (AEAD) using the KEK and a random 12-byte nonce. The
   file header — including the argon2 parameters and salt — is bound to the
   ciphertext as AEAD associated data, so tampering with the stored KDF
   parameters is detected on unlock instead of silently deriving a different key.
4. **Data encryption.** Metadata JSON and backup archives are encrypted to the
   age identity (X25519 + ChaCha20-Poly1305 via the age format).

### `master.key` file format

```
"SSHV"            4-byte magic
version           1 byte (0x02)
argon2 time       uint32, big-endian
argon2 memory     uint32, big-endian (KiB)
argon2 threads    1 byte
salt              32 bytes
nonce             12 bytes
ciphertext        encrypted age identity (+ Poly1305 tag)
```

The argon2 parameters are stored in the file, so existing vaults keep working if
defaults change in a future release.

**Format versions.** v1 files had the same layout but did not authenticate the
header. v2 (current) binds the header bytes above as AEAD associated data. A v1
file is read transparently and rewritten in place as v2 on the next successful
unlock, so no manual migration is needed.

### `metadata.age` file format

Key metadata lives in `~/.keyward/metadata.age`: an age file (X25519 +
ChaCha20-Poly1305, the standard `age-encryption.org/v1` binary format) wrapping a
single JSON document. Decrypted, the plaintext is:

```json
{
  "SchemaVersion": 1,
  "Keys": {
    "SHA256:<fingerprint>": {
      "Fingerprint": "SHA256:<fingerprint>",
      "Tags": ["work"],
      "Note": "...",
      "LastRotatedAt": "2026-01-02T15:04:05Z",
      "LinkedHosts": ["github.com"]
    }
  },
  "SavedAt": "2026-01-02T15:04:05Z"
}
```

`SchemaVersion` identifies the metadata schema (see the migration policy below);
files written before v0.6.0 omit the field and are read as version 0. The store
is written atomically (temp → fsync → rename → `chmod 0600`), with the previous
file moved aside as `metadata.age.bak` for rollback and crash recovery.

### Backup `.tar.age` file format

A backup is an age file wrapping an uncompressed **tar** archive, stored as
`~/.keyward/backups/<timestamp>.tar.age` (timestamp `YYYY-MM-DD_HH-MM-SS`). The
archive contains:

- every regular file in `~/.ssh` **except** `known_hosts` and `authorized_keys`
  (stored under their bare names, e.g. `id_ed25519`, `config`);
- the metadata vault, stored under the reserved prefix `.keyward/metadata.age`.

Each tar entry records the file's permission bits and modification time. On
restore, an entry whose name begins with `.keyward/` is written back under the
vault directory; everything else is written under `~/.ssh`. Restore is defensive:
paths are contained to their target directory (a `..` traversal entry is skipped),
restored modes are clamped to at most `0600`, and the whole archive and any single
entry are size-capped (128 MiB / 64 MiB) so a crafted archive can't exhaust
memory. The newest 5 backups are kept; older ones are pruned after each write.

## Format stability and migration policy

Keyward is pre-1.0 and the on-disk formats above are approaching a stability
commitment. From **1.0.0** onward:

- **Backward-compatible reads.** A release reads any `master.key`, `metadata.age`,
  or backup written by an earlier release; existing vaults keep working across
  upgrades with no manual steps.
- **Versioned, migrating changes only.** A breaking change to a format is made by
  bumping its version marker and migrating on read — never by silently changing
  the layout. The `master.key` v1 → v2 upgrade is the model: a v1 file is read
  transparently and rewritten as v2 on the next unlock. `metadata.age` carries a
  `SchemaVersion` field for the same purpose; the backup tar is self-describing
  through its entry names.
- **Forward tolerance.** Unknown JSON fields in `metadata.age` are ignored rather
  than rejected, so a store touched by a newer minor release still loads on an
  older one within the 0.x line.

## Local file-handling guarantees

- **Atomic writes.** All writes go to a temporary file, are `fsync`ed/renamed
  into place, then `chmod`ed to `0600`, so a crash can't leave a half-written or
  world-readable key file.
- **Rollback on destructive ops.** Password changes and restores first create a
  `.bak` copy and roll it back via rename if the operation fails. Key rotation
  leaves `.bak` copies of the previous key pair.
- **Memory hygiene.** In-memory key material (`[]byte`) is zeroed after use.
  One residual window remains: the age identity must pass through a Go `string`
  when it is encrypted and decrypted, and a string's backing array cannot be
  zeroed — it lingers on the heap until garbage collection. Exploiting this needs
  a separate memory-disclosure primitive (core dump, swap, `/proc`); the `[]byte`
  buffers around it are still wiped.
- **Backup retention.** Config backups are capped (last 5 kept) to limit how
  many copies of your SSH config linger on disk.

## Platform notes (Windows)

POSIX file modes do not mean on Windows what they mean on Unix, so Keyward treats
a few things differently there. This is by design, not a gap.

- **Permissions are ACL-governed.** Go synthesizes `os.FileMode` on Windows from
  file attributes; it never matches `0600`/`0700`/`0o077`, and real access is
  controlled by NTFS ACLs. Comparing mode bits would flag every file regardless
  of its actual protection, so the audit **skips** the key (`0600`), `~/.ssh`
  directory (`0700`), and config (`0o077`) permission checks on Windows and
  instead emits a single **Info** finding: file access is governed by NTFS ACLs,
  and you should confirm `~/.ssh` and your private keys are restricted to your
  user account. On Unix these checks run normally and a wrong mode is flagged.
- **Atomic writes stay atomic; the directory fsync is skipped.** Every write is
  still `temp -> fsync -> rename`, and `rename` is atomic on Windows. The extra
  *directory* fsync that makes the rename itself crash-durable is skipped, because
  opening a directory and calling `Sync` returns "Access is denied" on Windows.
  The file contents are still fsynced before the rename.
- **Symlink pre-open guard is a no-op.** New-key creation opens with `O_NOFOLLOW`
  on Unix to refuse a pre-planted symlink. Windows has no `O_NOFOLLOW`; the
  `O_EXCL` exclusive-create guard still applies, and the symlink threat model
  differs there.

## Verifying releases

Release artifacts are checksummed in `checksums.txt`, which is signed with
[cosign](https://github.com/sigstore/cosign) using keyless signing (Sigstore
OIDC — no long-lived signing key). Each release publishes `checksums.txt`,
`checksums.txt.sig`, and `checksums.txt.pem` alongside the archives.

To verify a download, first check the signature over `checksums.txt`:

```bash
cosign verify-blob checksums.txt \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  --certificate-identity-regexp '^https://github.com/gateway-of-last-resort/keyward/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

A `Verified OK` means `checksums.txt` was produced by this project's release
workflow. Then confirm your archive matches its listed checksum:

```bash
sha256sum -c checksums.txt --ignore-missing
```

## Dependencies

Keyward keeps its dependency surface small. The only direct dependencies that
touch cryptography are [`filippo.io/age`](https://filippo.io/age) and
`golang.org/x/crypto` (argon2, chacha20poly1305). We monitor these with
`govulncheck` in CI.
