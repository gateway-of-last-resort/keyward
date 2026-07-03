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

## Local file-handling guarantees

- **Atomic writes.** All writes go to a temporary file, are `fsync`ed/renamed
  into place, then `chmod`ed to `0600`, so a crash can't leave a half-written or
  world-readable key file.
- **Rollback on destructive ops.** Password changes and restores first create a
  `.bak` copy and roll it back via rename if the operation fails. Key rotation
  leaves `.bak` copies of the previous key pair.
- **Memory hygiene.** In-memory key material (`[]byte`) is zeroed after use.
- **Backup retention.** Config backups are capped (last 5 kept) to limit how
  many copies of your SSH config linger on disk.

## Dependencies

Keyward keeps its dependency surface small. The only direct dependencies that
touch cryptography are [`filippo.io/age`](https://filippo.io/age) and
`golang.org/x/crypto` (argon2, chacha20poly1305). We monitor these with
`govulncheck` in CI.
