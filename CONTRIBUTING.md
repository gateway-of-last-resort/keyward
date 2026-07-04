# Contributing to Keyward

Thanks for taking the time to contribute! Bug reports, feature ideas, and pull
requests are all welcome.

## Getting started

Keyward is a single Go module with no build system beyond the `go` toolchain.

```bash
git clone https://github.com/gateway-of-last-resort/keyward
cd keyward
go build ./...     # build every package
go test ./...      # run the full suite
```

Requires **Go 1.26+**. The security-sensitive core (crypto, config, storage,
audit, key parsing) depends only on `filippo.io/age` and `golang.org/x/crypto`;
the terminal UI adds the [Charm](https://charm.sh) stack. Please don't pull in
new dependencies without a good reason.

## Before you open a pull request

Run these locally — CI runs the same checks on Linux, macOS, and Windows and
must be green before a PR is merged:

```bash
go build ./...
go vet ./...
go test ./...
gofmt -l .            # must print nothing
golangci-lint run     # if you have it installed
```

To run a single test while iterating:

```bash
go test -v -run TestName ./pkg/crypto/
```

## Code style

Match the surrounding code. The conventions used throughout the repo:

- **Zero secrets after use.** Sensitive `[]byte` (key material, passwords) is
  wiped with `crypto.ZeroBytes`, typically via `defer`.
- **Atomic file writes.** Write to `os.CreateTemp`, `fsync`, `os.Chmod(0600)`,
  then `os.Rename` into place. Destructive operations (password change, restore)
  create a `.bak` first and roll it back on failure.
- **Wrap sentinel errors** with `fmt.Errorf("%w: %w", ErrX, err)` so callers can
  use `errors.Is`.
- **Byte-identical config round-trips.** The `internal/config` parser preserves
  raw lines, comments, and whitespace — don't reformat on write.

### Tests

- Table-driven with `t.Run` subtests.
- No mocks — use the real filesystem via `t.TempDir()`.
- Prefer write→read round-trip integration tests over isolated unit tests.
- New behavior needs a test; bug fixes should come with a regression test.

## Commits & branches

- Work on a branch, not `main`. Open a pull request against `main`.
- One logical change per commit, with tests alongside the code they cover.
- Use [Conventional Commits](https://www.conventionalcommits.org/) prefixes:
  `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`. Scope them
  where it helps, e.g. `fix(crypto): ...`.
- Keep the subject line short and imperative; put detail in the body.

## Reporting bugs & requesting features

Open an issue using the templates. For anything touching cryptography, key
handling, or file permissions, please read [SECURITY.md](SECURITY.md) first —
security-sensitive reports should follow the disclosure process there rather
than a public issue.
