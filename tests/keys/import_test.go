package keys_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/keys"
)

// makeSourceKey generates a key pair in an "external" temp dir and returns the
// path to its private file.
func makeSourceKey(t *testing.T, name string) string {
	t.Helper()
	extern := t.TempDir()
	if _, err := keys.GenerateKeys(extern, generateOpts(extern, name)); err != nil {
		t.Fatalf("generate source key: %v", err)
	}
	return filepath.Join(extern, name)
}

func TestImportKey_CopiesWithSecurePerms(t *testing.T) {
	src := makeSourceKey(t, "work_ed25519")
	dest := t.TempDir()

	key, err := keys.ImportKey(dest, src, keys.ImportOptions{})
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}

	destPriv := filepath.Join(dest, "work_ed25519")
	if key.PrivateKeyPath != destPriv {
		t.Errorf("PrivateKeyPath = %q, want %q", key.PrivateKeyPath, destPriv)
	}
	if key.Fingerprint == "" {
		t.Error("imported key has no fingerprint")
	}

	stat, err := os.Stat(destPriv)
	if err != nil {
		t.Fatalf("stat imported key: %v", err)
	}
	if runtime.GOOS != "windows" && stat.Mode().Perm() != 0o600 {
		t.Errorf("imported key perms = %o, want 0600", stat.Mode().Perm())
	}
	if _, err := os.Stat(destPriv + ".pub"); err != nil {
		t.Errorf("imported .pub missing: %v", err)
	}
}

func TestImportKey_ExpandsTilde(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if _, err := keys.GenerateKeys(home, generateOpts(home, "tilde_key")); err != nil {
		t.Fatalf("generate: %v", err)
	}

	key, err := keys.ImportKey(t.TempDir(), "~/tilde_key", keys.ImportOptions{})
	if err != nil {
		t.Fatalf("ImportKey with ~ path: %v", err)
	}
	if key.Fingerprint == "" {
		t.Error("imported tilde key has no fingerprint")
	}
}

func TestImportKey_RejectsMissingSource(t *testing.T) {
	dest := t.TempDir()
	_, err := keys.ImportKey(dest, filepath.Join(t.TempDir(), "nope"), keys.ImportOptions{})
	if !errors.Is(err, keys.ErrSourceNotFound) {
		t.Fatalf("err = %v, want ErrSourceNotFound", err)
	}
}

func TestImportKey_RejectsInvalidKey(t *testing.T) {
	extern := t.TempDir()
	bad := filepath.Join(extern, "not_a_key")
	if err := os.WriteFile(bad, []byte("this is not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := keys.ImportKey(t.TempDir(), bad, keys.ImportOptions{})
	if !errors.Is(err, keys.ErrInvalidKey) {
		t.Fatalf("err = %v, want ErrInvalidKey", err)
	}
}

func TestImportKey_RefusesOverwrite(t *testing.T) {
	src := makeSourceKey(t, "dup_ed25519")
	dest := t.TempDir()

	if _, err := keys.ImportKey(dest, src, keys.ImportOptions{}); err != nil {
		t.Fatalf("first import: %v", err)
	}
	_, err := keys.ImportKey(dest, src, keys.ImportOptions{})
	if !errors.Is(err, keys.ErrKeyAlreadyExists) {
		t.Fatalf("err = %v, want ErrKeyAlreadyExists", err)
	}
}
