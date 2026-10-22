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
	t.Setenv("HOME", home)        // POSIX
	t.Setenv("USERPROFILE", home) // Windows (os.UserHomeDir uses this)
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

// A .pub left at the destination must never end up paired with an imported key
// it does not belong to: it would hand that key the wrong fingerprint.
func TestImportKey_StaleOrMismatchedPub(t *testing.T) {
	plain := func(name string) keys.GenerateOptions {
		return keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519, Filename: name, AllowEmptyPassphrase: true}
	}

	tests := []struct {
		name      string
		setup     func(t *testing.T, src, dest string)
		protected bool
		overwrite bool
		wantErr   error
		wantPub   bool // a .pub exists at the destination afterwards
	}{
		{
			name:      "protected key, no source pub, stale dest pub",
			protected: true,
			setup: func(t *testing.T, src, dest string) {
				mustRemove(t, src+".pub")
				writeStalePub(t, dest)
			},
			wantErr: keys.ErrKeyAlreadyExists,
			wantPub: true, // the stale pub is left alone, the import is refused
		},
		{
			name:      "protected key, no source pub, stale dest pub, force",
			protected: true,
			overwrite: true,
			setup: func(t *testing.T, src, dest string) {
				mustRemove(t, src+".pub")
				writeStalePub(t, dest)
			},
			wantPub: false,
		},
		{
			name: "unencrypted key with a source pub from another key",
			setup: func(t *testing.T, src, dest string) {
				other := t.TempDir()
				if _, err := keys.GenerateKeys(other, plain("other")); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(filepath.Join(other, "other.pub"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(src+".pub", data, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: keys.ErrInvalidKey,
		},
		{
			name: "source pub is not a public key",
			setup: func(t *testing.T, src, dest string) {
				if err := os.WriteFile(src+".pub", []byte("garbage\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: keys.ErrInvalidKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extern := t.TempDir()
			opts := plain("id_imp")
			if tt.protected {
				opts = generateOpts(extern, "id_imp")
			}
			if _, err := keys.GenerateKeys(extern, opts); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join(extern, "id_imp")
			dest := t.TempDir()
			tt.setup(t, src, dest)

			_, err := keys.ImportKey(dest, src, keys.ImportOptions{Overwrite: tt.overwrite})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				if _, statErr := os.Stat(filepath.Join(dest, "id_imp")); statErr == nil {
					t.Error("private key written despite the refused import")
				}
			} else if err != nil {
				t.Fatalf("ImportKey: %v", err)
			}

			_, statErr := os.Stat(filepath.Join(dest, "id_imp.pub"))
			if gotPub := statErr == nil; gotPub != tt.wantPub {
				t.Errorf("dest .pub exists = %v, want %v", gotPub, tt.wantPub)
			}
		})
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

// writeStalePub puts another key's public half at dest/id_imp.pub.
func writeStalePub(t *testing.T, dest string) {
	t.Helper()
	other := t.TempDir()
	if _, err := keys.GenerateKeys(other, generateOpts(other, "other")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(other, "other.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "id_imp.pub"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Overwriting an existing file must leave the imported private key at 0600 even
// when the file it replaced was world-readable: OpenFile's perm only applies to
// files it creates.
func TestImportKey_ForceResetsMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are synthetic on Windows")
	}
	src := makeSourceKey(t, "id_force")
	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "id_force"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dest, "id_force"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := keys.ImportKey(dest, src, keys.ImportOptions{Overwrite: true}); err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dest, "id_force"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("imported key mode = %04o, want 0600", got)
	}
}
