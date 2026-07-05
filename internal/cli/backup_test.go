package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

// setupVault builds a sandbox HOME with an initialized vault and one SSH key,
// points LoadEnv at it, and returns the home dir.
func setupVault(t *testing.T, password string) string {
	t.Helper()
	home := t.TempDir()

	vaultDir := filepath.Join(home, ".keyward")
	sshDir := filepath.Join(home, ".ssh")
	for _, d := range []string{vaultDir, sshDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte("key material"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.InitMasterKey(filepath.Join(vaultDir, "master.key"), password); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	orig := osUserHomeDir
	osUserHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { osUserHomeDir = orig })
	return home
}

func TestBackup_CreatesArchive(t *testing.T) {
	home := setupVault(t, "correct-horse")
	t.Setenv("KEYWARD_PASSWORD", "correct-horse")

	var out, errb bytes.Buffer
	code := Run("v", []string{"backup"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errb.String())
	}

	entries, err := os.ReadDir(filepath.Join(home, ".keyward", "backups"))
	if err != nil {
		t.Fatalf("read backups dir: %v", err)
	}
	var found bool
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tar.age") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no .tar.age backup created; got %v", entries)
	}
}

func TestBackup_WrongPassword(t *testing.T) {
	setupVault(t, "correct-horse")
	t.Setenv("KEYWARD_PASSWORD", "wrong-password")

	var out, errb bytes.Buffer
	code := Run("v", []string{"backup"}, &out, &errb)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "unlock") {
		t.Errorf("stderr = %q, want an unlock error", errb.String())
	}
}

func TestBackup_OutCopiesArchive(t *testing.T) {
	home := setupVault(t, "pw")
	t.Setenv("KEYWARD_PASSWORD", "pw")
	out := filepath.Join(home, "external.tar.age")

	var stdout, stderr bytes.Buffer
	code := Run("v", []string{"backup", "--out", out}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("--out archive not written: %v", err)
	}
}
