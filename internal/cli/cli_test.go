package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/keys"
)

// withTempHome points LoadEnv's home resolution at an empty temp dir for the
// duration of a test.
func withTempHome(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	orig := osUserHomeDir
	osUserHomeDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { osUserHomeDir = orig })
}

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Run("v9.9.9", args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRun_NoArgs(t *testing.T) {
	code, _, stderr := run(t)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("expected usage on stderr, got %q", stderr)
	}
}

func TestRun_Version(t *testing.T) {
	code, stdout, _ := run(t, "version")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(stdout, "keyward v9.9.9") {
		t.Errorf("version output = %q", stdout)
	}
}

func TestRun_Help(t *testing.T) {
	code, stdout, _ := run(t, "--help")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(stdout, "Commands:") {
		t.Errorf("help output = %q", stdout)
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	code, _, stderr := run(t, "bogus")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestAudit_InvalidFailOn(t *testing.T) {
	// Bad --fail-on is a usage error, rejected before any filesystem work.
	code, _, stderr := run(t, "audit", "--fail-on=bogus")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "invalid --fail-on") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestAudit_JSONEmptyHome(t *testing.T) {
	withTempHome(t)
	code, stdout, stderr := run(t, "audit", "--json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout)
	}
	if _, ok := report["grade"]; !ok {
		t.Errorf("json missing grade key: %s", stdout)
	}
}

func TestList_JSONEmptyHome(t *testing.T) {
	withTempHome(t)
	code, stdout, stderr := run(t, "list", "--json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	var infos []keyInfo
	if err := json.Unmarshal([]byte(stdout), &infos); err != nil {
		t.Fatalf("output is not valid JSON array: %v\n%s", err, stdout)
	}
	if len(infos) != 0 {
		t.Errorf("expected no keys in empty home, got %d", len(infos))
	}
}

// Keys without a usable private file still have a path: list used to print the
// empty PrivateKeyPath for them, so a public-only key had "path": "" and an
// unrecognised private key was shown as an unencrypted one.
func TestList_KeysWithoutUsablePrivateFile(t *testing.T) {
	home := t.TempDir()
	orig := osUserHomeDir
	osUserHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { osUserHomeDir = orig })

	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pub := func(name string) {
		k, err := keys.GenerateKeys(t.TempDir(), keys.GenerateOptions{
			Algorithm: keys.AlgorithmEd25519, Filename: name, AllowEmptyPassphrase: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(k.PublicKeyPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sshDir, name+".pub"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pub("id_orphan")
	pub("id_junk")
	if err := os.WriteFile(filepath.Join(sshDir, "id_junk"), []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := run(t, "list", "--json")
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	var infos []keyInfo
	if err := json.Unmarshal([]byte(stdout), &infos); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		filepath.Join(sshDir, "id_junk"):       true,
		filepath.Join(sshDir, "id_orphan.pub"): true,
	}
	for _, info := range infos {
		if !want[info.Path] {
			t.Errorf("unexpected path %q", info.Path)
		}
		delete(want, info.Path)
	}
	if len(want) > 0 {
		t.Errorf("paths missing from list --json: %v", want)
	}

	_, stdout, _ = run(t, "list")
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "id_junk") && !strings.Contains(line, "unparsed") {
			t.Errorf("unrecognised private key not labelled unparsed: %q", line)
		}
	}
}
