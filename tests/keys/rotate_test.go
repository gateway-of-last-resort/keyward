package keys_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/keys"
)

func TestRotateKey_CrashSafe(t *testing.T) {
	dir := t.TempDir()
	orig, err := keys.GenerateKeys(dir, generateOpts(dir, "id_ed25519"))
	if err != nil {
		t.Fatalf("generate original: %v", err)
	}
	oldPriv, err := os.ReadFile(orig.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	newKey, bakPath, err := keys.RotateKey(orig, generateOpts(dir, "id_ed25519"))
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// The private key must still live at its original path — never only as .bak.
	if _, err := os.Stat(orig.PrivateKeyPath); err != nil {
		t.Fatalf("live private key missing after rotation: %v", err)
	}
	if newKey.PrivateKeyPath != orig.PrivateKeyPath {
		t.Errorf("new key path = %q, want %q", newKey.PrivateKeyPath, orig.PrivateKeyPath)
	}
	if newKey.Fingerprint == "" || newKey.Fingerprint == orig.Fingerprint {
		t.Errorf("fingerprint should change after rotation; got %q (old %q)", newKey.Fingerprint, orig.Fingerprint)
	}

	// .bak must hold the original private key content.
	if bakPath != orig.PrivateKeyPath+".bak" {
		t.Errorf("bakPath = %q, want %q", bakPath, orig.PrivateKeyPath+".bak")
	}
	bak, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("read .bak: %v", err)
	}
	if !bytes.Equal(bak, oldPriv) {
		t.Error(".bak does not contain the original private key")
	}

	// Parse must surface exactly one key, at the live path (not the temp or bak).
	parsed, err := keys.Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 1 {
		t.Fatalf("Parse found %d keys, want 1", len(parsed))
	}
	if parsed[0].PrivateKeyPath != orig.PrivateKeyPath {
		t.Errorf("parsed key path = %q, want %q", parsed[0].PrivateKeyPath, orig.PrivateKeyPath)
	}

	// No temp files must be left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".rotate-tmp") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

// A generation failure must leave the existing key completely untouched — no
// rename, no .bak — since generation now happens before anything live is moved.
func TestRotateKey_GenerationFailureLeavesKeyIntact(t *testing.T) {
	dir := t.TempDir()
	orig, err := keys.GenerateKeys(dir, generateOpts(dir, "id_ed25519"))
	if err != nil {
		t.Fatalf("generate original: %v", err)
	}
	before, err := os.ReadFile(orig.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	bad := generateOpts(dir, "id_ed25519")
	bad.Algorithm = "bogus" // invalid: generation fails up front
	if _, _, err := keys.RotateKey(orig, bad); err == nil {
		t.Fatal("expected rotation to fail with an invalid algorithm")
	}

	after, err := os.ReadFile(orig.PrivateKeyPath)
	if err != nil {
		t.Fatalf("live key missing after failed rotation: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("live key changed after a failed rotation")
	}
	if _, err := os.Stat(orig.PrivateKeyPath + ".bak"); !os.IsNotExist(err) {
		t.Errorf(".bak must not exist after a generation failure; stat err = %v", err)
	}
}
