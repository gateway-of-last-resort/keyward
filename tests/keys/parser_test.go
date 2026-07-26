// Package keys_test contains black-box tests for the keys package.
// Update the import path below to match your go.mod module name.
package keys_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gateway-of-last-resort/keyward/internal/keys"
)

// ── test helpers ────────────────────────────────────────────────────────────

// writeEd25519Pair creates a real Ed25519 key pair in dir.
// If passphrase is non-nil the private key is encrypted.
func writeEd25519Pair(t *testing.T, dir, name, comment string, passphrase []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	var privBlock *pem.Block
	if len(passphrase) > 0 {
		privBlock, err = ssh.MarshalPrivateKeyWithPassphrase(priv, comment, passphrase)
	} else {
		privBlock, err = ssh.MarshalPrivateKey(priv, comment)
	}
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	// Authorised-keys format: "type base64[ comment]\n"
	pubLine := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	if comment != "" {
		pubLine += " " + comment
	}
	pubLine += "\n"

	writeFile(t, filepath.Join(dir, name), pem.EncodeToMemory(privBlock), 0600)
	writeFile(t, filepath.Join(dir, name+".pub"), []byte(pubLine), 0644)
}

// writeRSAPair creates a real RSA key pair in dir (no passphrase).
func writeRSAPair(t *testing.T, dir, name string, bits int) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(%d): %v", bits, err)
	}

	privBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal rsa private: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	writeFile(t, filepath.Join(dir, name), pem.EncodeToMemory(privBlock), 0600)
	writeFile(t, filepath.Join(dir, name+".pub"), ssh.MarshalAuthorizedKey(sshPub), 0644)
}

// writePubOnly creates only the public-key file (no private counterpart).
func writePubOnly(t *testing.T, dir, name string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	writeFile(t, filepath.Join(dir, name+".pub"), ssh.MarshalAuthorizedKey(sshPub), 0644)
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("os.WriteFile(%s): %v", path, err)
	}
}

// writeUnparseablePrivate writes a valid <name>.pub plus a <name> holding data
// that is not a usable private key, so Parse still discovers the pair but cannot
// read the private half.
func writeUnparseablePrivate(t *testing.T, dir, name string, private []byte) {
	t.Helper()
	writePubOnly(t, dir, name)
	writeFile(t, filepath.Join(dir, name), private, 0600)
}

// ── tests ───────────────────────────────────────────────────────────────────

// TestParse_PrivateHalfStates pins the three states a key's private half can be
// in, and the invariant that PrivateKeyPath and UnparsedPrivatePath are mutually
// exclusive: a set PrivateKeyPath always means a usable private key.
func TestParse_PrivateHalfStates(t *testing.T) {
	pemHeader := "-----BEGIN OPENSSH PRIVATE KEY-----\n"

	tests := []struct {
		name         string
		write        func(t *testing.T, dir string)
		wantPrivate  bool // PrivateKeyPath is set
		wantUnparsed bool // UnparsedPrivatePath is set
		wantPubOnly  bool
	}{
		{
			name:        "usable pair",
			write:       func(t *testing.T, dir string) { writeEd25519Pair(t, dir, "id_k", "c", nil) },
			wantPrivate: true,
		},
		{
			name:        "public only",
			write:       func(t *testing.T, dir string) { writePubOnly(t, dir, "id_k") },
			wantPubOnly: true,
		},
		{
			name: "junk before header",
			write: func(t *testing.T, dir string) {
				writeUnparseablePrivate(t, dir, "id_k", []byte("JUNK\n"+pemHeader))
			},
			wantUnparsed: true,
		},
		{
			name: "utf-8 bom before header",
			write: func(t *testing.T, dir string) {
				writeUnparseablePrivate(t, dir, "id_k", append([]byte{0xEF, 0xBB, 0xBF}, pemHeader...))
			},
			wantUnparsed: true,
		},
		{
			name: "empty private file",
			write: func(t *testing.T, dir string) {
				writeUnparseablePrivate(t, dir, "id_k", nil)
			},
			wantUnparsed: true,
		},
		{
			name: "unreadable private file",
			write: func(t *testing.T, dir string) {
				if runtime.GOOS == "windows" {
					t.Skip("permission bits are synthesized on Windows")
				}
				if os.Geteuid() == 0 {
					t.Skip("root ignores the read bit")
				}
				writeUnparseablePrivate(t, dir, "id_k", []byte(pemHeader))
				if err := os.Chmod(filepath.Join(dir, "id_k"), 0000); err != nil {
					t.Fatal(err)
				}
			},
			wantUnparsed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.write(t, dir)

			got, err := keys.Parse(dir)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("Parse found %d keys, want 1", len(got))
			}
			k := got[0]

			if (k.PrivateKeyPath != "") != tt.wantPrivate {
				t.Errorf("PrivateKeyPath = %q, want set: %v", k.PrivateKeyPath, tt.wantPrivate)
			}
			if (k.UnparsedPrivatePath != "") != tt.wantUnparsed {
				t.Errorf("UnparsedPrivatePath = %q, want set: %v", k.UnparsedPrivatePath, tt.wantUnparsed)
			}
			if k.PrivateKeyPath != "" && k.UnparsedPrivatePath != "" {
				t.Error("both private path fields set; they must be mutually exclusive")
			}
			if k.IsPublicOnly != tt.wantPubOnly {
				t.Errorf("IsPublicOnly = %v, want %v", k.IsPublicOnly, tt.wantPubOnly)
			}
			if k.PublicKeyPath == "" {
				t.Error("PublicKeyPath is empty; the pair should have been discovered via the .pub")
			}

			wantIdentity := filepath.Join(dir, "id_k")
			if tt.wantPubOnly {
				wantIdentity += ".pub"
			}
			if k.IdentityPath() != wantIdentity {
				t.Errorf("IdentityPath() = %q, want %q", k.IdentityPath(), wantIdentity)
			}
		})
	}
}

// TestParse_OrderIsDeterministic guards the sort key: keys without a usable
// private path used to compare equal, so their order followed Go's map iteration
// and varied between runs.
func TestParse_OrderIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	writePubOnly(t, dir, "id_a")
	writePubOnly(t, dir, "id_b")
	writePubOnly(t, dir, "id_c")
	writeUnparseablePrivate(t, dir, "id_d", []byte("JUNK\n"))
	writeEd25519Pair(t, dir, "id_e", "c", nil)

	var first []string
	for i := range 5 {
		got, err := keys.Parse(dir)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		paths := make([]string, len(got))
		for j, k := range got {
			paths[j] = k.IdentityPath()
		}
		if i == 0 {
			first = paths
			if !slices.IsSorted(paths) {
				t.Errorf("Parse order is not ascending: %v", paths)
			}
			continue
		}
		if !slices.Equal(paths, first) {
			t.Fatalf("run %d order = %v, want %v", i, paths, first)
		}
	}
}

func TestParse_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	got, err := keys.Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 keys, got %d", len(got))
	}
}

func TestParse_IgnoresNonKeyFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "known_hosts"), []byte("github.com ssh-ed25519 AAAA..."), 0644)
	writeFile(t, filepath.Join(dir, "config"), []byte("Host *\n  ServerAliveInterval 60\n"), 0644)
	writeFile(t, filepath.Join(dir, "README.md"), []byte("# keys\n"), 0644)

	got, err := keys.Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 keys for non-key files, got %d", len(got))
	}
}

func TestParse_FullPair_Ed25519(t *testing.T) {
	dir := t.TempDir()
	writeEd25519Pair(t, dir, "id_ed25519", "", nil)

	got, err := keys.Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 key, got %d", len(got))
	}
	k := got[0]

	if k.Algorithm != "ssh-ed25519" {
		t.Errorf("Algorithm = %q, want ssh-ed25519", k.Algorithm)
	}
	if k.BitSize != 256 {
		t.Errorf("BitSize = %d, want 256", k.BitSize)
	}
	if k.HasPassphrase {
		t.Error("HasPassphrase should be false for unencrypted key")
	}
	if k.IsPublicOnly {
		t.Error("IsPublicOnly should be false for full pair")
	}
	if k.Fingerprint == "" {
		t.Error("Fingerprint should not be empty")
	}
	if k.PrivateKeyPath == "" {
		t.Error("PrivateKeyPath should not be empty")
	}
	if k.PublicKeyPath == "" {
		t.Error("PublicKeyPath should not be empty")
	}
}

func TestParse_FullPair_RSA_BitSize(t *testing.T) {
	dir := t.TempDir()
	writeRSAPair(t, dir, "id_rsa", 2048)

	got, err := keys.Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 key, got %d", len(got))
	}
	k := got[0]

	if k.BitSize != 2048 {
		t.Errorf("BitSize = %d, want 2048", k.BitSize)
	}
	if k.Algorithm != "ssh-rsa" {
		t.Errorf("Algorithm = %q, want ssh-rsa", k.Algorithm)
	}
	if k.HasPassphrase {
		t.Error("HasPassphrase should be false")
	}
}

func TestParse_WithPassphrase(t *testing.T) {
	dir := t.TempDir()
	writeEd25519Pair(t, dir, "id_protected", "", []byte("hunter2"))

	got, err := keys.Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 key, got %d", len(got))
	}
	k := got[0]

	if !k.HasPassphrase {
		t.Error("HasPassphrase should be true for encrypted key")
	}
	// Algorithm and Fingerprint must come from .pub when private is encrypted.
	if k.Algorithm == "" {
		t.Error("Algorithm should be populated from .pub even when private is encrypted")
	}
	if k.Fingerprint == "" {
		t.Error("Fingerprint should be populated from .pub even when private is encrypted")
	}
}

func TestParse_PublicOnly(t *testing.T) {
	dir := t.TempDir()
	writePubOnly(t, dir, "id_remote")

	got, err := keys.Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 key, got %d", len(got))
	}
	k := got[0]

	if !k.IsPublicOnly {
		t.Error("IsPublicOnly should be true when no private key file exists")
	}
	if k.PrivateKeyPath != "" {
		t.Errorf("PrivateKeyPath = %q, want empty for pub-only entry", k.PrivateKeyPath)
	}
	if k.PublicKeyPath == "" {
		t.Error("PublicKeyPath should not be empty for pub-only entry")
	}
}

func TestParse_Comment(t *testing.T) {
	dir := t.TempDir()
	const want = "ivan@laptop"
	writeEd25519Pair(t, dir, "id_ed25519", want, nil)

	got, err := keys.Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 key, got %d", len(got))
	}
	if got[0].Comment != want {
		t.Errorf("Comment = %q, want %q", got[0].Comment, want)
	}
}

// TestParse_ModifiedAt verifies that ModifiedAt reflects mtime, not birthtime.
// The field must never be named CreatedAt — this test enforces the contract.
func TestParse_ModifiedAt_IsMtime(t *testing.T) {
	dir := t.TempDir()
	writeEd25519Pair(t, dir, "id_ed25519", "", nil)

	info, err := os.Stat(filepath.Join(dir, "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	mtime := info.ModTime().UTC().Truncate(time.Second)

	got, err := keys.Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 key, got %d", len(got))
	}

	gotTime := got[0].ModifiedAt.UTC().Truncate(time.Second)
	if !gotTime.Equal(mtime) {
		t.Errorf("ModifiedAt = %v, want mtime %v", gotTime, mtime)
	}
}

func TestParse_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod semantics differ on Windows")
	}

	dir := t.TempDir()
	writeEd25519Pair(t, dir, "id_ed25519", "", nil)

	got, err := keys.Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 key, got %d", len(got))
	}
	k := got[0]

	if k.PrivatePerm != 0600 {
		t.Errorf("PrivatePerm = %04o, want 0600", k.PrivatePerm)
	}
	if k.PublicPerm != 0644 {
		t.Errorf("PublicPerm = %04o, want 0644", k.PublicPerm)
	}
}

func TestParse_MultipleKeys(t *testing.T) {
	dir := t.TempDir()
	writeEd25519Pair(t, dir, "id_ed25519", "", nil)
	writeRSAPair(t, dir, "id_rsa", 2048)
	writePubOnly(t, dir, "id_remote")

	got, err := keys.Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 keys, got %d", len(got))
	}
}

// TestParse_Paths verifies that key paths point to actual files inside dir.
func TestParse_Paths(t *testing.T) {
	dir := t.TempDir()
	writeEd25519Pair(t, dir, "id_ed25519", "", nil)

	got, err := keys.Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	k := got[0]

	wantPriv := filepath.Join(dir, "id_ed25519")
	wantPub := filepath.Join(dir, "id_ed25519.pub")

	if k.PrivateKeyPath != wantPriv {
		t.Errorf("PrivateKeyPath = %q, want %q", k.PrivateKeyPath, wantPriv)
	}
	if k.PublicKeyPath != wantPub {
		t.Errorf("PublicKeyPath = %q, want %q", k.PublicKeyPath, wantPub)
	}
}
