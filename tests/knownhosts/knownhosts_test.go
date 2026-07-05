package knownhosts_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/gateway-of-last-resort/keyward/internal/knownhosts"
)

// authorizedKey generates a fresh ed25519 public key and returns its
// "ssh-ed25519 AAAA…" authorized-key form (no trailing newline).
func authorizedKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// hashedHost returns a syntactically valid |1|salt|hash host token.
func hashedHost() string {
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdefghij"))
	hash := base64.StdEncoding.EncodeToString([]byte("jihgfedcba9876543210"))
	return "|1|" + salt + "|" + hash
}

// writeKnownHosts writes lines (joined with "\n", trailing newline) to a temp
// known_hosts file with mode 0640 and returns its path.
func writeKnownHosts(t *testing.T, lines []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return path
}

func TestParse_PlainHashedRevoked(t *testing.T) {
	k1 := authorizedKey(t)
	k2 := authorizedKey(t)
	k3 := authorizedKey(t)

	lines := []string{
		"# a comment line",
		"github.com,140.82.112.3 " + k1 + " user@host",
		hashedHost() + " " + k2,
		"@revoked badhost.example " + k3,
		"", // trailing blank
	}
	path := writeKnownHosts(t, lines)

	entries, err := knownhosts.Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}

	// Plain entry with multiple hosts.
	plain := entries[0]
	if plain.Hashed {
		t.Errorf("plain entry marked hashed")
	}
	if len(plain.Hosts) != 2 || plain.Hosts[0] != "github.com" {
		t.Errorf("hosts = %v, want [github.com 140.82.112.3]", plain.Hosts)
	}
	if plain.KeyType != "ssh-ed25519" {
		t.Errorf("KeyType = %q, want ssh-ed25519", plain.KeyType)
	}
	if !strings.HasPrefix(plain.Fingerprint, "SHA256:") {
		t.Errorf("Fingerprint = %q, want SHA256: prefix", plain.Fingerprint)
	}
	if plain.Comment != "user@host" {
		t.Errorf("Comment = %q, want user@host", plain.Comment)
	}
	if plain.LineNum != 2 {
		t.Errorf("LineNum = %d, want 2", plain.LineNum)
	}

	// Hashed entry.
	if !entries[1].Hashed {
		t.Errorf("hashed entry not marked hashed: %v", entries[1].Hosts)
	}
	if entries[1].LineNum != 3 {
		t.Errorf("hashed LineNum = %d, want 3", entries[1].LineNum)
	}

	// Revoked marker.
	if entries[2].Marker != "revoked" {
		t.Errorf("Marker = %q, want revoked", entries[2].Marker)
	}
	if entries[2].LineNum != 4 {
		t.Errorf("revoked LineNum = %d, want 4", entries[2].LineNum)
	}
}

func TestParse_MissingFileIsEmpty(t *testing.T) {
	entries, err := knownhosts.Parse(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("Parse missing file: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("got %d entries, want 0", len(entries))
	}
}

func TestForget_RemovesOnlyTargetLine(t *testing.T) {
	k1 := authorizedKey(t)
	k2 := authorizedKey(t)
	k3 := authorizedKey(t)

	lines := []string{
		"host1.example " + k1,
		"host2.example " + k2,
		"host3.example " + k3,
	}
	path := writeKnownHosts(t, lines)

	// Forget the middle entry (line 2).
	if err := knownhosts.Forget(path, 2); err != nil {
		t.Fatalf("Forget: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after Forget: %v", err)
	}
	want := lines[0] + "\n" + lines[2] + "\n"
	if string(got) != want {
		t.Fatalf("file after Forget:\n%q\nwant:\n%q", got, want)
	}

	// Neighbours still parse and line 2 is gone.
	entries, err := knownhosts.Parse(path)
	if err != nil {
		t.Fatalf("Parse after Forget: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Hosts[0] != "host1.example" || entries[1].Hosts[0] != "host3.example" {
		t.Errorf("surviving hosts = %v, %v", entries[0].Hosts, entries[1].Hosts)
	}
}

func TestForget_PreservesMode(t *testing.T) {
	k1 := authorizedKey(t)
	k2 := authorizedKey(t)
	path := writeKnownHosts(t, []string{"a.example " + k1, "b.example " + k2})

	if err := knownhosts.Forget(path, 1); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("mode = %o, want 640", got)
	}
}

func TestForget_Errors(t *testing.T) {
	k1 := authorizedKey(t)
	path := writeKnownHosts(t, []string{"a.example " + k1})

	if err := knownhosts.Forget(path, 99); !errors.Is(err, knownhosts.ErrLineOutOfRange) {
		t.Errorf("Forget out-of-range = %v, want ErrLineOutOfRange", err)
	}
	missing := filepath.Join(t.TempDir(), "nope")
	if err := knownhosts.Forget(missing, 1); !errors.Is(err, knownhosts.ErrFileNotFound) {
		t.Errorf("Forget missing = %v, want ErrFileNotFound", err)
	}
}
