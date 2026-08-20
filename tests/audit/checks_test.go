package audit_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
	"github.com/gateway-of-last-resort/keyward/internal/config"
	"github.com/gateway-of-last-resort/keyward/internal/keys"
)

// runConfigAudit runs the audit against a parsed config (no keys) rooted at
// sshDir and returns the finding messages.
func runConfigAudit(t *testing.T, cfgText, sshDir string) []audit.AuditResult {
	t.Helper()
	c := config.ParseBytes("config", []byte(cfgText))
	return audit.Run(nil, &c, sshDir).Results
}

func hasMessage(results []audit.AuditResult, substr string) (audit.Severity, bool) {
	for _, r := range results {
		if strings.Contains(r.Message, substr) {
			return r.Severity, true
		}
	}
	return "", false
}

// TestCheckPermissions_UnparseablePrivateKey pins that a private file which is
// present but cannot be parsed yields exactly one finding, and that the finding
// carries a path.
//
// Regression: keys.Parse leaves PrivateKeyPath empty for such a file while
// IsPublicOnly stays false (the file does exist), so checkPermissions used to
// call os.Stat("") and append a second "Private key does not exist or damaged"
// warning with no KeyPath, which the CLI rendered as a bare "key:".
func TestCheckPermissions_UnparseablePrivateKey(t *testing.T) {
	dir := t.TempDir()

	// A valid .pub so the pair is discovered at all, plus a private half with
	// junk ahead of the PEM header so it cannot be parsed.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_junk.pub"), ssh.MarshalAuthorizedKey(sshPub), 0600); err != nil {
		t.Fatal(err)
	}
	junk := "JUNK BEFORE HEADER\n-----BEGIN OPENSSH PRIVATE KEY-----\nnot base64\n"
	if err := os.WriteFile(filepath.Join(dir, "id_junk"), []byte(junk), 0600); err != nil {
		t.Fatal(err)
	}

	ks, err := keys.Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	results := audit.Run(ks, nil, dir).Results

	if _, found := hasMessage(results, "not recognized"); !found {
		t.Error("want the unparseable private key reported as not recognized")
	}
	if _, found := hasMessage(results, "Private key does not exist or damaged"); found {
		t.Error("unparseable private key must not also be reported as missing or damaged")
	}
	for _, r := range results {
		if r.Category == audit.CategoryKey && r.KeyPath == "" {
			t.Errorf("key finding has no KeyPath: %q", r.Message)
		}
	}
}

// TestCheckKeyLinkedToHost_UnparseablePrivate pins a behaviour change that came
// with filing findings under the private file: IdentityFile names the private
// key, so a key whose private half is unparseable can now be matched to a host.
// Before, it was resolved to its .pub and therefore always reported unlinked.
func TestCheckKeyLinkedToHost_UnparseablePrivate(t *testing.T) {
	tests := []struct {
		name       string
		cfg        string
		wantLinked bool
	}{
		{
			name:       "referenced by IdentityFile",
			cfg:        "Host h\n    IdentityFile %s\n",
			wantLinked: true,
		},
		{
			name: "not referenced",
			cfg:  "Host h\n    HostName example.com\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			priv := filepath.Join(dir, "id_junk")
			if err := os.WriteFile(priv, []byte("JUNK\n"), 0600); err != nil {
				t.Fatal(err)
			}
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			sshPub, err := ssh.NewPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(priv+".pub", ssh.MarshalAuthorizedKey(sshPub), 0600); err != nil {
				t.Fatal(err)
			}

			ks, err := keys.Parse(dir)
			if err != nil {
				t.Fatal(err)
			}
			if ks[0].UnparsedPrivatePath == "" {
				t.Fatal("fixture did not produce an unparseable private half")
			}

			c := config.ParseBytes("config", []byte(strings.Replace(tt.cfg, "%s", priv, 1)))
			results := audit.Run(ks, &c, dir).Results

			_, unlinked := hasMessage(results, "key not linked to any host")
			if unlinked == tt.wantLinked {
				t.Errorf("unlinked finding present = %v, want %v", unlinked, !tt.wantLinked)
			}
		})
	}
}

// TestIdentityFileInGlobalBlock covers an IdentityFile declared before the first
// Host, which applies to every host: the key it names must count as linked, and
// a global path that does not exist must still be reported. Both checks used to
// walk cfg.Blocks only, so a globally declared key was reported unlinked and a
// missing one went unnoticed.
func TestIdentityFileInGlobalBlock(t *testing.T) {
	t.Run("key is linked", func(t *testing.T) {
		dir := t.TempDir()
		// An unparseable private half is enough here: the key is still
		// discovered, is not public-only, and resolves to the private file.
		priv := filepath.Join(dir, "id_global")
		if err := os.WriteFile(priv, []byte("JUNK\n"), 0600); err != nil {
			t.Fatal(err)
		}
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(priv+".pub", ssh.MarshalAuthorizedKey(sshPub), 0600); err != nil {
			t.Fatal(err)
		}

		ks, err := keys.Parse(dir)
		if err != nil {
			t.Fatal(err)
		}
		c := config.ParseBytes("config", []byte("IdentityFile "+priv+"\n\nHost h\n    HostName example.com\n"))
		results := audit.Run(ks, &c, dir).Results

		if _, unlinked := hasMessage(results, "key not linked to any host"); unlinked {
			t.Error("a key named by a global IdentityFile must count as linked")
		}
	})

	t.Run("missing path is reported", func(t *testing.T) {
		dir := t.TempDir()
		cfg := "IdentityFile " + filepath.Join(dir, "absent") + "\n\nHost h\n"

		sev, found := hasMessage(runConfigAudit(t, cfg, dir), "Identity file does not exist")
		if !found {
			t.Fatal("expected a finding for a missing global IdentityFile")
		}
		if sev != audit.Warning {
			t.Errorf("severity = %s, want WARNING", sev)
		}
	})
}

func TestCheckForwardAgent(t *testing.T) {
	dir := t.TempDir()

	sev, found := hasMessage(runConfigAudit(t, "Host bastion\n    ForwardAgent yes\n", dir), "ForwardAgent is enabled")
	if !found {
		t.Fatal("expected ForwardAgent finding")
	}
	if sev != audit.Warning {
		t.Errorf("severity = %s, want WARNING", sev)
	}

	if _, found := hasMessage(runConfigAudit(t, "Host bastion\n    ForwardAgent no\n", dir), "ForwardAgent is enabled"); found {
		t.Error("ForwardAgent no should not be flagged")
	}
}

func TestCheckUserKnownHostsDevNull(t *testing.T) {
	dir := t.TempDir()

	sev, found := hasMessage(runConfigAudit(t, "Host x\n    UserKnownHostsFile /dev/null\n", dir), "UserKnownHostsFile is /dev/null")
	if !found {
		t.Fatal("expected /dev/null finding")
	}
	if sev != audit.Critical {
		t.Errorf("severity = %s, want CRITICAL", sev)
	}

	if _, found := hasMessage(runConfigAudit(t, "Host x\n    UserKnownHostsFile ~/.ssh/known_hosts\n", dir), "UserKnownHostsFile is /dev/null"); found {
		t.Error("a normal known_hosts path should not be flagged")
	}
}

// TestPlatformPermissionModel checks the consolidated Windows behaviour: where
// POSIX permission bits aren't enforceable the audit emits exactly one Info
// describing the ACL model, and on POSIX platforms that Info is absent (the real
// 0600/0700/0o077 checks run instead).
func TestPlatformPermissionModel(t *testing.T) {
	dir := t.TempDir()

	sev, found := hasMessage(runConfigAudit(t, "Host x\n", dir), "NTFS ACLs")
	if runtime.GOOS == "windows" {
		if !found {
			t.Fatal("expected the Windows permission-model Info")
		}
		if sev != audit.Info {
			t.Errorf("severity = %s, want INFO", sev)
		}
	} else if found {
		t.Error("permission-model Info must not appear on POSIX platforms")
	}
}

// TestCheckUserKnownHostsDevNull_MultiValueAndQuoted covers the bypass fix: a
// /dev/null listed among several paths, or quoted, must still be flagged, while a
// genuine path is not.
func TestCheckUserKnownHostsDevNull_MultiValueAndQuoted(t *testing.T) {
	dir := t.TempDir()
	for _, cfg := range []string{
		"Host x\n    UserKnownHostsFile /dev/null ~/.ssh/known_hosts\n",
		"Host x\n    UserKnownHostsFile \"/dev/null\"\n",
	} {
		sev, found := hasMessage(runConfigAudit(t, cfg, dir), "UserKnownHostsFile is /dev/null")
		if !found {
			t.Errorf("%q: /dev/null not detected", cfg)
		} else if sev != audit.Critical {
			t.Errorf("%q: severity = %s, want CRITICAL", cfg, sev)
		}
	}
	if _, found := hasMessage(runConfigAudit(t, "Host x\n    UserKnownHostsFile ~/.ssh/known_hosts\n", dir), "UserKnownHostsFile is /dev/null"); found {
		t.Error("a genuine known_hosts path must not be flagged")
	}
}

func TestCheckConfigPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")
	if err := os.WriteFile(cfgPath, []byte("Host x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sev, found := hasMessage(runConfigAudit(t, "Host x\n", dir), "SSH config is accessible by group/others")
	if !found {
		t.Fatal("expected config-permissions finding for 0644 config")
	}
	if sev != audit.Warning {
		t.Errorf("severity = %s, want WARNING", sev)
	}

	// Tightening to 0600 clears it.
	if err := os.Chmod(cfgPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, found := hasMessage(runConfigAudit(t, "Host x\n", dir), "SSH config is accessible by group/others"); found {
		t.Error("0600 config should not be flagged")
	}
}
