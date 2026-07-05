package audit_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
	"github.com/gateway-of-last-resort/keyward/internal/config"
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
