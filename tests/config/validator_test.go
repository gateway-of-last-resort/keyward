package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/config"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// hasError returns true if any ValidationResult has the given level and field.
func hasResult(results []config.ValidationResult, level config.ValidationLevel, field string) bool {
	for _, r := range results {
		if r.Level == level && r.Field == field {
			return true
		}
	}
	return false
}

// blockWithParam builds a one-host Config and returns a pointer to its block.
func blockWithParam(t *testing.T, params ...string) *config.Block {
	t.Helper()
	if len(params)%2 != 0 {
		t.Fatal("blockWithParam: params must be key-value pairs")
	}
	raw := "Host test\n"
	for i := 0; i < len(params); i += 2 {
		raw += "    " + params[i] + " " + params[i+1] + "\n"
	}
	c := config.ParseBytes("fake", []byte(raw))
	return &c.Blocks[0]
}

// ── ValidateBlock — Port ──────────────────────────────────────────────────────

func TestValidateBlock_Port_Valid(t *testing.T) {
	b := blockWithParam(t, "Port", "22")

	results := config.ValidateBlock(b)
	if hasResult(results, config.LevelError, "Port") {
		t.Error("valid Port 22 should not produce an error")
	}
}

func TestValidateBlock_Port_Zero(t *testing.T) {
	b := blockWithParam(t, "Port", "0")

	results := config.ValidateBlock(b)
	if !hasResult(results, config.LevelError, "Port") {
		t.Error("Port 0 should produce LevelError")
	}
}

func TestValidateBlock_Port_TooLarge(t *testing.T) {
	b := blockWithParam(t, "Port", "99999")

	results := config.ValidateBlock(b)
	if !hasResult(results, config.LevelError, "Port") {
		t.Error("Port 99999 should produce LevelError")
	}
}

func TestValidateBlock_Port_NotNumeric(t *testing.T) {
	b := blockWithParam(t, "Port", "ssh")

	results := config.ValidateBlock(b)
	if !hasResult(results, config.LevelError, "Port") {
		t.Error("non-numeric Port should produce LevelError")
	}
}

// ── ValidateBlock — IdentityFile ─────────────────────────────────────────────

func TestValidateBlock_IdentityFile_Missing(t *testing.T) {
	b := blockWithParam(t, "IdentityFile", "/nonexistent/path/id_ed25519")

	results := config.ValidateBlock(b)
	if !hasResult(results, config.LevelWarning, "IdentityFile") {
		t.Error("non-existent IdentityFile should produce LevelWarning")
	}
}

func TestValidateBlock_IdentityFile_WrongPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod semantics differ on Windows")
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("placeholder"), 0644); err != nil { // wrong perms
		t.Fatal(err)
	}

	b := blockWithParam(t, "IdentityFile", keyPath)

	results := config.ValidateBlock(b)
	if !hasResult(results, config.LevelWarning, "IdentityFile") {
		t.Error("IdentityFile with perms 0644 (not 0600) should produce LevelWarning")
	}
}

func TestValidateBlock_IdentityFile_CorrectPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod semantics differ on Windows")
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("placeholder"), 0600); err != nil {
		t.Fatal(err)
	}

	b := blockWithParam(t, "IdentityFile", keyPath)

	results := config.ValidateBlock(b)
	if hasResult(results, config.LevelWarning, "IdentityFile") {
		t.Error("IdentityFile with correct 0600 perms should not warn")
	}
}

// ── ValidateBlock — ForwardAgent ─────────────────────────────────────────────

func TestValidateBlock_ForwardAgent_Invalid(t *testing.T) {
	b := blockWithParam(t, "ForwardAgent", "maybe")

	results := config.ValidateBlock(b)
	if !hasResult(results, config.LevelWarning, "ForwardAgent") {
		t.Error("ForwardAgent=maybe should produce LevelWarning")
	}
}

func TestValidateBlock_ForwardAgent_Valid(t *testing.T) {
	for _, v := range []string{"yes", "no", "ask"} {
		b := blockWithParam(t, "ForwardAgent", v)
		results := config.ValidateBlock(b)
		if hasResult(results, config.LevelWarning, "ForwardAgent") {
			t.Errorf("ForwardAgent=%q should not produce a warning", v)
		}
	}
}

// ── ValidateBlock — StrictHostKeyChecking ────────────────────────────────────

func TestValidateBlock_StrictHostKeyChecking_Invalid(t *testing.T) {
	b := blockWithParam(t, "StrictHostKeyChecking", "off")

	results := config.ValidateBlock(b)
	if !hasResult(results, config.LevelWarning, "StrictHostKeyChecking") {
		t.Error("StrictHostKeyChecking=off should produce LevelWarning")
	}
}

func TestValidateBlock_StrictHostKeyChecking_Valid(t *testing.T) {
	for _, v := range []string{"yes", "no", "ask", "accept-new"} {
		b := blockWithParam(t, "StrictHostKeyChecking", v)
		results := config.ValidateBlock(b)
		if hasResult(results, config.LevelWarning, "StrictHostKeyChecking") {
			t.Errorf("StrictHostKeyChecking=%q should not produce a warning", v)
		}
	}
}

// ── ValidateBlock — User ─────────────────────────────────────────────────────

func TestValidateBlock_User_Empty(t *testing.T) {
	b := blockWithParam(t, "User", "   ") // whitespace-only

	results := config.ValidateBlock(b)
	if !hasResult(results, config.LevelError, "User") {
		t.Error("empty/whitespace User should produce LevelError")
	}
}

// ── ValidateConfig — duplicates ───────────────────────────────────────────────

func TestValidateConfig_DuplicateHost_Error(t *testing.T) {
	raw := `Host dupe
    HostName first.example.com

Host dupe
    HostName second.example.com
`
	c := config.ParseBytes("fake", []byte(raw))

	results := config.ValidateConfig(&c)
	if !hasResult(results, config.LevelError, "Host") {
		t.Error("duplicate Host pattern should produce LevelError")
	}
}

func TestValidateConfig_NoDuplicates_Clean(t *testing.T) {
	c := threeHostConfig(t) // alpha, beta, gamma — all unique

	results := config.ValidateConfig(&c)
	if hasResult(results, config.LevelError, "Host") {
		t.Error("unique Host patterns should not produce duplicate errors")
	}
}

// ── ValidateConfig — StrictHostKeyChecking in global / Host * ────────────────

// TestValidateConfig_StrictHostKeyChecking_Global_Error covers the security-
// critical case: StrictHostKeyChecking no in the global block or Host * is a
// critical misconfiguration that affects ALL hosts.
func TestValidateConfig_StrictHostKeyChecking_Global_Error(t *testing.T) {
	raw := `StrictHostKeyChecking no

Host myserver
    HostName example.com
`
	c := config.ParseBytes("fake", []byte(raw))

	results := config.ValidateConfig(&c)
	if !hasResult(results, config.LevelError, "StrictHostKeyChecking") {
		t.Error("StrictHostKeyChecking no in global block should produce LevelError")
	}
}

func TestValidateConfig_StrictHostKeyChecking_HostStar_Error(t *testing.T) {
	raw := `Host *
    StrictHostKeyChecking no
`
	c := config.ParseBytes("fake", []byte(raw))

	results := config.ValidateConfig(&c)
	if !hasResult(results, config.LevelError, "StrictHostKeyChecking") {
		t.Error("StrictHostKeyChecking no in Host * should produce LevelError")
	}
}

// ── ValidateConfig delegates to ValidateBlock ─────────────────────────────────

func TestValidateConfig_DelegatesBlockValidation(t *testing.T) {
	raw := `Host bad
    Port 99999
`
	c := config.ParseBytes("fake", []byte(raw))

	results := config.ValidateConfig(&c)
	if !hasResult(results, config.LevelError, "Port") {
		t.Error("ValidateConfig should delegate to ValidateBlock and surface Port error")
	}
}
