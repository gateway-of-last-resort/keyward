package config_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/config"
)

// cfgBytes is a helper that parses a raw config string in-memory.
func cfgBytes(t *testing.T, raw string) config.Config {
	t.Helper()
	return config.ParseBytes("~/.ssh/config", []byte(raw))
}

// ── ParseBytes ───────────────────────────────────────────────────────────────

func TestParseBytes_SingleHost(t *testing.T) {
	raw := `Host myserver
    HostName 192.168.1.100
    User root
    Port 22
`
	c := cfgBytes(t, raw)

	if len(c.Blocks) != 1 {
		t.Fatalf("want 1 block, got %d", len(c.Blocks))
	}
	b := c.Blocks[0]
	if b.Pattern != "myserver" {
		t.Errorf("Pattern = %q, want myserver", b.Pattern)
	}
	if b.IsMatch {
		t.Error("IsMatch should be false for Host block")
	}
}

func TestParseBytes_GlobalParams(t *testing.T) {
	raw := `ServerAliveInterval 60
ServerAliveCountMax 3

Host work
    HostName 10.0.0.1
    User admin
`
	c := cfgBytes(t, raw)

	// Global block must capture params that appear before the first Host.
	vals, ok := config.GetParam(&c.Global, "ServerAliveInterval")
	if !ok || len(vals) == 0 {
		t.Fatal("ServerAliveInterval not found in Global block")
	}
	if vals[0] != "60" {
		t.Errorf("ServerAliveInterval = %q, want 60", vals[0])
	}
}

func TestParseBytes_MultipleHosts(t *testing.T) {
	raw := `Host alpha
    HostName alpha.example.com

Host beta
    HostName beta.example.com

Host gamma
    HostName gamma.example.com
`
	c := cfgBytes(t, raw)

	if len(c.Blocks) != 3 {
		t.Fatalf("want 3 blocks, got %d", len(c.Blocks))
	}
	patterns := []string{"alpha", "beta", "gamma"}
	for i, want := range patterns {
		if c.Blocks[i].Pattern != want {
			t.Errorf("Blocks[%d].Pattern = %q, want %q", i, c.Blocks[i].Pattern, want)
		}
	}
}

// TestParseBytes_CommentsPreserved checks that comment tokens survive round-trip.
func TestParseBytes_CommentsPreserved(t *testing.T) {
	raw := `# Global comment
ServerAliveInterval 60

# This is the work server
Host work
    HostName 10.0.0.1
    # Port 22 is the default
    User admin
`
	c := cfgBytes(t, raw)

	// After serialising back, the original bytes must be identical.
	got := config.Serialize(&c)
	if !bytes.Equal(got, []byte(raw)) {
		t.Errorf("Serialize after ParseBytes changed content:\ngot:\n%s\nwant:\n%s", got, raw)
	}
}

// TestParseBytes_OnlyComments is an edge case: a valid config with no Host blocks.
func TestParseBytes_OnlyComments(t *testing.T) {
	raw := `# This file is intentionally empty
# Managed by ssh-vault
`
	c := cfgBytes(t, raw)

	if c.Blocks != nil {
		t.Errorf("want 0 blocks for comment-only config, got %d", len(c.Blocks))
	}
	// Must serialise back identically — no data loss.
	if got := config.Serialize(&c); !bytes.Equal(got, []byte(raw)) {
		t.Errorf("comment-only config changed after round-trip:\ngot:\n%s", got)
	}
}

// TestParseBytes_MatchBlockPreservedVerbatim ensures Match blocks are stored
// and written back byte-for-byte without interpretation.
func TestParseBytes_MatchBlockPreservedVerbatim(t *testing.T) {
	raw := `Host normal
    HostName example.com

Match host *.internal exec "ping -c1 %h"
    ProxyJump bastion
`
	c := cfgBytes(t, raw)

	// At least one block must be flagged as IsMatch.
	found := false
	for _, b := range c.Blocks {
		if b.IsMatch {
			found = true
			break
		}
	}
	if !found {
		t.Error("Match block not detected")
	}

	// Round-trip must be identical.
	if got := config.Serialize(&c); !bytes.Equal(got, []byte(raw)) {
		t.Errorf("Match block changed after round-trip:\ngot:\n%s", got)
	}
}

func TestParseBytes_WindowsLineEndings(t *testing.T) {
	raw := "Host win\r\n    HostName windows.local\r\n    User admin\r\n"
	c := config.ParseBytes("fake", []byte(raw))

	if len(c.Blocks) != 1 {
		t.Fatalf("want 1 block for CRLF config, got %d", len(c.Blocks))
	}
	vals, ok := config.GetParam(&c.Blocks[0], "HostName")
	if !ok || vals[0] != "windows.local" {
		t.Errorf("HostName not parsed correctly from CRLF input")
	}
}

// TestParseBytes_OriginalSnapshot verifies that Config.Original is an
// independent clone — mutating the source slice must not affect it.
func TestParseBytes_OriginalSnapshot(t *testing.T) {
	raw := []byte("Host foo\n    User bar\n")
	c := config.ParseBytes("fake", raw)

	// Mutate original slice.
	raw[0] = 'X'

	// Original in Config must still start with 'H'.
	if len(c.Original) == 0 || c.Original[0] != 'H' {
		t.Error("Config.Original was not cloned; it shares memory with the input slice")
	}
}

// ── ParseFile ────────────────────────────────────────────────────────────────

func TestParseFile_ReadsFromDisk(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")
	content := "Host prod\n    HostName prod.example.com\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	c, err := config.ParseFile(cfgPath)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if c.Path != cfgPath {
		t.Errorf("Config.Path = %q, want %q", c.Path, cfgPath)
	}
	if len(c.Blocks) != 1 {
		t.Fatalf("want 1 block, got %d", len(c.Blocks))
	}
}

func TestParseFile_ErrorOnMissingFile(t *testing.T) {
	_, err := config.ParseFile("/nonexistent/path/config")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// ── Reset ────────────────────────────────────────────────────────────────────

// TestReset_ByteIdentical is a contract test: after any edit, Reset must
// produce a Config whose Serialize output is byte-for-byte the original.
// This includes configs with Match blocks — a historically tricky edge case.
func TestReset_ByteIdentical(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "simple",
			raw:  "Host simple\n    User alice\n",
		},
		{
			name: "with_match",
			raw: `Host normal
    HostName example.com

Match host *.corp
    ProxyJump jump.corp
`,
		},
		{
			name: "only_comments",
			raw:  "# managed by ssh-vault\n# do not edit manually\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := config.ParseBytes("fake", []byte(tc.raw))
			// Simulate an edit.
			config.AddBlock(&c, "tmphost")
			// Reset.
			config.Reset(&c)

			got := config.Serialize(&c)
			if !bytes.Equal(got, []byte(tc.raw)) {
				t.Errorf("after Reset, Serialize differs from original:\ngot:\n%s\nwant:\n%s", got, tc.raw)
			}
		})
	}
}
