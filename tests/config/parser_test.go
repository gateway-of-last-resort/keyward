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

// TestParseBytes_EqualsSeparator covers ssh_config(5)'s "keyword = argument"
// form (optional whitespace around '='): the value must not keep the '=', and the
// line must still round-trip byte-identically (it was not edited).
func TestParseBytes_EqualsSeparator(t *testing.T) {
	for _, raw := range []string{
		"Host web\n    Port=2222\n",
		"Host web\n    Port =2222\n",
		"Host web\n    Port = 2222\n",
		"Host web\n\tPort\t=\t2222\n",
	} {
		c := cfgBytes(t, raw)
		if len(c.Blocks) != 1 {
			t.Fatalf("%q: want 1 block, got %d", raw, len(c.Blocks))
		}
		vals, ok := config.GetParam(&c.Blocks[0], "Port")
		if !ok || len(vals) == 0 || vals[0] != "2222" {
			t.Errorf("%q: Port = %q (ok=%v), want [\"2222\"]", raw, vals, ok)
		}
		if got := config.Serialize(&c); !bytes.Equal(got, []byte(raw)) {
			t.Errorf("%q: round-trip changed bytes:\n%q", raw, got)
		}
	}
}

// TestParseBytes_HostEqualsPattern checks that "Host=pattern" (no space) starts a
// block, not a stray param glued onto the previous one.
func TestParseBytes_HostEqualsPattern(t *testing.T) {
	c := cfgBytes(t, "Host=example\n    User root\n")
	if len(c.Blocks) != 1 {
		t.Fatalf("Host=example: want 1 block, got %d", len(c.Blocks))
	}
	if c.Blocks[0].Pattern != "example" {
		t.Errorf("Pattern = %q, want example", c.Blocks[0].Pattern)
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

// TestParseBytes_TabSeparators verifies that ssh_config's tab separator is
// honoured everywhere a space is: on the Host/Match keyword line and between a
// param key and its value. Before the fix, "Host\tgithub.com" fell through to
// parseParam and no block was created, silently merging following directives
// into the previous block.
func TestParseBytes_TabSeparators(t *testing.T) {
	raw := "Host\tgithub.com\n\tHostName\tgithub.com\n\tUser\tgit\n"
	c := cfgBytes(t, raw)

	if len(c.Blocks) != 1 {
		t.Fatalf("want 1 block for tab-separated Host, got %d", len(c.Blocks))
	}
	b := c.Blocks[0]
	if b.Pattern != "github.com" {
		t.Errorf("Pattern = %q, want github.com", b.Pattern)
	}
	if b.IsMatch {
		t.Error("IsMatch should be false for a Host block")
	}

	// Tab-separated params must be parsed into key/value, not one blob.
	vals, ok := config.GetParam(&b, "HostName")
	if !ok || len(vals) == 0 || vals[0] != "github.com" {
		t.Errorf("GetParam(HostName) = %v, %v; want [github.com], true", vals, ok)
	}
	vals, ok = config.GetParam(&b, "User")
	if !ok || len(vals) == 0 || vals[0] != "git" {
		t.Errorf("GetParam(User) = %v, %v; want [git], true", vals, ok)
	}

	// FindBlock must locate the tab-separated host.
	if fb := config.FindBlock(&c, "github.com"); fb == nil {
		t.Error("FindBlock(github.com) = nil for tab-separated Host")
	}

	// Round-trip must remain byte-identical (Raw preserves the tabs).
	if got := config.Serialize(&c); !bytes.Equal(got, []byte(raw)) {
		t.Errorf("tab-separated config changed after round-trip:\ngot:\n%q\nwant:\n%q", got, raw)
	}
}

// TestParseBytes_TabSeparatedMatch mirrors the above for Match blocks.
func TestParseBytes_TabSeparatedMatch(t *testing.T) {
	raw := "Match\thost *.internal\n\tProxyJump bastion\n"
	c := cfgBytes(t, raw)

	if len(c.Blocks) != 1 {
		t.Fatalf("want 1 block for tab-separated Match, got %d", len(c.Blocks))
	}
	if !c.Blocks[0].IsMatch {
		t.Error("tab-separated Match not detected as IsMatch")
	}
	if got := config.Serialize(&c); !bytes.Equal(got, []byte(raw)) {
		t.Errorf("tab-separated Match changed after round-trip:\ngot:\n%q", got)
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
