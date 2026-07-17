package config_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

// TestParseBytes_MixedLineEndings checks that a file mixing CRLF and LF lines
// round-trips byte-for-byte, rather than being force-converted to one style.
func TestParseBytes_MixedLineEndings(t *testing.T) {
	for _, raw := range []string{
		"Host a\r\n    User x\nHost b\n", // mixed
		"Host a\r\n    User root\r\n",    // all CRLF
		"Host a\n    User root\n",        // all LF
	} {
		c := cfgBytes(t, raw)
		if got := config.Serialize(&c); !bytes.Equal(got, []byte(raw)) {
			t.Errorf("round-trip changed line endings:\n in: %q\nout: %q", raw, got)
		}
	}
}

// TestRenameHost_MatchBlock guards against silent divergence: renaming a Match
// block must rewrite the on-disk Match line, not only b.Pattern in memory.
func TestRenameHost_MatchBlock(t *testing.T) {
	c := cfgBytes(t, "Match host *.corp\n    User root\n")
	config.RenameHost(&c.Blocks[0], "host *.example")
	out := string(config.Serialize(&c))
	if c.Blocks[0].Pattern != "host *.example" {
		t.Fatalf("Pattern = %q, want %q", c.Blocks[0].Pattern, "host *.example")
	}
	if !strings.Contains(out, "Match host *.example") {
		t.Errorf("serialized config did not follow the rename:\n%s", out)
	}
	if strings.Contains(out, "*.corp") {
		t.Errorf("old Match pattern still present after rename:\n%s", out)
	}
}

// TestKeywords_ExtendedRecognised confirms the parser recognises common keywords
// that were missing, so they can be added and their commented form toggled.
func TestKeywords_ExtendedRecognised(t *testing.T) {
	for _, kw := range []string{"IdentitiesOnly", "CertificateFile", "Include", "GatewayPorts", "PKCS11Provider"} {
		if !config.IsValidSSHKeyword(kw) {
			t.Errorf("keyword %q should be recognised", kw)
		}
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

// blockOf returns the index of the block whose tokens contain the raw line, or
// -1. Comment attribution is about which block owns a line, so the tests below
// assert on ownership rather than on the serialised bytes (which are identical
// either way — every grouping writes the same tokens in the same order).
func blockOf(c config.Config, rawLine string) int {
	for i := range c.Blocks {
		for _, tk := range c.Blocks[i].Tokens {
			if tk.Raw == rawLine {
				return i
			}
		}
	}
	return -1
}

// TestParseBytes_CommentAttribution pins which block owns a comment sitting
// between two blocks. A run of comments directly above a Host — no blank line
// in between — describes that Host and opens its block. Anything cut off from
// the Host by a blank line trails the block above instead. Before this, every
// pending comment was flushed into the following block, so a commented-out
// param at the end of one Host surfaced under the next one.
func TestParseBytes_CommentAttribution(t *testing.T) {
	raw := `# file header

Host vpn
    User ubuntu
#    Port 22

# describes pi4
Host pi4
    User pi
`
	c := cfgBytes(t, raw)

	if len(c.Blocks) != 2 {
		t.Fatalf("want 2 blocks, got %d", len(c.Blocks))
	}

	tests := []struct {
		name string
		line string
		want int
	}{
		// Cut off from Host pi4 by a blank line: it is vpn's commented-out param.
		{"trailing_comment_stays_with_block_above", "#    Port 22", 0},
		// Directly above Host pi4: it describes pi4.
		{"adjacent_comment_opens_next_block", "# describes pi4", 1},
		// Nothing above the first Host to trail, and Global has no UI, so the
		// header stays with the first block rather than vanishing from view.
		{"file_header_stays_with_first_block", "# file header", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := blockOf(c, tt.line); got != tt.want {
				t.Errorf("%q is owned by block %d, want %d", tt.line, got, tt.want)
			}
		})
	}

	// Regrouping must not disturb the bytes.
	if got := config.Serialize(&c); !bytes.Equal(got, []byte(raw)) {
		t.Errorf("Serialize changed content:\ngot:\n%s\nwant:\n%s", got, raw)
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
