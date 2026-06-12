package config_test

import (
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/config"
)

// makeBlock returns a parsed Block from a raw Host snippet.
func makeBlock(t *testing.T, raw string) config.Block {
	t.Helper()
	c := config.ParseBytes("fake", []byte(raw))
	if len(c.Blocks) == 0 {
		t.Fatalf("makeBlock: no blocks parsed from:\n%s", raw)
	}
	return c.Blocks[0]
}

// ── GetParam ─────────────────────────────────────────────────────────────────

func TestGetParam_Found(t *testing.T) {
	b := makeBlock(t, "Host srv\n    Port 2222\n    User deploy\n")

	vals, ok := config.GetParam(&b, "Port")
	if !ok {
		t.Fatal("GetParam: expected ok=true, got false")
	}
	if len(vals) != 1 || vals[0] != "2222" {
		t.Errorf("GetParam(Port) = %v, want [2222]", vals)
	}
}

// TestGetParam_CaseInsensitive verifies that SSH config keys are case-insensitive.
func TestGetParam_CaseInsensitive(t *testing.T) {
	b := makeBlock(t, "Host srv\n    hostname example.com\n")

	vals, ok := config.GetParam(&b, "HostName")
	if !ok || vals[0] != "example.com" {
		t.Errorf("GetParam case-insensitive: ok=%v vals=%v", ok, vals)
	}
}

func TestGetParam_NotFound(t *testing.T) {
	b := makeBlock(t, "Host srv\n    User alice\n")

	_, ok := config.GetParam(&b, "Port")
	if ok {
		t.Error("GetParam: expected ok=false for missing key, got true")
	}
}

// TestGetParam_MultiValue verifies that repeated parameters (e.g. IdentityFile)
// return all values in order.
func TestGetParam_MultiValue(t *testing.T) {
	raw := "Host multi\n    IdentityFile ~/.ssh/id_ed25519\n    IdentityFile ~/.ssh/id_rsa\n"
	b := makeBlock(t, raw)

	vals, ok := config.GetParam(&b, "IdentityFile")
	if !ok {
		t.Fatal("GetParam(IdentityFile): expected ok=true")
	}
	if len(vals) != 2 {
		t.Fatalf("want 2 IdentityFile values, got %d: %v", len(vals), vals)
	}
}

// ── GetParamWithLine ─────────────────────────────────────────────────────────

func TestGetParamWithLine_ReturnsLineNumbers(t *testing.T) {
	b := makeBlock(t, "Host srv\n    Port 22\n    User admin\n")

	results, ok := config.GetParamWithLine(&b, "Port")
	if !ok || len(results) == 0 {
		t.Fatal("GetParamWithLine(Port): not found")
	}
	if results[0].Line == 0 {
		t.Error("LineNum should be non-zero")
	}
}

// ── SetParam ─────────────────────────────────────────────────────────────────

func TestSetParam_UpdatesExisting(t *testing.T) {
	b := makeBlock(t, "Host srv\n    Port 22\n")

	changed := config.SetParam(&b, "Port", []string{"2222"})
	if !changed {
		t.Error("SetParam: expected true (key existed), got false")
	}

	vals, _ := config.GetParam(&b, "Port")
	if vals[0] != "2222" {
		t.Errorf("Port after SetParam = %q, want 2222", vals[0])
	}
}

func TestSetParam_ReturnsFalseWhenMissing(t *testing.T) {
	b := makeBlock(t, "Host srv\n    User alice\n")

	changed := config.SetParam(&b, "Port", []string{"443"})
	if changed {
		t.Error("SetParam: expected false when key does not exist")
	}

	_, ok := config.GetParam(&b, "Port")
	if ok {
		t.Error("SetParam should not insert a new key, use AddParam for that")
	}
}

// TestSetParam_DeletesExcess verifies that passing fewer values removes the extras.
func TestSetParam_DeletesExcess(t *testing.T) {
	raw := "Host multi\n    IdentityFile ~/.ssh/a\n    IdentityFile ~/.ssh/b\n    IdentityFile ~/.ssh/c\n"
	b := makeBlock(t, raw)

	config.SetParam(&b, "IdentityFile", []string{"~/.ssh/a"})

	vals, _ := config.GetParam(&b, "IdentityFile")
	if len(vals) != 1 {
		t.Errorf("after SetParam with 1 value, got %d IdentityFile values: %v", len(vals), vals)
	}
}

// ── AddParam ─────────────────────────────────────────────────────────────────

func TestAddParam_AppendsNew(t *testing.T) {
	b := makeBlock(t, "Host srv\n    User alice\n")

	config.AddParam(&b, "IdentityFile", "~/.ssh/id_ed25519")

	vals, ok := config.GetParam(&b, "IdentityFile")
	if !ok || vals[0] != "~/.ssh/id_ed25519" {
		t.Errorf("AddParam: IdentityFile = %v ok=%v", vals, ok)
	}
}

func TestAddParam_AllowsDuplicateKeys(t *testing.T) {
	b := makeBlock(t, "Host srv\n    IdentityFile ~/.ssh/a\n")

	config.AddParam(&b, "IdentityFile", "~/.ssh/b")

	vals, _ := config.GetParam(&b, "IdentityFile")
	if len(vals) != 2 {
		t.Errorf("AddParam: expected 2 IdentityFile values, got %d", len(vals))
	}
}

// ── RemoveParam ───────────────────────────────────────────────────────────────

// TestRemoveParam_RemovesFirstOnly is a critical contract test.
// In SSH config, IdentityFile can appear multiple times and that is valid.
// RemoveParam must remove ONLY the first occurrence, leaving the rest intact.
func TestRemoveParam_RemovesFirstOnly(t *testing.T) {
	raw := "Host multi\n    IdentityFile ~/.ssh/a\n    IdentityFile ~/.ssh/b\n"
	b := makeBlock(t, raw)

	removed := config.RemoveParam(&b, "IdentityFile")
	if !removed {
		t.Fatal("RemoveParam: expected true, got false")
	}

	vals, ok := config.GetParam(&b, "IdentityFile")
	if !ok {
		t.Fatal("second IdentityFile should still exist after removing first")
	}
	if len(vals) != 1 || vals[0] != "~/.ssh/b" {
		t.Errorf("after RemoveParam, remaining IdentityFile = %v, want [~/.ssh/b]", vals)
	}
}

func TestRemoveParam_ReturnsFalseWhenMissing(t *testing.T) {
	b := makeBlock(t, "Host srv\n    User alice\n")

	removed := config.RemoveParam(&b, "Port")
	if removed {
		t.Error("RemoveParam: expected false for missing key, got true")
	}
}

// ── RenameHost ───────────────────────────────────────────────────────────────

func TestRenameHost_UpdatesPatternAndToken(t *testing.T) {
	b := makeBlock(t, "Host oldname\n    User alice\n")

	config.RenameHost(&b, "newname")

	if b.Pattern != "newname" {
		t.Errorf("Block.Pattern = %q, want newname", b.Pattern)
	}

	// The HOST token Raw must be cleared so the writer rebuilds it.
	for _, tok := range b.Tokens {
		if tok.Type == config.HOST {
			if tok.Raw != "" {
				t.Errorf("HOST token Raw = %q after rename; want empty so writer rebuilds it", tok.Raw)
			}
			if tok.Value != "newname" {
				t.Errorf("HOST token Value = %q, want newname", tok.Value)
			}
		}
	}
}

// ── ToggleLine ───────────────────────────────────────────────────────────────

func TestToggleLine_ParamToComment(t *testing.T) {
	raw := "Host srv\n    Port 22\n    User alice\n"
	c := config.ParseBytes("fake", []byte(raw))
	b := &c.Blocks[0]

	// Find the Port line number.
	results, _ := config.GetParamWithLine(b, "Port")
	if len(results) == 0 {
		t.Fatal("Port not found")
	}
	lineNum := results[0].Line

	toggled := config.ToggleLine(b, lineNum)
	if !toggled {
		t.Fatal("ToggleLine PARAM→COMMENT: expected true")
	}

	// Port should no longer be a retrievable PARAM.
	_, ok := config.GetParam(b, "Port")
	if ok {
		t.Error("Port still found as PARAM after toggle to COMMENT")
	}
}

func TestToggleLine_CommentToParam(t *testing.T) {
	raw := "Host srv\n    # Port 2222\n    User alice\n"
	c := config.ParseBytes("fake", []byte(raw))
	b := &c.Blocks[0]

	// The comment is on line 2 (1-indexed); find it by iterating tokens.
	var commentLine int
	for _, tok := range b.Tokens {
		if tok.Type == config.COMMENT {
			commentLine = tok.LineNum
			break
		}
	}
	if commentLine == 0 {
		t.Fatal("no COMMENT token found in block")
	}

	toggled := config.ToggleLine(b, commentLine)
	if !toggled {
		t.Fatal("ToggleLine COMMENT→PARAM: expected true")
	}

	vals, ok := config.GetParam(b, "Port")
	if !ok {
		t.Fatal("Port not found as PARAM after toggle from COMMENT")
	}
	if vals[0] != "2222" {
		t.Errorf("Port = %q after toggle, want 2222", vals[0])
	}
}

// TestToggleLine_InvalidComment verifies that an unparseable commented line
// is NOT toggled and returns false — no data corruption.
func TestToggleLine_InvalidComment_NoToggle(t *testing.T) {
	raw := "Host srv\n    # this is a prose comment, not a param\n    User alice\n"
	c := config.ParseBytes("fake", []byte(raw))
	b := &c.Blocks[0]

	var commentLine int
	for _, tok := range b.Tokens {
		if tok.Type == config.COMMENT {
			commentLine = tok.LineNum
			break
		}
	}
	if commentLine == 0 {
		t.Fatal("no COMMENT token found")
	}

	toggled := config.ToggleLine(b, commentLine)
	if toggled {
		t.Error("ToggleLine should return false for non-parseable comment, got true")
	}
}

func TestToggleLine_HostLine_ReturnsFalse(t *testing.T) {
	raw := "Host srv\n    User alice\n"
	c := config.ParseBytes("fake", []byte(raw))
	b := &c.Blocks[0]

	var hostLine int
	for _, tok := range b.Tokens {
		if tok.Type == config.HOST {
			hostLine = tok.LineNum
			break
		}
	}

	toggled := config.ToggleLine(b, hostLine)
	if toggled {
		t.Error("ToggleLine on HOST token should return false")
	}
}
