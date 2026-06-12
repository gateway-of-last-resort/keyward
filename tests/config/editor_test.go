package config_test

import (
	"strings"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/config"
)

// threeHostConfig returns a canonical Config with three Host blocks for editor tests.
func threeHostConfig(t *testing.T) config.Config {
	t.Helper()
	raw := `Host alpha
    HostName alpha.example.com
    User alice

Host beta
    HostName beta.example.com
    User bob

Host gamma
    HostName gamma.example.com
    User carol
`
	return config.ParseBytes("~/.ssh/config", []byte(raw))
}

// ── FindBlock ────────────────────────────────────────────────────────────────

func TestFindBlock_Found(t *testing.T) {
	c := threeHostConfig(t)

	b := config.FindBlock(&c, "beta")
	if b == nil {
		t.Fatal("FindBlock(beta): expected non-nil, got nil")
	}
	if b.Pattern != "beta" {
		t.Errorf("Pattern = %q, want beta", b.Pattern)
	}
}

// TestFindBlock_CaseInsensitive ensures pattern matching follows SSH rules.
func TestFindBlock_CaseInsensitive(t *testing.T) {
	c := threeHostConfig(t)

	b := config.FindBlock(&c, "BETA")
	if b == nil {
		t.Fatal("FindBlock(BETA): case-insensitive match expected non-nil")
	}
}

func TestFindBlock_NotFound(t *testing.T) {
	c := threeHostConfig(t)

	b := config.FindBlock(&c, "delta")
	if b != nil {
		t.Errorf("FindBlock(delta): expected nil, got %+v", b)
	}
}

// TestFindBlock_ReturnsPointerIntoConfig verifies that modifying the returned
// *Block actually mutates the Config (pointer into the slice, not a copy).
func TestFindBlock_ReturnsPointerIntoConfig(t *testing.T) {
	c := threeHostConfig(t)

	b := config.FindBlock(&c, "alpha")
	config.AddParam(b, "IdentityFile", "~/.ssh/id_ed25519")

	b2 := config.FindBlock(&c, "alpha")
	vals, ok := config.GetParam(b2, "IdentityFile")
	if !ok || vals[0] != "~/.ssh/id_ed25519" {
		t.Error("FindBlock returned a copy, not a pointer into Config")
	}
}

// ── AddBlock ─────────────────────────────────────────────────────────────────

func TestAddBlock_AppendsBlock(t *testing.T) {
	c := threeHostConfig(t)
	before := len(c.Blocks)

	config.AddBlock(&c, "delta")

	if len(c.Blocks) != before+1 {
		t.Fatalf("want %d blocks after AddBlock, got %d", before+1, len(c.Blocks))
	}
	if c.Blocks[len(c.Blocks)-1].Pattern != "delta" {
		t.Errorf("new block Pattern = %q, want delta", c.Blocks[len(c.Blocks)-1].Pattern)
	}
}

func TestAddBlock_SetsModified(t *testing.T) {
	c := threeHostConfig(t)
	c.Modified = false

	config.AddBlock(&c, "newhost")

	if !c.Modified {
		t.Error("Config.Modified should be true after AddBlock")
	}
}

// ── RemoveBlock ───────────────────────────────────────────────────────────────

func TestRemoveBlock_Removes(t *testing.T) {
	c := threeHostConfig(t)

	removed := config.RemoveBlock(&c, "beta")
	if !removed {
		t.Fatal("RemoveBlock(beta): expected true, got false")
	}
	if config.FindBlock(&c, "beta") != nil {
		t.Error("beta block still exists after RemoveBlock")
	}
	if len(c.Blocks) != 2 {
		t.Errorf("want 2 blocks after remove, got %d", len(c.Blocks))
	}
}

func TestRemoveBlock_ReturnsFalseWhenMissing(t *testing.T) {
	c := threeHostConfig(t)

	removed := config.RemoveBlock(&c, "nonexistent")
	if removed {
		t.Error("RemoveBlock: expected false for missing block, got true")
	}
}

// ── DuplicateBlock ───────────────────────────────────────────────────────────

func TestDuplicateBlock_CreatesIndependentCopy(t *testing.T) {
	c := threeHostConfig(t)

	ok := config.DuplicateBlock(&c, "alpha", "alpha-copy")
	if !ok {
		t.Fatal("DuplicateBlock: expected true, got false")
	}

	orig := config.FindBlock(&c, "alpha")
	copy_ := config.FindBlock(&c, "alpha-copy")
	if orig == nil || copy_ == nil {
		t.Fatal("original or copy block not found after DuplicateBlock")
	}

	// Mutating the copy must not affect the original.
	config.SetParam(copy_, "User", []string{"mutated"})

	origVals, _ := config.GetParam(orig, "User")
	if origVals[0] == "mutated" {
		t.Error("DuplicateBlock: mutating copy affected original (shallow-copy bug)")
	}
}

func TestDuplicateBlock_ReturnsFalseWhenSourceMissing(t *testing.T) {
	c := threeHostConfig(t)

	ok := config.DuplicateBlock(&c, "nonexistent", "copy")
	if ok {
		t.Error("DuplicateBlock: expected false for missing source, got true")
	}
}

// ── MoveBlock ─────────────────────────────────────────────────────────────────

func TestMoveBlock_MovesToIndex(t *testing.T) {
	c := threeHostConfig(t)
	// Blocks: [alpha, beta, gamma]. Move gamma to index 0.
	ok := config.MoveBlock(&c, "gamma", 0)
	if !ok {
		t.Fatal("MoveBlock: expected true")
	}
	if c.Blocks[0].Pattern != "gamma" {
		t.Errorf("Blocks[0].Pattern = %q, want gamma", c.Blocks[0].Pattern)
	}
}

func TestMoveBlock_ClampsToBounds(t *testing.T) {
	c := threeHostConfig(t)

	// Index 999 should clamp to last position.
	ok := config.MoveBlock(&c, "alpha", 999)
	if !ok {
		t.Fatal("MoveBlock: expected true")
	}
	last := c.Blocks[len(c.Blocks)-1]
	if last.Pattern != "alpha" {
		t.Errorf("after clamped MoveBlock, last block = %q, want alpha", last.Pattern)
	}
}

// ── Search ───────────────────────────────────────────────────────────────────

func TestSearch_ByPattern(t *testing.T) {
	c := threeHostConfig(t)

	results := config.Search(&c, "alpha")
	if len(results) != 1 || results[0].Pattern != "alpha" {
		t.Errorf("Search(alpha) = %v blocks, want [alpha]", len(results))
	}
}

func TestSearch_ByHostName(t *testing.T) {
	c := threeHostConfig(t)

	results := config.Search(&c, "beta.example.com")
	if len(results) != 1 {
		t.Fatalf("Search by HostName: want 1 result, got %d", len(results))
	}
	if results[0].Pattern != "beta" {
		t.Errorf("Search by HostName: Pattern = %q, want beta", results[0].Pattern)
	}
}

func TestSearch_ByUser(t *testing.T) {
	c := threeHostConfig(t)

	results := config.Search(&c, "carol")
	if len(results) != 1 {
		t.Fatalf("Search by User: want 1 result, got %d", len(results))
	}
	if results[0].Pattern != "gamma" {
		t.Errorf("Search by User: Pattern = %q, want gamma", results[0].Pattern)
	}
}

func TestSearch_NoDuplicates(t *testing.T) {
	// A block that matches on BOTH pattern and HostName must appear once.
	raw := "Host example\n    HostName example.com\n"
	c := config.ParseBytes("fake", []byte(raw))

	results := config.Search(&c, "example")
	if len(results) != 1 {
		t.Errorf("Search: expected 1 result (no duplicates), got %d", len(results))
	}
}

func TestSearch_NoResults(t *testing.T) {
	c := threeHostConfig(t)

	results := config.Search(&c, "zzznomatch")
	if len(results) != 0 {
		t.Errorf("Search with no match: expected 0 results, got %d", len(results))
	}
}

// ── Diff ─────────────────────────────────────────────────────────────────────

func TestDiff_Added(t *testing.T) {
	c := threeHostConfig(t)
	config.AddBlock(&c, "newhost")

	diffs := config.Diff(&c)
	if !containsSubstr(diffs, "newhost") {
		t.Errorf("Diff: expected newhost in output, got: %v", diffs)
	}
}

func TestDiff_Modified(t *testing.T) {
	c := threeHostConfig(t)
	b := config.FindBlock(&c, "alpha")
	config.SetParam(b, "User", []string{"modified-user"})

	diffs := config.Diff(&c)
	if !containsSubstr(diffs, "alpha") {
		t.Errorf("Diff: expected alpha in diff output for modification, got: %v", diffs)
	}
}

func TestDiff_Removed(t *testing.T) {
	c := threeHostConfig(t)
	config.RemoveBlock(&c, "gamma")

	diffs := config.Diff(&c)
	if !containsSubstr(diffs, "gamma") {
		t.Errorf("Diff: expected gamma in diff output for removal, got: %v", diffs)
	}
}

func TestDiff_EmptyWhenUnchanged(t *testing.T) {
	c := threeHostConfig(t)

	diffs := config.Diff(&c)
	if len(diffs) != 0 {
		t.Errorf("Diff on unchanged config: expected empty, got %v", diffs)
	}
}

// ── Reset ────────────────────────────────────────────────────────────────────

func TestReset_RestoresBlocks(t *testing.T) {
	c := threeHostConfig(t)

	config.RemoveBlock(&c, "beta")
	config.AddBlock(&c, "injected")

	config.Reset(&c)

	if len(c.Blocks) != 3 {
		t.Fatalf("after Reset: want 3 blocks, got %d", len(c.Blocks))
	}
	if config.FindBlock(&c, "injected") != nil {
		t.Error("after Reset: injected block should not exist")
	}
	if config.FindBlock(&c, "beta") == nil {
		t.Error("after Reset: beta block should be restored")
	}
}

func TestReset_ClearsModifiedFlag(t *testing.T) {
	c := threeHostConfig(t)
	config.AddBlock(&c, "tmp")

	config.Reset(&c)

	if c.Modified {
		t.Error("Config.Modified should be false after Reset")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func containsSubstr(lines []string, substr string) bool {
	for _, l := range lines {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}
