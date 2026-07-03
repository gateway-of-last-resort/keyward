package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWriteFile_WritesWithPerm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")

	if err := atomicWriteFile(path, []byte("hello"), 0600); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q, want %q", got, "hello")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeIsPOSIX() && info.Mode().Perm() != 0600 {
		t.Errorf("perm = %v, want 0600", info.Mode().Perm())
	}

	// No temp files must remain in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestAtomicWriteFile_ErrorOnMissingDir(t *testing.T) {
	// A path inside a nonexistent directory must error, not panic or partially
	// write.
	path := filepath.Join(t.TempDir(), "nope", "out.bin")
	if err := atomicWriteFile(path, []byte("x"), 0600); err == nil {
		t.Fatal("expected error writing into a missing directory")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file should not exist after failed write; stat err = %v", err)
	}
}

func TestPruneBackups_KeepsNewestAndReportsRemoveErrors(t *testing.T) {
	dir := t.TempDir()
	// Timestamp-prefixed names sort oldest-first, matching real backups.
	names := []string{
		"2026-01-01_00-00-00.tar.age",
		"2026-01-02_00-00-00.tar.age",
		"2026-01-03_00-00-00.tar.age",
		"2026-01-04_00-00-00.tar.age",
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// A non-matching file must never be pruned.
	if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := pruneBackups(dir, 2); err != nil {
		t.Fatalf("pruneBackups: %v", err)
	}

	remaining := map[string]bool{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		remaining[e.Name()] = true
	}
	// Oldest two dropped, newest two + unrelated file kept.
	for _, gone := range names[:2] {
		if remaining[gone] {
			t.Errorf("%s should have been pruned", gone)
		}
	}
	for _, kept := range append(names[2:], "keep.txt") {
		if !remaining[kept] {
			t.Errorf("%s should have been kept", kept)
		}
	}
}

func TestPruneBackups_SurfacesRemoveError(t *testing.T) {
	if !runtimeIsPOSIX() {
		t.Skip("relies on unix directory write-permission semantics")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	dir := t.TempDir()
	for _, n := range []string{"a.tar.age", "b.tar.age", "c.tar.age"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// A read-only directory forbids unlinking its entries, so os.Remove fails.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	if err := pruneBackups(dir, 1); err == nil {
		t.Fatal("expected pruneBackups to surface the os.Remove failure")
	}
}

// runtimeIsPOSIX reports whether POSIX permission bits are meaningful here.
func runtimeIsPOSIX() bool {
	return os.PathSeparator == '/'
}
