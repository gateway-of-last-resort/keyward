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

// runtimeIsPOSIX reports whether POSIX permission bits are meaningful here.
func runtimeIsPOSIX() bool {
	return os.PathSeparator == '/'
}
