package keys

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
)

func TestParseMissingDir(t *testing.T) {
	// A missing directory must surface as ErrDirNotFound and also satisfy
	// errors.Is(err, fs.ErrNotExist) so callers (cmd/keyward) can tell "no
	// ~/.ssh yet" apart from a real read failure and start with an empty list.
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	ks, err := Parse(missing)
	if err == nil {
		t.Fatalf("Parse(%q) = nil error, want error", missing)
	}
	if ks != nil {
		t.Errorf("Parse returned keys %v, want nil", ks)
	}
	if !errors.Is(err, ErrDirNotFound) {
		t.Errorf("errors.Is(err, ErrDirNotFound) = false, err = %v", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("errors.Is(err, fs.ErrNotExist) = false, err = %v", err)
	}
}

func TestParseEmptyDir(t *testing.T) {
	// An existing but empty directory is not an error: keyward must launch
	// with an empty key list.
	dir := t.TempDir()

	ks, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse(%q) = %v, want nil error", dir, err)
	}
	if len(ks) != 0 {
		t.Errorf("Parse returned %d keys, want 0", len(ks))
	}
}
