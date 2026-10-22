//go:build darwin || freebsd

package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/config"
)

// ufImmutable is UF_IMMUTABLE from <sys/stat.h>; package syscall does not export it.
const ufImmutable = 0x2

// When the config is written but an old history copy can't be pruned, the save
// still happened: Save must report ErrPruneFailed, not a failure, and the config
// must already count as saved (Modified cleared, Original updated). An immutable
// history file is the portable-enough way to make os.Remove fail here.
func TestSave_PruneFailureIsNotASaveFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	histDir := filepath.Join(home, ".keyward", "backups", "config")
	if err := os.MkdirAll(histDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Six old copies; the oldest must go once the save adds a seventh.
	for _, ts := range []string{"2020-01-01", "2020-01-02", "2020-01-03", "2020-01-04", "2020-01-05", "2020-01-06"} {
		if err := os.WriteFile(filepath.Join(histDir, "config_"+ts+"_00-00-00.bak"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldest := filepath.Join(histDir, "config_2020-01-01_00-00-00.bak")
	if err := syscall.Chflags(oldest, ufImmutable); err != nil {
		t.Skipf("cannot set immutable flag: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Chflags(oldest, 0) })

	path := filepath.Join(home, "config")
	if err := os.WriteFile(path, []byte("Host a\n    User old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	config.SetParam(&c.Blocks[0], "User", []string{"new"})
	c.Modified = true

	err = config.Save(&c)
	if !errors.Is(err, config.ErrPruneFailed) {
		t.Fatalf("Save = %v, want ErrPruneFailed", err)
	}
	if c.Modified {
		t.Error("Modified still set after the file was written")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Original) != string(got) {
		t.Errorf("Original = %q, want the bytes on disk %q", c.Original, got)
	}
}
