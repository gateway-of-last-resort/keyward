package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/config"
)

// A ~/.ssh/config managed by stow, chezmoi or home-manager is a symlink into a
// dotfiles tree. Saving must update the file the link points to and keep the
// link, not replace it with a regular file that the dotfiles tree never sees.
func TestSave_WritesThroughSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs extra privileges on Windows")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	dotfiles := filepath.Join(t.TempDir(), "dotfiles")
	if err := os.MkdirAll(dotfiles, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dotfiles, "ssh_config")
	if err := os.WriteFile(target, []byte("Host a\n    User old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "config")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	c, err := config.ParseFile(link)
	if err != nil {
		t.Fatal(err)
	}
	config.SetParam(&c.Blocks[0], "User", []string{"new"})
	c.Modified = true
	if err := config.Save(&c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("config is no longer a symlink after Save")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if want := "Host a\n    User new\n"; string(got) != want {
		t.Fatalf("link target = %q, want %q", got, want)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(home, "temp.*.atom")); len(leftovers) > 0 {
		t.Errorf("temp files left next to the link: %v", leftovers)
	}
}
