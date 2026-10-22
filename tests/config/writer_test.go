package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// Edits that leave something other than the file's final empty token last (a
// block added to the end, the last block removed or moved) must not strip the
// trailing newline; a file that had none keeps having none.
func TestSerialize_TrailingNewlineAfterEdits(t *testing.T) {
	tests := []struct {
		name string
		in   string
		edit func(c *config.Config)
		want string
	}{
		{
			name: "add block",
			in:   "Host a\n    User x\n",
			edit: func(c *config.Config) { config.AddBlock(c, "b") },
			want: "Host a\n    User x\n\nHost b\n",
		},
		{
			name: "add block to empty file",
			in:   "",
			edit: func(c *config.Config) { config.AddBlock(c, "b") },
			want: "Host b\n",
		},
		{
			name: "move last block up",
			in:   "Host a\n    User x\nHost b\n    User y\n",
			edit: func(c *config.Config) { config.MoveBlock(c, 1, 0) },
			want: "Host b\n    User y\n\nHost a\n    User x\n",
		},
		{
			name: "remove last block",
			in:   "Host a\n    User x\nHost b\n    User y\n",
			edit: func(c *config.Config) { config.RemoveBlock(c, 1) },
			want: "Host a\n    User x\n",
		},
		{
			name: "crlf file",
			in:   "Host a\r\n    User x\r\n",
			edit: func(c *config.Config) { config.AddBlock(c, "b") },
			want: "Host a\r\n    User x\r\n\r\nHost b\r\n",
		},
		{
			name: "no trailing newline stays without one",
			in:   "Host a\n    User x",
			edit: func(c *config.Config) { config.AddBlock(c, "b") },
			want: "Host a\n    User x\nHost b",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := config.ParseBytes("cfg", []byte(tt.in))
			tt.edit(&c)
			if got := string(config.Serialize(&c)); got != tt.want {
				t.Errorf("Serialize = %q, want %q", got, tt.want)
			}
		})
	}
}

// Two saves within one second must leave two history copies; the second used to
// overwrite the first, losing the version before the first save.
func TestSave_SameSecondKeepsHistory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path := filepath.Join(home, "config")
	if err := os.WriteFile(path, []byte("Host a\n    User v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"v2", "v3"} {
		config.SetParam(&c.Blocks[0], "User", []string{v})
		c.Modified = true
		if err := config.Save(&c); err != nil {
			t.Fatalf("Save %s: %v", v, err)
		}
	}

	history, err := filepath.Glob(filepath.Join(home, ".keyward", "backups", "config", "config_*.bak"))
	if err != nil {
		t.Fatal(err)
	}
	var bodies []string
	for _, h := range history {
		b, err := os.ReadFile(h)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, string(b))
	}
	if len(bodies) != 2 || !strings.Contains(bodies[0], "v1") || !strings.Contains(bodies[1], "v2") {
		t.Errorf("history copies = %q, want the v1 and v2 versions in order", bodies)
	}
}
