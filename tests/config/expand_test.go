package config_test

import (
	"os/user"
	"path/filepath"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/config"
)

func TestExpandPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("KW_TEST_DIR", "/opt/keys")
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"/abs/id_ed25519", "/abs/id_ed25519", true},
		{"~/.ssh/id_ed25519", filepath.Join(home, ".ssh", "id_ed25519"), true},
		{`"~/.ssh/my key"`, filepath.Join(home, ".ssh", "my key"), true},
		{"%d/.ssh/id_x", home + "/.ssh/id_x", true},
		{"/keys/%u", "/keys/" + u.Username, true},
		{"/keys/100%%", "/keys/100%", true},
		{"${KW_TEST_DIR}/id", "/opt/keys/id", true},
		{"$KW_TEST_DIR/id", "$KW_TEST_DIR/id", true}, // ssh only expands ${VAR}
		{"none", "", false},
		{"NONE", "", false},
		{"~/.ssh/%h_key", "", false},
		{"~bob/.ssh/id", "", false},
		{"${UNTERMINATED/id", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := config.ExpandPath(tt.in)
		if ok != tt.wantOK || got != tt.want {
			t.Errorf("ExpandPath(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.wantOK)
		}
	}
}
