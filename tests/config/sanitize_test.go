package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/config"
)

func TestValidateParamValue_RejectsControlChars(t *testing.T) {
	cases := []struct{ name, val string }{
		{"newline", "22\nProxyCommand evil"},
		{"carriage return", "22\rProxyCommand evil"},
		{"tab", "22\tfoo"},
		{"null", "22\x00"},
		{"del", "22\x7f"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := config.ValidateParamValue("Port", tc.val); !errors.Is(err, config.ErrControlChars) {
				t.Fatalf("got %v, want ErrControlChars", err)
			}
		})
	}
	// A clean single-line value still passes.
	if err := config.ValidateParamValue("HostName", "example.com"); err != nil {
		t.Fatalf("clean value rejected: %v", err)
	}
}

// TestMutators_StripControlChars is the defense-in-depth check: a caller that
// bypasses ValidateParamValue and feeds a newline-bearing value straight into a
// mutator must NOT be able to materialize an extra config directive on serialize.
func TestMutators_StripControlChars(t *testing.T) {
	const inject = "22\nProxyCommand touch /tmp/pwned"

	t.Run("SetParam", func(t *testing.T) {
		c := config.ParseBytes("cfg", []byte("Host web\n    Port 22\n"))
		config.SetParam(&c.Blocks[0], "Port", []string{inject})
		assertNoInjectedDirective(t, &c)
	})
	t.Run("AddParam", func(t *testing.T) {
		c := config.ParseBytes("cfg", []byte("Host web\n    HostName example.com\n"))
		config.AddParam(&c.Blocks[0], "Port", inject)
		assertNoInjectedDirective(t, &c)
	})
	t.Run("RenameHost", func(t *testing.T) {
		c := config.ParseBytes("cfg", []byte("Host web\n    Port 22\n"))
		config.RenameHost(&c.Blocks[0], "web2\n    ProxyCommand evil")
		assertNoInjectedDirective(t, &c)
	})
	t.Run("AddBlock", func(t *testing.T) {
		c := config.ParseBytes("cfg", []byte("Host web\n    Port 22\n"))
		config.AddBlock(&c, "evil\n    ProxyCommand pwn")
		assertNoInjectedDirective(t, &c)
	})
	t.Run("DuplicateBlock", func(t *testing.T) {
		c := config.ParseBytes("cfg", []byte("Host web\n    Port 22\n"))
		if !config.DuplicateBlock(&c, "web", "evil\n    ProxyCommand pwn") {
			t.Fatal("DuplicateBlock returned false")
		}
		assertNoInjectedDirective(t, &c)
	})
}

// assertNoInjectedDirective fails if serializing c produces a standalone
// ProxyCommand line, which would mean a control character survived into output.
func assertNoInjectedDirective(t *testing.T, c *config.Config) {
	t.Helper()
	out := string(config.Serialize(c))
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ProxyCommand") {
			t.Fatalf("injected directive materialized:\n%s", out)
		}
	}
}
