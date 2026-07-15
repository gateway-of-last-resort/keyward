package config_test

import (
	"bytes"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/config"
)

// FuzzParseConfig checks two properties of the ~/.ssh/config parser against
// arbitrary input: it never panics, and Parse -> Serialize is idempotent. The
// raw round-trip is not byte-identical for every input (Serialize trims one
// trailing newline and normalises line endings), so the invariant is a fixed
// point: serialising the parsed-then-serialised form must reproduce it exactly.
// A failure means the parser loses or mutates data on a second pass.
func FuzzParseConfig(f *testing.F) {
	seeds := []string{
		"Host web\n    HostName example.com\n    Port 22\n",
		"# comment only\n\n# another comment",
		"Host a\n\tPort 2222\n", // tab separator
		"Host a\r\n    Port 22\r\n",
		"Match host *.internal\n    ForwardAgent yes",
		"IdentityFile ~/.ssh/id_ed25519\n\nHost x\n    User git\n",
		"Host *\n    StrictHostKeyChecking accept-new",
		"",
		"\n\n\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		c := config.ParseBytes("fuzz", data) // must not panic on any bytes
		canon := config.Serialize(&c)

		c2 := config.ParseBytes("fuzz", canon)
		canon2 := config.Serialize(&c2)

		if !bytes.Equal(canon, canon2) {
			t.Fatalf("Parse/Serialize not idempotent:\ninput:  %q\nfirst:  %q\nsecond: %q", data, canon, canon2)
		}
	})
}
