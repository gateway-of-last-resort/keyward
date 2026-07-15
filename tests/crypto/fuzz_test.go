package crypto_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

// FuzzLoadMasterKey feeds arbitrary bytes to the master-key loader, which parses
// a hand-rolled binary header with positional indexing. The contract under fuzz
// is that no input crashes the loader: a malformed or truncated file must return
// an error, never panic (out-of-range slice, etc.). Seeded with a real key plus
// truncations and junk.
func FuzzLoadMasterKey(f *testing.F) {
	seedDir := f.TempDir()
	realPath := filepath.Join(seedDir, "seed.key")
	if _, err := crypto.InitMasterKey(realPath, "correct horse"); err != nil {
		f.Fatalf("seed InitMasterKey: %v", err)
	}
	real, err := os.ReadFile(realPath)
	if err != nil {
		f.Fatalf("read seed: %v", err)
	}

	f.Add(real)
	f.Add(real[:min(len(real), 40)]) // truncated header
	f.Add([]byte("SSHV\x02"))        // magic + version, nothing else
	f.Add([]byte("SSHV\x99"))        // unsupported version byte
	f.Add([]byte("not a key at all"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "master.key")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		// Any (identity, error) result is acceptable; the only failure is a panic.
		_, _ = crypto.LoadMasterKey(path, "correct horse")
	})
}
