package crypto_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

// keyPath returns a fresh master.key path inside a temp dir.
func keyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "master.key")
}

// initKey creates a master key at a fresh path and returns the path.
func initKey(t *testing.T, password string) string {
	t.Helper()
	path := keyPath(t)
	if _, err := crypto.InitMasterKey(path, password); err != nil {
		t.Fatalf("InitMasterKey: %v", err)
	}
	return path
}

// corrupt reads the key file, mutates it via fn, and writes it back.
func corrupt(t *testing.T, path string, fn func([]byte) []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if err := os.WriteFile(path, fn(data), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func TestMasterKey_RoundTrip(t *testing.T) {
	path := initKey(t, "correct horse")

	id, err := crypto.LoadMasterKey(path, "correct horse")
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}

	// The loaded identity must be usable end-to-end for the vault.
	x, ok := id.(*age.X25519Identity)
	if !ok {
		t.Fatalf("loaded identity is %T, want *age.X25519Identity", id)
	}
	ct, err := crypto.Encrypt([]byte("payload"), x.Recipient())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := crypto.Decrypt(ct, id)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != "payload" {
		t.Fatalf("got %q, want payload", pt)
	}
}

func TestMasterKey_SameKeyAcrossLoads(t *testing.T) {
	path := initKey(t, "pw")

	id1, err := crypto.LoadMasterKey(path, "pw")
	if err != nil {
		t.Fatalf("load 1: %v", err)
	}
	id2, err := crypto.LoadMasterKey(path, "pw")
	if err != nil {
		t.Fatalf("load 2: %v", err)
	}
	if id1.(*age.X25519Identity).String() != id2.(*age.X25519Identity).String() {
		t.Fatal("two loads returned different identities")
	}
}

func TestInitMasterKey_Errors(t *testing.T) {
	t.Run("empty password", func(t *testing.T) {
		if _, err := crypto.InitMasterKey(keyPath(t), ""); !errors.Is(err, crypto.ErrEmptyPassword) {
			t.Fatalf("got %v, want ErrEmptyPassword", err)
		}
	})
	t.Run("already exists", func(t *testing.T) {
		path := initKey(t, "pw")
		if _, err := crypto.InitMasterKey(path, "pw"); !errors.Is(err, crypto.ErrMasterKeyExists) {
			t.Fatalf("got %v, want ErrMasterKeyExists", err)
		}
	})
}

func TestLoadMasterKey_Errors(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		if _, err := crypto.LoadMasterKey(keyPath(t), "pw"); !errors.Is(err, crypto.ErrMasterKeyNotFound) {
			t.Fatalf("got %v, want ErrMasterKeyNotFound", err)
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		path := initKey(t, "right")
		if _, err := crypto.LoadMasterKey(path, "wrong"); !errors.Is(err, crypto.ErrWrongPassword) {
			t.Fatalf("got %v, want ErrWrongPassword", err)
		}
	})
}

// TestLoadMasterKey_Corrupt drives the positional header parser through every
// rejection path. None may panic (out-of-bounds), all must return a sentinel.
//
// Header layout (byte offsets): magic[0:4] version[4] time[5:9] memory[9:13]
// threads[13] salt[14:46] nonce[46:58] ciphertext[58:].
func TestLoadMasterKey_Corrupt(t *testing.T) {
	cases := []struct {
		name string
		mut  func([]byte) []byte
		want error
	}{
		{
			name: "bad magic",
			mut:  func(b []byte) []byte { b[0] = 'X'; return b },
			want: crypto.ErrCorruptedMasterKey,
		},
		{
			name: "unsupported version",
			mut:  func(b []byte) []byte { b[4] = 0xFF; return b },
			want: crypto.ErrUnsupportedVersion,
		},
		{
			name: "zero argon2 time",
			mut:  func(b []byte) []byte { b[5], b[6], b[7], b[8] = 0, 0, 0, 0; return b },
			want: crypto.ErrCorruptedMasterKey,
		},
		{
			name: "zero argon2 memory",
			mut:  func(b []byte) []byte { b[9], b[10], b[11], b[12] = 0, 0, 0, 0; return b },
			want: crypto.ErrCorruptedMasterKey,
		},
		{
			name: "zero argon2 threads",
			mut:  func(b []byte) []byte { b[13] = 0; return b },
			want: crypto.ErrCorruptedMasterKey,
		},
		{
			name: "truncated below minimum",
			mut:  func(b []byte) []byte { return b[:73] }, // one byte under minFileSize (74)
			want: crypto.ErrCorruptedMasterKey,
		},
		{
			name: "empty file",
			mut:  func(b []byte) []byte { return []byte{} },
			want: crypto.ErrCorruptedMasterKey,
		},
		{
			name: "corrupt nonce",
			mut:  func(b []byte) []byte { b[46] ^= 0xFF; return b },
			want: crypto.ErrWrongPassword,
		},
		{
			name: "corrupt salt",
			mut:  func(b []byte) []byte { b[14] ^= 0xFF; return b },
			want: crypto.ErrWrongPassword,
		},
		{
			name: "corrupt ciphertext tag",
			mut:  func(b []byte) []byte { b[len(b)-1] ^= 0xFF; return b },
			want: crypto.ErrWrongPassword,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := initKey(t, "pw")
			corrupt(t, path, tc.mut)
			_, err := crypto.LoadMasterKey(path, "pw") // must not panic
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestChangeMasterKeyPassword(t *testing.T) {
	path := initKey(t, "old")

	if err := crypto.ChangeMasterKeyPassword(path, "old", "new"); err != nil {
		t.Fatalf("ChangeMasterKeyPassword: %v", err)
	}

	if _, err := crypto.LoadMasterKey(path, "old"); !errors.Is(err, crypto.ErrWrongPassword) {
		t.Fatalf("old password: got %v, want ErrWrongPassword", err)
	}
	if _, err := crypto.LoadMasterKey(path, "new"); err != nil {
		t.Fatalf("new password: %v", err)
	}
	// The temporary .bak must not survive a successful change.
	if _, err := os.Stat(path + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".bak still present: %v", err)
	}
}

func TestChangeMasterKeyPassword_Errors(t *testing.T) {
	t.Run("empty new password leaves key intact", func(t *testing.T) {
		path := initKey(t, "old")
		if err := crypto.ChangeMasterKeyPassword(path, "old", ""); !errors.Is(err, crypto.ErrEmptyPassword) {
			t.Fatalf("got %v, want ErrEmptyPassword", err)
		}
		// Original password must still work — the guard fires before any rename.
		if _, err := crypto.LoadMasterKey(path, "old"); err != nil {
			t.Fatalf("key damaged after rejected change: %v", err)
		}
	})
	t.Run("wrong old password", func(t *testing.T) {
		path := initKey(t, "old")
		if err := crypto.ChangeMasterKeyPassword(path, "wrong", "new"); !errors.Is(err, crypto.ErrWrongPassword) {
			t.Fatalf("got %v, want ErrWrongPassword", err)
		}
	})
}
