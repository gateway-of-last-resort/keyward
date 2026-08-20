package crypto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// versionByte returns the format version byte (offset 4) of the key file.
func versionByte(t *testing.T, path string) byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if len(data) < 5 {
		t.Fatalf("key file too short: %d bytes", len(data))
	}
	return data[4]
}

// writeLegacyV1 hand-writes a v1-format master.key (unauthenticated header, no
// AAD) so migration can be tested — the public API only ever writes v2 now.
func writeLegacyV1(t *testing.T, path, password string, id *age.X25519Identity) {
	t.Helper()
	salt := make([]byte, 32)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand salt: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}
	kek := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	cipher, err := chacha20poly1305.New(kek)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	encrypted := cipher.Seal(nil, nonce, []byte(id.String()), nil)

	buf := new(bytes.Buffer)
	buf.WriteString("SSHV")
	buf.WriteByte(0x01)
	_ = binary.Write(buf, binary.BigEndian, uint32(3))
	_ = binary.Write(buf, binary.BigEndian, uint32(64*1024))
	buf.WriteByte(4)
	buf.Write(salt)
	buf.Write(nonce)
	buf.Write(encrypted)

	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatalf("write legacy key: %v", err)
	}
}

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
	// A file that exists but cannot be read used to surface the raw OS error,
	// which callers could neither classify with errors.Is nor tell apart from a
	// corrupt file.
	t.Run("unreadable", func(t *testing.T) {
		path := keyPath(t)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		err := errFromLoad(t, path)
		if !errors.Is(err, crypto.ErrReadFailed) {
			t.Fatalf("got %v, want ErrReadFailed", err)
		}
		if errors.Is(err, crypto.ErrMasterKeyNotFound) || errors.Is(err, crypto.ErrCorruptedMasterKey) {
			t.Errorf("read failure misclassified: %v", err)
		}
	})
	t.Run("permission denied", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not deny reads here")
		}
		path := initKey(t, "pw")
		if err := os.Chmod(path, 0000); err != nil {
			t.Fatal(err)
		}
		if err := errFromLoad(t, path); !errors.Is(err, crypto.ErrReadFailed) {
			t.Fatalf("got %v, want ErrReadFailed", err)
		}
	})
}

// errFromLoad returns the error from an unlock that must not succeed.
func errFromLoad(t *testing.T, path string) error {
	t.Helper()
	if _, err := crypto.LoadMasterKey(path, "pw"); err != nil {
		return err
	}
	t.Fatal("LoadMasterKey succeeded, want an error")
	return nil
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

// TestLoadMasterKey_RejectsOversizedKDFParams guards the fix for a DoS found by
// FuzzLoadMasterKey: the argon2 memory parameter read from the file is bounded,
// so a crafted or corrupt header cannot make argon2 allocate gigabytes and hang
// on unlock. The memory field is the uint32 at offset 9 (after magic+version+time).
func TestLoadMasterKey_RejectsOversizedKDFParams(t *testing.T) {
	path := initKey(t, "correct horse")
	corrupt(t, path, func(b []byte) []byte {
		binary.BigEndian.PutUint32(b[9:13], 0xFFFFFFFF) // argon2 memory (KiB)
		return b
	})

	_, err := crypto.LoadMasterKey(path, "correct horse")
	if !errors.Is(err, crypto.ErrCorruptedMasterKey) {
		t.Fatalf("err = %v, want ErrCorruptedMasterKey", err)
	}
}

// TestLoadMasterKey_RecoversFromBak simulates a crash during a password change:
// the primary master.key is renamed aside before the replacement is written, so
// only the .bak survives. LoadMasterKey must recover it (and MasterKeyExists must
// report the vault as present) rather than let the app create a new, orphaning
// identity.
func TestLoadMasterKey_RecoversFromBak(t *testing.T) {
	path := initKey(t, "correct horse")
	if err := os.Rename(path, path+".bak"); err != nil {
		t.Fatal(err)
	}

	if !crypto.MasterKeyExists(path) {
		t.Error("MasterKeyExists should count a leftover .bak as present")
	}

	id, err := crypto.LoadMasterKey(path, "correct horse")
	if err != nil {
		t.Fatalf("LoadMasterKey should recover from .bak: %v", err)
	}
	if id == nil {
		t.Fatal("nil identity after recovery")
	}
	// The .bak was promoted back to the primary path.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("primary not restored from .bak: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Error(".bak should be gone after promotion")
	}
}

// TestMasterKeyExists_AbsentVault confirms a truly empty vault dir reports absent
// and LoadMasterKey returns ErrMasterKeyNotFound (so the app offers first-run setup).
func TestMasterKeyExists_AbsentVault(t *testing.T) {
	path := keyPath(t)
	if crypto.MasterKeyExists(path) {
		t.Error("MasterKeyExists should be false with no key and no .bak")
	}
	if _, err := crypto.LoadMasterKey(path, "x"); !errors.Is(err, crypto.ErrMasterKeyNotFound) {
		t.Fatalf("err = %v, want ErrMasterKeyNotFound", err)
	}
}

func TestInitMasterKey_WritesV2(t *testing.T) {
	path := initKey(t, "pw")
	if v := versionByte(t, path); v != 0x02 {
		t.Fatalf("new key version %#x, want 0x02", v)
	}
}

func TestLoadMasterKey_MigratesV1ToV2(t *testing.T) {
	path := keyPath(t)
	id := newIdentity(t)
	writeLegacyV1(t, path, "pw", id)

	if v := versionByte(t, path); v != 0x01 {
		t.Fatalf("pre-load version %#x, want 0x01", v)
	}

	loaded, err := crypto.LoadMasterKey(path, "pw")
	if err != nil {
		t.Fatalf("load v1: %v", err)
	}
	if loaded.(*age.X25519Identity).String() != id.String() {
		t.Fatal("migrated identity differs from original")
	}

	// First successful unlock must have rewritten the file in place as v2.
	if v := versionByte(t, path); v != 0x02 {
		t.Fatalf("post-load version %#x, want 0x02 (auto-migrated)", v)
	}
	// And the migrated file still unlocks (now via the v2 AAD path).
	if _, err := crypto.LoadMasterKey(path, "pw"); err != nil {
		t.Fatalf("reload migrated v2: %v", err)
	}
}

// TestLoadMasterKey_V2ParamTamper flips a byte of the authenticated argon2
// header; the load must fail rather than derive a key under altered parameters.
func TestLoadMasterKey_V2ParamTamper(t *testing.T) {
	path := initKey(t, "pw")
	// b[12] is the low byte of argon2 memory: changing it by one keeps the KDF
	// cost sane while tampering with an authenticated parameter.
	corrupt(t, path, func(b []byte) []byte { b[12] ^= 0x01; return b })
	if _, err := crypto.LoadMasterKey(path, "pw"); !errors.Is(err, crypto.ErrWrongPassword) {
		t.Fatalf("got %v, want ErrWrongPassword", err)
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
