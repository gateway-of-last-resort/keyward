package crypto_test

import (
	"bytes"
	"errors"
	"testing"

	"filippo.io/age"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

// newIdentity generates a fresh X25519 identity for test use.
func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	id := newIdentity(t)

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"nil", nil},
		{"small", []byte("hello world")},
		{"binary", []byte{0x00, 0x01, 0xff, 0xfe, 0x00}},
		{"large", bytes.Repeat([]byte("A"), 1<<16)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := crypto.Encrypt(tc.data, id.Recipient())
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			pt, err := crypto.Decrypt(ct, id)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			want := tc.data
			if want == nil {
				want = []byte{}
			}
			if !bytes.Equal(pt, want) {
				t.Fatalf("round-trip mismatch: got %q want %q", pt, want)
			}
		})
	}
}

func TestEncrypt_NilRecipient(t *testing.T) {
	if _, err := crypto.Encrypt([]byte("x"), nil); !errors.Is(err, crypto.ErrNilRecipient) {
		t.Fatalf("got %v, want ErrNilRecipient", err)
	}
}

func TestDecrypt_NilIdentity(t *testing.T) {
	if _, err := crypto.Decrypt([]byte("x"), nil); !errors.Is(err, crypto.ErrNilIdentity) {
		t.Fatalf("got %v, want ErrNilIdentity", err)
	}
}

func TestDecrypt_WrongIdentity(t *testing.T) {
	ct, err := crypto.Encrypt([]byte("secret"), newIdentity(t).Recipient())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// A different identity can't open the ciphertext.
	if _, err := crypto.Decrypt(ct, newIdentity(t)); !errors.Is(err, crypto.ErrDecryptFailed) {
		t.Fatalf("got %v, want ErrDecryptFailed", err)
	}
}

func TestDecrypt_Garbage(t *testing.T) {
	// Non-age input must return an error, never panic.
	cases := [][]byte{
		nil,
		{},
		[]byte("not age ciphertext"),
		bytes.Repeat([]byte{0xff}, 512),
	}
	for _, in := range cases {
		if _, err := crypto.Decrypt(in, newIdentity(t)); !errors.Is(err, crypto.ErrDecryptFailed) {
			t.Fatalf("Decrypt(%d bytes): got %v, want ErrDecryptFailed", len(in), err)
		}
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	crypto.ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, v)
		}
	}
	// Must not panic on empty/nil.
	crypto.ZeroBytes(nil)
	crypto.ZeroBytes([]byte{})
}
