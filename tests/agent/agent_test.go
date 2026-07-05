package agent_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"

	kagent "github.com/gateway-of-last-resort/keyward/internal/agent"
)

// newKeyPEM returns an unencrypted ed25519 private key in PEM form and its
// expected SHA256 fingerprint.
func newKeyPEM(t *testing.T) ([]byte, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test@agent")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), ssh.FingerprintSHA256(signer.PublicKey())
}

func TestAddAndLoaded(t *testing.T) {
	keyring := xagent.NewKeyring()
	pemBytes, wantFP := newKeyPEM(t)

	if err := kagent.AddKey(keyring, pemBytes, nil, "test@agent"); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	loaded, err := kagent.Loaded(keyring)
	if err != nil {
		t.Fatalf("Loaded: %v", err)
	}
	if !loaded[wantFP] {
		t.Fatalf("fingerprint %s not reported as loaded; got %v", wantFP, loaded)
	}
}

func TestAddKey_PassphraseRequired(t *testing.T) {
	keyring := xagent.NewKeyring()

	// Marshal an ed25519 key with a passphrase so ParseRawPrivateKey reports
	// it as missing when none is supplied.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "c", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(block)

	if err := kagent.AddKey(keyring, pemBytes, nil, "c"); !errors.Is(err, kagent.ErrPassphraseRequired) {
		t.Fatalf("err = %v, want ErrPassphraseRequired", err)
	}
	if err := kagent.AddKey(keyring, pemBytes, []byte("secret"), "c"); err != nil {
		t.Fatalf("AddKey with correct passphrase: %v", err)
	}
}

func TestLoadedFingerprints_NoAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, err := kagent.LoadedFingerprints(); !errors.Is(err, kagent.ErrNoAgent) {
		t.Fatalf("err = %v, want ErrNoAgent", err)
	}
}
