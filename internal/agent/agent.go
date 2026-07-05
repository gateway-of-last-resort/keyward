// Package agent is a thin wrapper around golang.org/x/crypto/ssh/agent for the
// two operations keyward needs: loading a key into the running ssh-agent and
// listing which keys are currently loaded (by fingerprint).
package agent

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	// ErrNoAgent means SSH_AUTH_SOCK is unset or the socket can't be dialed.
	ErrNoAgent = errors.New("no ssh-agent available (SSH_AUTH_SOCK not set)")
	// ErrPassphraseRequired means the key is encrypted but no passphrase was given.
	ErrPassphraseRequired = errors.New("key is passphrase-protected")
	// ErrWrongPassphrase means the supplied passphrase did not decrypt the key.
	ErrWrongPassphrase = errors.New("wrong passphrase")
	ErrAddFailed       = errors.New("failed to add key to agent")
	ErrListFailed      = errors.New("failed to list agent keys")
)

// Dial connects to the ssh-agent named by SSH_AUTH_SOCK. The returned closer
// must be called when done.
func Dial() (agent.ExtendedAgent, func() error, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, ErrNoAgent
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrNoAgent, err)
	}
	return agent.NewClient(conn), conn.Close, nil
}

// AddKey loads a private key (PEM) into a, decrypting it with passphrase when
// the key is encrypted. comment is shown by `ssh-add -l`.
func AddKey(a agent.Agent, privPEM, passphrase []byte, comment string) error {
	raw, err := ssh.ParseRawPrivateKey(privPEM)

	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if len(passphrase) == 0 {
			return ErrPassphraseRequired
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(privPEM, passphrase)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrWrongPassphrase, err)
		}
	} else if err != nil {
		return fmt.Errorf("%w: %w", ErrAddFailed, err)
	}

	if err := a.Add(agent.AddedKey{PrivateKey: raw, Comment: comment}); err != nil {
		return fmt.Errorf("%w: %w", ErrAddFailed, err)
	}
	return nil
}

// Loaded returns the SHA256 fingerprints of the keys currently held by a, in the
// same form as ssh.FingerprintSHA256 so they can be matched against keys.Key.
func Loaded(a agent.Agent) (map[string]bool, error) {
	list, err := a.List()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrListFailed, err)
	}
	out := make(map[string]bool, len(list))
	for _, k := range list {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		out[ssh.FingerprintSHA256(pub)] = true
	}
	return out, nil
}

// Add dials the ssh-agent and loads a key into it.
func Add(privPEM, passphrase []byte, comment string) error {
	a, closeFn, err := Dial()
	if err != nil {
		return err
	}
	defer func() { _ = closeFn() }()
	return AddKey(a, privPEM, passphrase, comment)
}

// LoadedFingerprints dials the ssh-agent and returns its loaded fingerprints.
// It returns ErrNoAgent (which callers may treat as "no keys") when no agent
// is running.
func LoadedFingerprints() (map[string]bool, error) {
	a, closeFn, err := Dial()
	if err != nil {
		return nil, err
	}
	defer func() { _ = closeFn() }()
	return Loaded(a)
}
