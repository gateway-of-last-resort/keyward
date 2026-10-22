package keys

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

var (
	ErrImportFailed   = errors.New("failed to import key")
	ErrSourceNotFound = errors.New("source key not found")
	ErrInvalidKey     = errors.New("not a valid SSH private key")
)

// ImportOptions configures ImportKey.
type ImportOptions struct {
	// Overwrite allows replacing an existing key of the same name in destDir.
	Overwrite bool
}

// ImportKey copies an external private key at srcPath into destDir with 0600
// permissions, bringing it under keyward's management. It validates that srcPath
// is a real SSH private key first, copies (or derives) the matching .pub, and
// returns the freshly parsed Key. It refuses to overwrite an existing file
// (ErrKeyAlreadyExists) unless opts.Overwrite is set.
func ImportKey(destDir, srcPath string, opts ImportOptions) (Key, error) {
	// The TUI has no shell to expand ~, so do it here (a no-op once the shell
	// has already expanded it for the CLI).
	srcPath = ExpandTilde(srcPath)

	data, err := os.ReadFile(srcPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Key{}, fmt.Errorf("%w: %s", ErrSourceNotFound, srcPath)
		}
		return Key{}, fmt.Errorf("%w: %w", ErrImportFailed, err)
	}
	defer crypto.ZeroBytes(data)

	// Validate: a passphrase-protected key is still a valid key to import.
	rawKey, perr := ssh.ParseRawPrivateKey(data)
	var passphraseErr *ssh.PassphraseMissingError
	protected := errors.As(perr, &passphraseErr)
	if perr != nil && !protected {
		return Key{}, fmt.Errorf("%w: %s", ErrInvalidKey, srcPath)
	}

	destPriv := filepath.Join(destDir, filepath.Base(srcPath))
	destPub := destPriv + ".pub"

	pubData, err := publicKeyFor(srcPath, rawKey, protected)
	if err != nil {
		return Key{}, err
	}
	// With no public half to write, a .pub already at the destination would be
	// paired with the imported private key and lend it the wrong fingerprint.
	if pubData == nil && !opts.Overwrite {
		if _, err := os.Lstat(destPub); err == nil {
			return Key{}, fmt.Errorf("%w: %s", ErrKeyAlreadyExists, destPub)
		}
	}

	f, err := openKeyFile(destPriv, opts.Overwrite, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return Key{}, fmt.Errorf("%w: %s", ErrKeyAlreadyExists, destPriv)
		}
		return Key{}, fmt.Errorf("%w: %w", ErrImportFailed, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(destPriv)
		return Key{}, fmt.Errorf("%w: %w", ErrImportFailed, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(destPriv)
		return Key{}, fmt.Errorf("%w: %w", ErrImportFailed, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(destPriv)
		return Key{}, fmt.Errorf("%w: %w", ErrImportFailed, err)
	}

	if pubData != nil {
		err = writePublicFile(destPub, pubData, opts.Overwrite)
	} else if rmErr := os.Remove(destPub); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		err = fmt.Errorf("%w: %w", ErrImportFailed, rmErr)
	}
	if err != nil {
		_ = os.Remove(destPriv)
		return Key{}, err
	}

	// Re-parse destDir so the returned Key carries fingerprint, bit size, etc.
	parsed, err := Parse(destDir)
	if err != nil {
		return Key{}, fmt.Errorf("%w: %w", ErrImportFailed, err)
	}
	for _, k := range parsed {
		if k.PrivateKeyPath == destPriv {
			return k, nil
		}
	}
	return Key{}, fmt.Errorf("%w: imported key not found after parse", ErrImportFailed)
}

// ExpandTilde replaces a leading ~ or ~/ with the user's home directory.
func ExpandTilde(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[2:])
}

// publicKeyFor returns the .pub content to install next to the imported key:
// the source's .pub when present, otherwise one derived from the private key.
// It returns nil for a passphrase-protected key with no .pub, which can't be
// derived without the passphrase; Parse still recognizes it by its private file.
// A source .pub that is not a public key, or does not match an unencrypted
// private key, is rejected rather than copied.
func publicKeyFor(srcPath string, rawKey any, protected bool) ([]byte, error) {
	pubData, err := os.ReadFile(srcPath + ".pub")
	if err == nil {
		pub, _, _, _, perr := ssh.ParseAuthorizedKey(pubData)
		if perr != nil {
			return nil, fmt.Errorf("%w: %s.pub is not a public key", ErrInvalidKey, srcPath)
		}
		if !protected {
			if signer, serr := ssh.NewSignerFromKey(rawKey); serr == nil &&
				!bytes.Equal(signer.PublicKey().Marshal(), pub.Marshal()) {
				return nil, fmt.Errorf("%w: %s.pub does not match the private key", ErrInvalidKey, srcPath)
			}
		}
		return pubData, nil
	}

	if protected {
		return nil, nil
	}

	signer, err := ssh.NewSignerFromKey(rawKey)
	if err != nil {
		return nil, nil // unusual key type; skip .pub rather than fail the import
	}
	return ssh.MarshalAuthorizedKey(signer.PublicKey()), nil
}

func writePublicFile(destPub string, data []byte, overwrite bool) error {
	f, err := openKeyFile(destPub, overwrite, 0644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrKeyAlreadyExists, destPub)
		}
		return fmt.Errorf("%w: %w", ErrImportFailed, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(destPub)
		return fmt.Errorf("%w: %w", ErrImportFailed, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(destPub)
		return fmt.Errorf("%w: %w", ErrImportFailed, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(destPub)
		return fmt.Errorf("%w: %w", ErrImportFailed, err)
	}
	return nil
}
