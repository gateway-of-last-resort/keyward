package keys

import (
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
	if err := f.Close(); err != nil {
		_ = os.Remove(destPriv)
		return Key{}, fmt.Errorf("%w: %w", ErrImportFailed, err)
	}

	if err := importPublicKey(srcPath, destPriv, rawKey, protected, opts.Overwrite); err != nil {
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

// importPublicKey writes destPriv's .pub: it copies the source's .pub when
// present, otherwise derives one from the private key (only possible when the
// key is not passphrase-protected). A passphrase-protected key with no .pub is
// imported without one — Parse still recognizes it by its private file.
func importPublicKey(srcPath, destPriv string, rawKey any, protected, overwrite bool) error {
	destPub := destPriv + ".pub"

	if pubData, err := os.ReadFile(srcPath + ".pub"); err == nil {
		return writePublicFile(destPub, pubData, overwrite)
	}

	if protected {
		return nil // can't derive a public key without the passphrase
	}

	signer, err := ssh.NewSignerFromKey(rawKey)
	if err != nil {
		return nil // unusual key type; skip .pub rather than fail the import
	}
	return writePublicFile(destPub, ssh.MarshalAuthorizedKey(signer.PublicKey()), overwrite)
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
	if err := f.Close(); err != nil {
		_ = os.Remove(destPub)
		return fmt.Errorf("%w: %w", ErrImportFailed, err)
	}
	return nil
}
