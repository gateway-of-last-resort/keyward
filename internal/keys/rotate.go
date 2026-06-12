package keys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var (
	ErrNoPrivateKey = errors.New("key has no private key file")
	ErrRenameFailed = errors.New("failed to rename key file")
	ErrRotateFailed = errors.New("key rotation failed")
)

// RotateKey replaces an existing key pair with a newly generated one.
//
// The old private and public key files are renamed to <name>.bak and
// <name>.pub.bak before the new key is generated. If generation fails,
// the renames are rolled back automatically.
//
// The caller is responsible for recording the rotation date in storage
// (via storage.Update setting KeyMetadata.LastRotatedAt).
func RotateKey(key Key, opts GenerateOptions) (newKey Key, bakPath string, err error) {
	if key.PrivateKeyPath == "" {
		return Key{}, "", ErrNoPrivateKey
	}

	dir := filepath.Dir(key.PrivateKeyPath)
	privBak := key.PrivateKeyPath + ".bak"
	pubBak := key.PublicKeyPath + ".bak"

	if err := os.Rename(key.PrivateKeyPath, privBak); err != nil {
		return Key{}, "", fmt.Errorf("%w: %w", ErrRenameFailed, err)
	}

	if key.PublicKeyPath != "" {
		if err := os.Rename(key.PublicKeyPath, pubBak); err != nil {
			_ = os.Rename(privBak, key.PrivateKeyPath)
			return Key{}, "", fmt.Errorf("%w: %w", ErrRenameFailed, err)
		}
	}

	newKey, genErr := GenerateKeys(dir, opts)
	if genErr != nil {
		rollbackErr := os.Rename(privBak, key.PrivateKeyPath)
		if key.PublicKeyPath != "" {
			rollbackErr = errors.Join(rollbackErr, os.Rename(pubBak, key.PublicKeyPath))
		}
		return Key{}, "", errors.Join(ErrRotateFailed, genErr, rollbackErr)
	}

	return newKey, privBak, nil
}
