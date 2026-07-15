package keys

import (
	"errors"
	"io"
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
// It is crash-safe: the new pair is generated under temporary names first, so a
// crash or a generation failure never touches the live key. Only once the new
// pair is fully written is it moved into place with rename (which atomically
// replaces the destination), and the old key is preserved as <name>.bak /
// <name>.pub.bak. At no point does the private key vanish from its live name.
//
// The caller is responsible for recording the rotation date in storage
// (via storage.Update setting KeyMetadata.LastRotatedAt).
func RotateKey(key Key, opts GenerateOptions) (newKey Key, bakPath string, err error) {
	if key.PrivateKeyPath == "" {
		return Key{}, "", ErrNoPrivateKey
	}

	dir := filepath.Dir(key.PrivateKeyPath)
	livePriv := key.PrivateKeyPath
	oldPub := key.PublicKeyPath
	// The rotated key always has a public half. If the old key had no .pub file
	// (e.g. an imported private-only key), the new public key goes to the standard
	// path next to the private key, instead of leaving the generated temporary
	// <name>.rotate-tmp.pub behind as an orphaned public-only "ghost" key.
	newPub := oldPub
	if newPub == "" {
		newPub = livePriv + ".pub"
	}
	privBak := livePriv + ".bak"
	pubBak := newPub + ".bak"

	// 1. Generate the new pair under a temporary name. Nothing live is touched,
	//    so a failure here leaves the existing key completely intact.
	tmpOpts := opts
	tmpOpts.Filename = filepath.Base(livePriv) + ".rotate-tmp"
	tmpOpts.Overwrite = true
	tmpKey, genErr := GenerateKeys(dir, tmpOpts)
	if genErr != nil {
		return Key{}, "", errors.Join(ErrRotateFailed, genErr)
	}
	tmpPriv := tmpKey.PrivateKeyPath
	tmpPub := tmpKey.PublicKeyPath

	// 2. Preserve the old pair as .bak by copying, so the live files stay in
	//    place until they are atomically replaced. Only back up the public half if
	//    the old key actually had one.
	if err := copyFile(livePriv, privBak, 0600); err != nil {
		_ = errors.Join(os.Remove(tmpPriv), os.Remove(tmpPub))
		return Key{}, "", errors.Join(ErrRotateFailed, err)
	}
	if oldPub != "" {
		if err := copyFile(oldPub, pubBak, 0644); err != nil {
			_ = errors.Join(os.Remove(tmpPriv), os.Remove(tmpPub), os.Remove(privBak))
			return Key{}, "", errors.Join(ErrRotateFailed, err)
		}
	}

	// 3. Move the new pair into the live names. rename replaces the destination,
	//    so the private key is always present under its name.
	if err := os.Rename(tmpPriv, livePriv); err != nil {
		cleanup := []error{os.Remove(tmpPriv), os.Remove(tmpPub), os.Remove(privBak)}
		if oldPub != "" {
			cleanup = append(cleanup, os.Remove(pubBak))
		}
		_ = errors.Join(cleanup...)
		return Key{}, "", errors.Join(ErrRotateFailed, ErrRenameFailed, err)
	}
	if err := os.Rename(tmpPub, newPub); err != nil {
		// Private key already swapped; restore the old one from .bak so the live
		// pair stays consistent, and report failure.
		rb := copyFile(privBak, livePriv, 0600)
		_ = os.Remove(tmpPub)
		return Key{}, "", errors.Join(ErrRotateFailed, ErrRenameFailed, err, rb)
	}

	tmpKey.PrivateKeyPath = livePriv
	tmpKey.PublicKeyPath = newPub
	return tmpKey, privBak, nil
}

// copyFile copies src to dst, truncating dst, with the given permissions.
func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}
