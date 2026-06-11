package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ErrDirNotFound      = errors.New("target directory not found")
	ErrInvalidAlgorithm = errors.New("invalid algorithm")
	ErrMissingFilename  = errors.New("missing filename")
	ErrEmptyPassphrase  = errors.New("empty passphrase")
	ErrBitSizeTooSmall  = errors.New("bit size must be at least 2048")
	ErrKeyAlreadyExists = errors.New("key already exists")
	ErrWriteFailed      = errors.New("failed to write key file")
	ErrCreateFailed     = errors.New("failed to create key file")
)

type Algorithm string

const (
	AlgorithmEd25519 Algorithm = "ssh-ed25519"
	AlgorithmRSA     Algorithm = "ssh-rsa"
)

type GenerateOptions struct {
	Algorithm            Algorithm
	Filename             string
	Overwrite            bool
	BitSize              int
	Comment              string
	Passphrase           string
	AllowEmptyPassphrase bool
}

func (a Algorithm) IsValid() bool {
	switch a {
	case AlgorithmEd25519, AlgorithmRSA:
		return true
	default:
		return false
	}
}

// risks of passphrase exposure in core dumps or memory inspection tools.
// TODO: change Passphrase field type from string to []byte in GenerateOptions,
// then explicitly zero it after use: for i := range opts.Passphrase { opts.Passphrase[i] = 0 }

func GenerateKeys(dir string, opts GenerateOptions) (Key, error) {

	info, errDir := os.Stat(dir)
	if errDir != nil {
		if errors.Is(errDir, os.ErrNotExist) {
			return Key{}, fmt.Errorf("%w: %s", ErrDirNotFound, dir)
		}
		return Key{}, errDir
	}
	if !info.IsDir() {
		return Key{}, fmt.Errorf("%w: %s is not a directory", ErrDirNotFound, dir)
	}

	if !opts.Algorithm.IsValid() {
		return Key{}, fmt.Errorf("%w: %s", ErrInvalidAlgorithm, opts.Algorithm)
	}

	if opts.Filename == "" {
		return Key{}, ErrMissingFilename
	}

	if opts.Passphrase == "" {
		if !opts.AllowEmptyPassphrase {
			return Key{}, ErrEmptyPassphrase
		}
	}

	privatePath := filepath.Join(dir, opts.Filename)
	publicPath := privatePath + ".pub"

	_, errPriv := os.Stat(privatePath)
	_, errPub := os.Stat(publicPath)

	if !errors.Is(errPriv, os.ErrNotExist) || !errors.Is(errPub, os.ErrNotExist) {
		if !opts.Overwrite {
			return Key{}, fmt.Errorf("%w: %s", ErrKeyAlreadyExists, opts.Filename)
		}
	}

	var (
		privPem   []byte
		pubPem    []byte
		sshPub    ssh.PublicKey
		bitSize   int
		errPubKey error
	)

	switch opts.Algorithm {
	case AlgorithmEd25519:
		// generate ed25519
		bitSize = 256

		edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return Key{}, err
		}

		var privBlock *pem.Block

		if opts.Passphrase != "" {
			privBlock, err = ssh.MarshalPrivateKeyWithPassphrase(edPriv, opts.Comment, []byte(opts.Passphrase))
		} else {
			privBlock, err = ssh.MarshalPrivateKey(edPriv, opts.Comment)
		}

		if err != nil {
			return Key{}, err
		}
		privPem = pem.EncodeToMemory(privBlock)

		sshPub, errPubKey = ssh.NewPublicKey(edPub)
		if errPubKey != nil {
			return Key{}, errPubKey
		}

		pubPem = ssh.MarshalAuthorizedKey(sshPub)

	case AlgorithmRSA:
		if opts.BitSize == 0 {
			opts.BitSize = 4096
		}

		if opts.BitSize < 2048 {
			return Key{}, fmt.Errorf("%w, your input: %d", ErrBitSizeTooSmall, opts.BitSize)
		}

		bitSize = opts.BitSize

		rsaPriv, err := rsa.GenerateKey(rand.Reader, opts.BitSize)
		if err != nil {
			return Key{}, err
		}

		var privBlock *pem.Block

		if opts.Passphrase != "" {
			privBlock, err = ssh.MarshalPrivateKeyWithPassphrase(rsaPriv, opts.Comment, []byte(opts.Passphrase))
		} else {
			privBlock, err = ssh.MarshalPrivateKey(rsaPriv, opts.Comment)
		}
		if err != nil {
			return Key{}, err
		}
		privPem = pem.EncodeToMemory(privBlock)

		sshPub, errPubKey = ssh.NewPublicKey(&rsaPriv.PublicKey)
		if errPubKey != nil {
			return Key{}, errPubKey
		}
		pubPem = ssh.MarshalAuthorizedKey(sshPub)

	}

	if privPem == nil {
		return Key{}, fmt.Errorf("failed to encode private key")
	}

	if opts.Comment != "" {
		pubPem = []byte(strings.TrimSpace(string(pubPem)) + " " + opts.Comment + "\n")
	}

	filePriv, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

	if err != nil {
		return Key{}, fmt.Errorf("%w: %s", ErrCreateFailed, privatePath)
	}

	cleanup := func() {
		removeErr := errors.Join(os.Remove(privatePath), os.Remove(publicPath))
		_ = removeErr
	}

	_, err = filePriv.Write(privPem)
	if err != nil {
		filePriv.Close()
		cleanup()
		return Key{}, fmt.Errorf("%w: %s", ErrWriteFailed, privatePath)
	}

	if err := filePriv.Close(); err != nil {
		cleanup()
		return Key{}, fmt.Errorf("%w: %s", ErrWriteFailed, privatePath)
	}

	filePub, err := os.OpenFile(publicPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		cleanup()
		return Key{}, fmt.Errorf("%w: %s", ErrCreateFailed, publicPath)
	}

	_, err = filePub.Write(pubPem)
	if err != nil {
		filePub.Close()
		cleanup()
		return Key{}, fmt.Errorf("%w: %s", ErrWriteFailed, publicPath)
	}

	if err := filePub.Close(); err != nil {
		cleanup()
		return Key{}, fmt.Errorf("%w: %s", ErrWriteFailed, publicPath)
	}

	return Key{
		PrivateKeyPath: privatePath,
		PublicKeyPath:  publicPath,
		HasPassphrase:  opts.Passphrase != "",
		PrivatePerm:    0600,
		PublicPerm:     0644,
		Algorithm:      string(opts.Algorithm),
		ModifiedAt:     time.Now(),
		Fingerprint:    ssh.FingerprintSHA256(sshPub),
		BitSize:        bitSize,
		Comment:        opts.Comment,
	}, nil
}
