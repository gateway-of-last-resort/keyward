package keys

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Key represents a parsed SSH key pair (or public-only key) found on disk.
type Key struct {
	PrivateKeyPath string
	PublicKeyPath  string
	HasPassphrase  bool
	IsPublicOnly   bool
	PrivatePerm    os.FileMode
	PublicPerm     os.FileMode
	Algorithm      string
	ModifiedAt     time.Time
	Fingerprint    string
	BitSize        int
	Comment        string
}

type keyPairs struct {
	privatePath string
	publicPath  string
}

// Parse scans path for SSH key pairs and returns all recognised keys sorted by PrivateKeyPath.
func Parse(path string) ([]Key, error) {

	entries, err := os.ReadDir(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Wrap the original error so errors.Is(err, fs.ErrNotExist) also
			// holds for callers; the message still carries the path.
			return nil, fmt.Errorf("%w: %w", ErrDirNotFound, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrReadDirFailed, err)
	}

	pairs := make(map[string]*keyPairs)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filename := entry.Name()

		if strings.HasSuffix(filename, ".bak") {
			continue
		}

		baseName := strings.TrimSuffix(filename, ".pub")

		if pairs[baseName] == nil {
			pairs[baseName] = &keyPairs{}
		}

		fullPath := filepath.Join(path, filename)

		if strings.HasSuffix(filename, ".pub") {
			pairs[baseName].publicPath = fullPath
		} else {
			pairs[baseName].privatePath = fullPath
		}
	}

	var listOfKeys []Key
	privateFileHeader := []byte("-----BEGIN")

	for _, pair := range pairs {
		var temp Key
		isValid := false
		var parsedPublicKey ssh.PublicKey

		if pair.privatePath != "" {
			privateData, err := os.ReadFile(pair.privatePath)
			if err == nil && bytes.HasPrefix(privateData, privateFileHeader) {
				temp.PrivateKeyPath = pair.privatePath

				if stat, err := os.Stat(pair.privatePath); err == nil {
					temp.PrivatePerm = stat.Mode().Perm()
					temp.ModifiedAt = stat.ModTime()
				}

				rawKey, err := ssh.ParseRawPrivateKey(privateData)

				var passphraseErr *ssh.PassphraseMissingError
				if errors.As(err, &passphraseErr) {
					isValid = true
					temp.HasPassphrase = true
				} else if err == nil {
					isValid = true
					switch pk := rawKey.(type) {
					case *rsa.PrivateKey:
						temp.BitSize = pk.N.BitLen()

					case *ecdsa.PrivateKey:
						temp.BitSize = pk.Curve.Params().BitSize

					case ed25519.PrivateKey, *ed25519.PrivateKey:
						temp.BitSize = 256

					case *dsa.PrivateKey:
						temp.BitSize = pk.PublicKey.Parameters.P.BitLen()
					}

					signer, err := ssh.NewSignerFromKey(rawKey)
					if err == nil {
						parsedPublicKey = signer.PublicKey()
					}
				}
			}
		} else {
			temp.IsPublicOnly = true
		}

		if pair.publicPath != "" {
			publicData, err := os.ReadFile(pair.publicPath)
			if err == nil {
				pubKey, comment, _, _, err := ssh.ParseAuthorizedKey(publicData)
				if err == nil {
					temp.PublicKeyPath = pair.publicPath
					temp.Comment = comment
					isValid = true

					if stat, err := os.Stat(pair.publicPath); err == nil {
						temp.PublicPerm = stat.Mode().Perm()
					}

					if parsedPublicKey == nil {
						parsedPublicKey = pubKey
					}
				}
			}

		}

		if !isValid {
			continue
		}

		if parsedPublicKey != nil {
			temp.Algorithm = parsedPublicKey.Type()
			temp.Fingerprint = ssh.FingerprintSHA256(parsedPublicKey)
			// For passphrase-protected keys, BitSize was not set from the private key.
			// Extract it from the public key instead.
			if temp.BitSize == 0 {
				if cp, ok := parsedPublicKey.(ssh.CryptoPublicKey); ok {
					switch pub := cp.CryptoPublicKey().(type) {
					case *rsa.PublicKey:
						temp.BitSize = pub.N.BitLen()
					case *ecdsa.PublicKey:
						temp.BitSize = pub.Curve.Params().BitSize
					case ed25519.PublicKey:
						temp.BitSize = 256
					}
				}
			}
		}
		listOfKeys = append(listOfKeys, temp)

	}

	sort.Slice(listOfKeys, func(i, j int) bool {
		return listOfKeys[i].PrivateKeyPath < listOfKeys[j].PrivateKeyPath
	})

	return listOfKeys, nil
}
