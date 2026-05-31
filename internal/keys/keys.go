package keys

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Key struct {
	PrivateKeyPath string
	PublicKeyPath  string
	HasPassphrase  bool
	PrivatePerm    os.FileMode
	PublicPerm     os.FileMode
	Algorithm      string
	CreatedAt      time.Time
	Fingerprint    string
	BitSize        int
}

type keyPairs struct {
	privatePath string
	publicPath  string
}

func ParseKeys(path string) ([]Key, error) {

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	pairs := make(map[string]*keyPairs)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filename := entry.Name()

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
					temp.CreatedAt = stat.ModTime()
				} else {
					continue
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
		}

		if pair.publicPath != "" {
			publicData, err := os.ReadFile(pair.publicPath)
			if err == nil {
				pubKey, _, _, _, err := ssh.ParseAuthorizedKey(publicData)
				if err == nil {
					temp.PublicKeyPath = pair.publicPath
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
			temp.Algorithm = strings.TrimSuffix(parsedPublicKey.Type(), "ssh-")
			temp.Fingerprint = ssh.FingerprintSHA256(parsedPublicKey)
		}
		listOfKeys = append(listOfKeys, temp)

	}

	return listOfKeys, nil
}
