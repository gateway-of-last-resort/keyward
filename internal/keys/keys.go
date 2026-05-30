package keys

import (
	"bytes"
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
	//Permissions    [2]os.FileMode // 0 for private, 1 for public
	PrivatePerm os.FileMode
	PublicPerm  os.FileMode
	Algorithm   string
	CreatedAt   time.Time
	Fingerprint string
	BitSize     int
}

func Parse(path string) ([]Key, error) {
	//home, err := os.UserHomeDir()
	//sshDir := filepath.Join(home, ".ssh")

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	pubMap := make(map[string]string)
	var candidates []string

	for _, entry := range entries {
		if !entry.IsDir() {
			filename := entry.Name()
			if strings.HasSuffix(filename, ".pub") {
				pubMap[strings.TrimSuffix(filename, ".pub")] = filepath.Join(path, filename)
			} else {
				candidates = append(candidates, filepath.Join(path, filename))
			}
		}
	}

	var listOfKeys []Key
	privateFileHeader := []byte("-----BEGIN")

	for _, candidate := range candidates {
		filename := filepath.Base(candidate)
		publicPath, ok := pubMap[filename]

		if !ok {
			continue
		}

		privateKeyData, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}

		if !bytes.HasPrefix(privateKeyData, privateFileHeader) {
			continue
		}

		fileStatPrivate, err := os.Stat(candidate)
		if err != nil {
			continue
		}

		fileStatPublic, err := os.Stat(publicPath)
		if err != nil {
			continue
		}

		_, err = ssh.ParseRawPrivateKey(privateKeyData)
		hasPassphrase := false

		var passphraseErr *ssh.PassphraseMissingError
		if errors.As(err, &passphraseErr) {
			hasPassphrase = true
		} else if err != nil {
			continue
		}

		publicKeyData, err := os.ReadFile(publicPath)
		if err != nil {
			continue
		}

		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyData)
		if err != nil {
			continue
		}

		listOfKeys = append(listOfKeys, Key{
			PrivateKeyPath: candidate,
			PublicKeyPath:  publicPath,
			HasPassphrase:  hasPassphrase,
			PrivatePerm:    fileStatPrivate.Mode().Perm(),
			PublicPerm:     fileStatPublic.Mode().Perm(),
			Algorithm:      pubKey.Type(),
			CreatedAt:      fileStatPrivate.ModTime(),
			Fingerprint:    ssh.FingerprintSHA256(pubKey),
		})

	}

	return listOfKeys, nil
}
