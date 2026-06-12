package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

// Init creates the vault directory structure under dir with 0700 permissions.
func Init(dir string) error {
	dirs := []string{
		dir,
		filepath.Join(dir, backupDir),
		filepath.Join(dir, backupDir, "config"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			return err
		}
	}

	return nil
}

// Load decrypts and deserialises the metadata store from dir.
// Returns an empty Store if no metadata file exists yet.
func Load(dir string, identity age.Identity) (Store, error) {

	metaPath := filepath.Join(dir, metadataFile)
	bakPath := metaPath + ".bak"

	if _, err := os.Stat(metaPath); errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat(bakPath); err == nil {
			if err := os.Rename(bakPath, metaPath); err != nil {
				return Store{}, fmt.Errorf("metadata recovery failed: %w", err)
			}
		}
	}

	data, err := os.ReadFile(metaPath)
	if errors.Is(err, os.ErrNotExist) {
		return Store{Keys: make(map[string]KeyMetadata)}, nil
	} else if err != nil {
		return Store{}, err
	}

	plaintext, err := crypto.Decrypt(data, identity)
	if err != nil {
		return Store{}, err
	}
	defer crypto.ZeroBytes(plaintext)

	var s Store
	if err := json.Unmarshal(plaintext, &s); err != nil {
		return Store{}, ErrCorrupted
	}
	if s.Keys == nil {
		s.Keys = make(map[string]KeyMetadata)
	}
	return s, nil

}

// Save encrypts and atomically writes the store to dir/metadata.age.
func Save(s *Store, dir string, identity age.Identity) error {

	s.SavedAt = time.Now()
	plaintext, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCorrupted, err)
	}
	defer crypto.ZeroBytes(plaintext)

	x25519, ok := identity.(*age.X25519Identity)
	if !ok {
		return ErrInvalidIdentity
	}
	recipient := x25519.Recipient()

	ciphertext, err := crypto.Encrypt(plaintext, recipient)
	if err != nil {
		return err
	}

	metaPath := filepath.Join(dir, metadataFile)
	if err := os.Rename(metaPath, metaPath+".bak"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}

	tmp, err := os.CreateTemp(dir, "temp*")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}

	_, err = tmp.Write(ciphertext)
	if err != nil {
		delErr := os.Remove(tmp.Name())
		return errors.Join(ErrWriteFailed, err, delErr)
	}

	err = tmp.Close()
	if err != nil {
		rollbackErr := os.Rename(metaPath+".bak", metaPath)
		delErr := os.Remove(tmp.Name())
		return errors.Join(ErrWriteFailed, err, delErr, rollbackErr)
	}
	err = os.Rename(tmp.Name(), metaPath)
	if err != nil {
		rollbackErr := os.Rename(metaPath+".bak", metaPath)
		return errors.Join(ErrWriteFailed, err, rollbackErr)
	}

	err = os.Chmod(metaPath, 0600)
	if err != nil {
		rollbackErr := os.Rename(metaPath+".bak", metaPath)
		return errors.Join(ErrWriteFailed, err, rollbackErr)
	}

	os.Remove(metaPath + ".bak")
	return nil
}

// Get returns the metadata for the given fingerprint or ErrNotFound.
func Get(s Store, fingerprint string) (KeyMetadata, error) {

	if fingerprint == "" {
		return KeyMetadata{}, ErrInvalidFingerprint
	}

	meta, ok := s.Keys[fingerprint]
	if !ok {
		return KeyMetadata{}, ErrNotFound
	}

	return meta, nil
}

// Put inserts meta into the store. Returns ErrAlreadyExists if the fingerprint is taken.
func Put(s *Store, meta KeyMetadata) error {

	if meta.Fingerprint == "" {
		return ErrInvalidFingerprint
	}

	if _, ok := s.Keys[meta.Fingerprint]; ok {
		return ErrAlreadyExists
	}

	if meta.Tags == nil {
		meta.Tags = []string{}
	}

	if meta.LinkedHosts == nil {
		meta.LinkedHosts = []string{}
	}

	s.Keys[meta.Fingerprint] = meta
	return nil
}

// Update applies fn to the metadata entry identified by fingerprint.
func Update(s *Store, fingerprint string, fn func(*KeyMetadata)) error {

	if fingerprint == "" {
		return ErrInvalidFingerprint
	}

	meta, ok := s.Keys[fingerprint]
	if !ok {
		return ErrNotFound
	}

	if meta.Fingerprint != fingerprint {
		return ErrInvalidFingerprint
	}

	fn(&meta)
	s.Keys[fingerprint] = meta
	return nil
}

// Delete removes the metadata entry for fingerprint. Returns ErrNotFound if absent.
func Delete(s *Store, fingerprint string) error {
	if fingerprint == "" {
		return ErrInvalidFingerprint
	}

	if _, ok := s.Keys[fingerprint]; !ok {
		return ErrNotFound
	}

	delete(s.Keys, fingerprint)

	return nil
}

// List returns all metadata entries sorted by fingerprint.
func List(s Store) []KeyMetadata {
	result := make([]KeyMetadata, 0, len(s.Keys))

	for _, key := range s.Keys {
		result = append(result, key)
	}

	slices.SortFunc(result, func(a, b KeyMetadata) int {
		return strings.Compare(a.Fingerprint, b.Fingerprint)
	})

	return result
}
