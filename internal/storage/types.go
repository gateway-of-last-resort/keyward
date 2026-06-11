package storage

import (
	"errors"
	"time"
)

// KeyMetadata holds user-managed metadata for a single SSH key, keyed by fingerprint.
type KeyMetadata struct {
	Fingerprint   string
	Tags          []string
	Note          string
	LastRotatedAt time.Time
	LinkedHosts   []string
}

// Store is the in-memory representation of the encrypted metadata store.
type Store struct {
	Keys    map[string]KeyMetadata
	SavedAt time.Time
}

const (
	defaultDir   = ".ssh-vault"
	metadataFile = "metadata.age"
	backupDir    = "backups"
)

var (
	ErrNotFound           = errors.New("key metadata not found")
	ErrAlreadyExists      = errors.New("key metadata already exists")
	ErrCorrupted          = errors.New("metadata file is corrupted")
	ErrInvalidIdentity    = errors.New("invalid identity type")
	ErrWriteFailed        = errors.New("failed to write metadata file")
	ErrInvalidFingerprint = errors.New("invalid fingerprint")
	ErrBackupFailed       = errors.New("failed to create backup file")
	ErrRestoreFailed      = errors.New("failed to restore backup file")
	ErrBackupNotFound     = errors.New("backup file not found")
)
