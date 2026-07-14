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
	// SchemaVersion identifies the on-disk metadata schema. Save stamps it with
	// CurrentSchemaVersion; stores written before versioning (v0.5.x and earlier)
	// have no such field and decode as 0, which is treated as the original schema.
	// It exists so a future breaking change can be detected and migrated on Load.
	SchemaVersion int
	Keys          map[string]KeyMetadata
	SavedAt       time.Time
}

// CurrentSchemaVersion is the metadata schema version written by this build.
// Bump it only alongside a documented, backward-compatible migration (see the
// on-disk formats section of SECURITY.md).
const CurrentSchemaVersion = 1

const (
	defaultDir   = ".keyward"
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
