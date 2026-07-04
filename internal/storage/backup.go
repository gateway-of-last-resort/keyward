package storage

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

// BackupResult reports the outcome of a successful CreateBackup.
//   - Path is the written archive.
//   - Skipped lists ~/.ssh entries that couldn't be read and were left OUT of
//     the archive; the backup still succeeded for everything else, so callers
//     should surface this rather than let the user assume full coverage.
//   - PruneErr is a non-fatal error from removing old backups after the write.
type BackupResult struct {
	Path     string
	Skipped  []string
	PruneErr error
}

func CreateBackup(sshDir, vaultDir string, identity age.Identity) (BackupResult, error) {
	skipFiles := map[string]bool{
		"known_hosts":     true,
		"authorized_keys": true,
	}

	type archiveEntry struct {
		path    string
		tarName string
	}

	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return BackupResult{}, ErrBackupFailed
	}

	var files []archiveEntry
	for _, entry := range entries {
		if entry.IsDir() || skipFiles[entry.Name()] {
			continue
		}
		files = append(files, archiveEntry{
			path:    filepath.Join(sshDir, entry.Name()),
			tarName: entry.Name(),
		})
	}

	metaPath := filepath.Join(vaultDir, metadataFile)
	if _, err := os.Stat(metaPath); err == nil {
		files = append(files, archiveEntry{
			path:    metaPath,
			tarName: defaultDir + "/" + metadataFile,
		})
	}

	tarBuffer := new(bytes.Buffer)
	tarWriter := tar.NewWriter(tarBuffer)

	var skipped []string
	for _, f := range files {
		data, err := os.ReadFile(f.path)
		if err != nil {
			skipped = append(skipped, f.tarName)
			continue
		}

		stat, err := os.Stat(f.path)
		if err != nil {
			skipped = append(skipped, f.tarName)
			continue
		}

		header := &tar.Header{
			Name:    f.tarName,
			Mode:    int64(stat.Mode().Perm()),
			Size:    int64(len(data)),
			ModTime: stat.ModTime(),
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			return BackupResult{}, ErrBackupFailed
		}
		if _, err := tarWriter.Write(data); err != nil {
			return BackupResult{}, ErrBackupFailed
		}
	}

	if err := tarWriter.Close(); err != nil {
		return BackupResult{}, ErrBackupFailed
	}

	x25519Identity, ok := identity.(*age.X25519Identity)
	if !ok {
		return BackupResult{}, ErrInvalidIdentity
	}

	plaintext := tarBuffer.Bytes()
	defer crypto.ZeroBytes(plaintext)

	ciphertext, err := crypto.Encrypt(plaintext, x25519Identity.Recipient())
	if err != nil {
		return BackupResult{}, ErrBackupFailed
	}

	backupPath := filepath.Join(vaultDir, backupDir)
	if err := os.MkdirAll(backupPath, 0700); err != nil {
		return BackupResult{}, ErrBackupFailed
	}

	filename := time.Now().Format("2006-01-02_15-04-05") + ".tar.age"
	finalPath := filepath.Join(backupPath, filename)

	if err := atomicWriteFile(finalPath, ciphertext, 0600); err != nil {
		return BackupResult{}, ErrBackupFailed
	}

	// The archive is durably written; pruning old copies is best-effort and its
	// failure must not fail the backup, but it is reported so it isn't lost.
	pruneErr := pruneBackups(backupPath, maxBackups)

	return BackupResult{Path: finalPath, Skipped: skipped, PruneErr: pruneErr}, nil
}

const maxBackups = 5

const (
	// maxBackupSize caps the encrypted archive we buffer into memory on restore.
	maxBackupSize = 128 << 20 // 128 MiB
	// maxRestoreFileSize caps any single file extracted from a backup, so a
	// crafted or corrupt archive can't exhaust memory (local self-DoS).
	maxRestoreFileSize = 64 << 20 // 64 MiB
)

// pruneBackups removes the oldest .tar.age files in dir, keeping at most max.
// It returns any os.Remove failures joined together rather than swallowing them,
// so the caller can report that stale backups still linger.
func pruneBackups(dir string, max int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".tar.age") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	// entries are sorted by name (timestamp prefix), so oldest are first
	var errs []error
	for len(files) > max {
		if err := os.Remove(files[0]); err != nil {
			errs = append(errs, err)
		}
		files = files[1:]
	}
	return errors.Join(errs...)
}

func RestoreBackup(backupPath, sshDir, vaultDir string, identity age.Identity) error {

	if fi, err := os.Stat(backupPath); err != nil {
		return ErrBackupNotFound
	} else if fi.Size() > maxBackupSize {
		return ErrRestoreFailed
	}

	data, err := os.ReadFile(backupPath)
	if err != nil {
		return ErrBackupNotFound
	}
	plaintext, err := crypto.Decrypt(data, identity)
	if err != nil {
		return ErrRestoreFailed
	}
	defer crypto.ZeroBytes(plaintext)

	tarReader := tar.NewReader(bytes.NewReader(plaintext))

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrRestoreFailed
		}

		if header.Size < 0 || header.Size > maxRestoreFileSize {
			return ErrRestoreFailed
		}
		fileData, err := io.ReadAll(io.LimitReader(tarReader, maxRestoreFileSize+1))
		if err != nil {
			return ErrRestoreFailed
		}
		if int64(len(fileData)) > maxRestoreFileSize {
			return ErrRestoreFailed
		}

		name := filepath.ToSlash(header.Name)

		var base, rel string
		if strings.HasPrefix(name, defaultDir+"/") {
			base, rel = vaultDir, name[len(defaultDir)+1:]
		} else {
			base, rel = sshDir, name
		}
		targetPath := filepath.Join(base, filepath.FromSlash(rel))

		// Containment guard: filepath.Join resolves ".." components, so if the
		// result escapes base it's a path-traversal attempt — skip it. This
		// replaces the fragile strings.Contains(name, "..") check.
		cleanBase := filepath.Clean(base)
		if targetPath != cleanBase && !strings.HasPrefix(targetPath, cleanBase+string(os.PathSeparator)) {
			continue
		}

		moved := false
		if _, statErr := os.Stat(targetPath); !errors.Is(statErr, os.ErrNotExist) {
			if err := os.Rename(targetPath, targetPath+".pre-restore"); err != nil {
				return errors.Join(ErrRestoreFailed, err)
			}
			moved = true
		}

		// rollback puts the pre-existing file back if we moved one aside. Its own
		// failure is joined into the returned error so the user learns the target
		// is now in an inconsistent state instead of it being silently swallowed.
		rollback := func() error {
			if !moved {
				return nil
			}
			return os.Rename(targetPath+".pre-restore", targetPath)
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
			return errors.Join(ErrRestoreFailed, err, rollback())
		}

		dir := filepath.Dir(targetPath)
		tmp, err := os.CreateTemp(dir, "restore-*.tmp")
		if err != nil {
			return errors.Join(ErrRestoreFailed, err, rollback())
		}
		tmpPath := tmp.Name()

		if _, err := tmp.Write(fileData); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
			return errors.Join(ErrRestoreFailed, err, rollback())
		}
		if err := tmp.Close(); err != nil {
			_ = os.Remove(tmpPath)
			return errors.Join(ErrRestoreFailed, err, rollback())
		}
		if err := os.Rename(tmpPath, targetPath); err != nil {
			_ = os.Remove(tmpPath)
			return errors.Join(ErrRestoreFailed, err, rollback())
		}
		// Clamp to at most owner rw; never trust the archive's mode bits (a
		// restored private key must not land at 0777).
		if err := os.Chmod(targetPath, os.FileMode(header.Mode).Perm()&0600); err != nil {
			return errors.Join(ErrRestoreFailed, err, rollback())
		}

		if moved {
			_ = os.Remove(targetPath + ".pre-restore")
		}
	}

	return nil
}
