package storage

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"io/fs"
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
	type archiveEntry struct {
		path    string
		tarName string
	}

	if fi, err := os.Stat(sshDir); err != nil || !fi.IsDir() {
		return BackupResult{}, ErrBackupFailed
	}

	var files []archiveEntry
	var skipped []string
	walkErr := filepath.WalkDir(sshDir, func(path string, d fs.DirEntry, err error) error {
		if path == sshDir {
			return err
		}
		rel, relErr := filepath.Rel(sshDir, path)
		if relErr != nil {
			return relErr
		}
		tarName := filepath.ToSlash(rel)
		if err != nil {
			skipped = append(skipped, tarName)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		topLevel := !strings.Contains(tarName, "/")

		switch {
		case d.IsDir():
			// A top-level .keyward would collide with the prefix restore uses
			// for vault files.
			if topLevel && tarName == defaultDir {
				skipped = append(skipped, tarName)
				return fs.SkipDir
			}
			return nil
		case d.Type()&fs.ModeSymlink != 0:
			// A link to a file is archived by content, as before; a link to a
			// directory is not followed, so a loop can't recurse forever.
			if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
				skipped = append(skipped, tarName)
				return nil
			}
		case !d.Type().IsRegular():
			// Sockets (ControlMaster) and FIFOs carry no data, and reading a
			// FIFO would block the backup.
			return nil
		}
		if topLevel && (tarName == "known_hosts" || tarName == "authorized_keys") {
			return nil
		}
		files = append(files, archiveEntry{path: path, tarName: tarName})
		return nil
	})
	if walkErr != nil {
		return BackupResult{}, ErrBackupFailed
	}

	metaPath := filepath.Join(vaultDir, metadataFile)
	files = append(files, archiveEntry{
		path:    metaPath,
		tarName: defaultDir + "/" + metadataFile,
	})

	tarBuffer := new(bytes.Buffer)
	tarWriter := tar.NewWriter(tarBuffer)

	for _, f := range files {
		data, stat, err := readForBackup(f.path, f.path == metaPath)
		if errors.Is(err, os.ErrNotExist) && f.path == metaPath {
			continue
		}
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

// readForBackup reads a file and its mode for archiving. The metadata file is
// read under metaMu so a concurrent Save can't leave it momentarily absent.
func readForBackup(path string, isMeta bool) ([]byte, os.FileInfo, error) {
	if isMeta {
		metaMu.Lock()
		defer metaMu.Unlock()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	stat, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	return data, stat, nil
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

	// Restore can overwrite metadata.age; hold metaMu so it never interleaves
	// with a background Save of the in-memory store.
	metaMu.Lock()
	defer metaMu.Unlock()

	tarReader := tar.NewReader(bytes.NewReader(plaintext))

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrRestoreFailed
		}

		// Keyward only ever archives regular files. A directory or link entry
		// would otherwise be written out as an empty file over the real one.
		if header.Typeflag != tar.TypeReg {
			continue
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
		// result escapes base it's a path-traversal attempt; skip it. An entry
		// that resolves to base itself ("." or ".keyward/") is skipped too: it
		// would move the whole ~/.ssh or vault directory aside and put a file there.
		cleanBase := filepath.Clean(base)
		if !strings.HasPrefix(targetPath, cleanBase+string(os.PathSeparator)) {
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

		// Clamp; never trust the archive's mode bits (a restored private key must
		// not land at 0777). A public half keeps the read bits it was archived
		// with: 0644 is its normal mode, and restoring it at 0600 narrows the
		// file behind the user's back.
		mask := os.FileMode(0600)
		if strings.HasSuffix(name, ".pub") {
			mask = 0644
		}
		if err := atomicWriteFile(targetPath, fileData, os.FileMode(header.Mode).Perm()&mask); err != nil {
			return errors.Join(ErrRestoreFailed, err, rollback())
		}

		if moved {
			_ = os.Remove(targetPath + ".pre-restore")
		}
	}

	return nil
}
