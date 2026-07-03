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

func CreateBackup(sshDir, vaultDir string, identity age.Identity) (string, error) {
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
		return "", ErrBackupFailed
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

	for _, f := range files {
		data, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}

		stat, err := os.Stat(f.path)
		if err != nil {
			continue
		}

		header := &tar.Header{
			Name:    f.tarName,
			Mode:    int64(stat.Mode().Perm()),
			Size:    int64(len(data)),
			ModTime: stat.ModTime(),
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			return "", ErrBackupFailed
		}
		if _, err := tarWriter.Write(data); err != nil {
			return "", ErrBackupFailed
		}
	}

	if err := tarWriter.Close(); err != nil {
		return "", ErrBackupFailed
	}

	x25519Identity, ok := identity.(*age.X25519Identity)
	if !ok {
		return "", ErrInvalidIdentity
	}

	plaintext := tarBuffer.Bytes()
	defer crypto.ZeroBytes(plaintext)

	ciphertext, err := crypto.Encrypt(plaintext, x25519Identity.Recipient())
	if err != nil {
		return "", ErrBackupFailed
	}

	backupPath := filepath.Join(vaultDir, backupDir)
	if err := os.MkdirAll(backupPath, 0700); err != nil {
		return "", ErrBackupFailed
	}

	filename := time.Now().Format("2006-01-02_15-04-05") + ".tar.age"
	finalPath := filepath.Join(backupPath, filename)

	if err := atomicWriteFile(finalPath, ciphertext, 0600); err != nil {
		return "", ErrBackupFailed
	}

	pruneBackups(backupPath, maxBackups)

	return finalPath, nil
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
func pruneBackups(dir string, max int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".tar.age") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	// entries are sorted by name (timestamp prefix), so oldest are first
	for len(files) > max {
		os.Remove(files[0])
		files = files[1:]
	}
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

		_, statErr := os.Stat(targetPath)
		if !errors.Is(statErr, os.ErrNotExist) {
			os.Rename(targetPath, targetPath+".pre-restore")
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
			os.Rename(targetPath+".pre-restore", targetPath)
			return ErrRestoreFailed
		}

		dir := filepath.Dir(targetPath)
		tmp, err := os.CreateTemp(dir, "restore-*.tmp")
		if err != nil {
			os.Rename(targetPath+".pre-restore", targetPath)
			return ErrRestoreFailed
		}
		tmpPath := tmp.Name()

		if _, err := tmp.Write(fileData); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			os.Rename(targetPath+".pre-restore", targetPath)
			return ErrRestoreFailed
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmpPath)
			os.Rename(targetPath+".pre-restore", targetPath)
			return ErrRestoreFailed
		}
		if err := os.Rename(tmpPath, targetPath); err != nil {
			os.Remove(tmpPath)
			os.Rename(targetPath+".pre-restore", targetPath)
			return ErrRestoreFailed
		}
		// Clamp to at most owner rw; never trust the archive's mode bits (a
		// restored private key must not land at 0777).
		if err := os.Chmod(targetPath, os.FileMode(header.Mode).Perm()&0600); err != nil {
			os.Rename(targetPath+".pre-restore", targetPath)
			return ErrRestoreFailed
		}

		os.Remove(targetPath + ".pre-restore")
	}

	return nil
}
