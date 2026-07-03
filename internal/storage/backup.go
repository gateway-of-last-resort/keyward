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

		fileData, err := io.ReadAll(tarReader)
		if err != nil {
			return ErrRestoreFailed
		}

		if strings.Contains(header.Name, "..") {
			continue
		}

		name := filepath.ToSlash(header.Name)

		var targetPath string
		if strings.HasPrefix(name, defaultDir+"/") {
			rel := name[len(defaultDir)+1:]
			targetPath = filepath.Join(vaultDir, rel)
		} else {
			targetPath = filepath.Join(sshDir, name)
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
		if err := os.Chmod(targetPath, os.FileMode(header.Mode).Perm()); err != nil {
			os.Rename(targetPath+".pre-restore", targetPath)
			return ErrRestoreFailed
		}

		os.Remove(targetPath + ".pre-restore")
	}

	return nil
}
