package storage_test

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
	"github.com/gateway-of-last-resort/keyward/internal/storage"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

type tarEntry struct {
	name string
	mode int64
	data []byte
}

// writeBackupArchive builds a tar of entries, encrypts it to id, and writes it
// to path — used to craft hostile archives CreateBackup would never produce.
func writeBackupArchive(t *testing.T, path string, id *age.X25519Identity, entries []tarEntry) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name:     e.name,
			Mode:     e.mode,
			Size:     int64(len(e.data)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	ct, err := crypto.Encrypt(buf.Bytes(), id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, ct, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRestore_ClampsPermissionsAndBlocksTraversal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are synthetic on Windows")
	}
	root := t.TempDir()
	sshDir := filepath.Join(root, "ssh")
	vaultDir := filepath.Join(root, "vault")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := storage.Init(vaultDir); err != nil {
		t.Fatal(err)
	}

	id := newIdentity(t)
	backup := filepath.Join(root, "hostile.tar.age")
	writeBackupArchive(t, backup, id, []tarEntry{
		{name: "id_rsa", mode: 0777, data: []byte("PRIVATE")}, // world-writable
		{name: "../escape", mode: 0644, data: []byte("pwned")}, // path traversal
	})

	if err := storage.RestoreBackup(backup, sshDir, vaultDir, id); err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}

	// The restored key must be clamped to at most 0600, never 0777.
	info, err := os.Stat(filepath.Join(sshDir, "id_rsa"))
	if err != nil {
		t.Fatalf("restored key missing: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("restored key perm = %04o, want 0600", info.Mode().Perm())
	}

	// The traversal entry must not have escaped sshDir.
	if _, err := os.Stat(filepath.Join(root, "escape")); !os.IsNotExist(err) {
		t.Errorf("path traversal wrote outside base; stat err = %v", err)
	}
}
