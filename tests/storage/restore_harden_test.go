package storage_test

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"filippo.io/age"
	"github.com/gateway-of-last-resort/keyward/internal/storage"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

type tarEntry struct {
	name     string
	mode     int64
	data     []byte
	typeflag byte // zero means tar.TypeReg
	linkname string
}

// writeBackupArchive builds a tar of entries, encrypts it to id, and writes it
// to path — used to craft hostile archives CreateBackup would never produce.
func writeBackupArchive(t *testing.T, path string, id *age.X25519Identity, entries []tarEntry) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		size := int64(len(e.data))
		if typeflag != tar.TypeReg {
			size = 0
		}
		if err := tw.WriteHeader(&tar.Header{
			Name:     e.name,
			Mode:     e.mode,
			Size:     size,
			Typeflag: typeflag,
			Linkname: e.linkname,
		}); err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
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

// TestRestore_ClampPerFileKind pins which bits survive a restore: a public half
// keeps the read bits it was archived with (0644 used to be narrowed to 0600 by
// the blanket clamp), while everything else stays owner-only. Archive modes are
// still never trusted, so a hostile 0777 is clamped either way.
func TestRestore_ClampPerFileKind(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are synthetic on Windows")
	}

	tests := []struct {
		name     string
		archived int64
		want     os.FileMode
	}{
		{name: "id_rsa.pub", archived: 0644, want: 0644},
		{name: "id_rsa.pub", archived: 0600, want: 0600},
		{name: "id_rsa.pub", archived: 0777, want: 0644},
		{name: "id_rsa", archived: 0644, want: 0600},
		{name: "config", archived: 0644, want: 0600},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/"+strconv.FormatInt(tt.archived, 8), func(t *testing.T) {
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
			backup := filepath.Join(root, "backup.tar.age")
			writeBackupArchive(t, backup, id, []tarEntry{
				{name: tt.name, mode: tt.archived, data: []byte("DATA")},
			})

			if err := storage.RestoreBackup(backup, sshDir, vaultDir, id); err != nil {
				t.Fatalf("RestoreBackup: %v", err)
			}

			info, err := os.Stat(filepath.Join(sshDir, tt.name))
			if err != nil {
				t.Fatalf("restored file missing: %v", err)
			}
			if info.Mode().Perm() != tt.want {
				t.Errorf("perm = %04o, want %04o", info.Mode().Perm(), tt.want)
			}
		})
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
		{name: "id_rsa", mode: 0777, data: []byte("PRIVATE")},  // world-writable
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

// Keyward only archives regular files under ~/.ssh and the vault. A crafted or
// corrupt archive must not turn a link or directory entry into an empty file
// over a real one, nor replace ~/.ssh or the vault directory itself ("." and ".keyward/.").
func TestRestore_SkipsNonRegularAndBaseEntries(t *testing.T) {
	sshDir, vaultDir := t.TempDir(), t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(sshDir, "config")
	if err := os.WriteFile(cfg, []byte("Host keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "b.tar.age")
	writeBackupArchive(t, archive, id, []tarEntry{
		{name: "config", mode: 0o777, typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		{name: "subdir", mode: 0o755, typeflag: tar.TypeDir},
		{name: ".", mode: 0o600, data: []byte("x")},
		{name: ".keyward/.", mode: 0o600, data: []byte("x")},
		{name: "restored", mode: 0o600, data: []byte("ok")},
	})

	if err := storage.RestoreBackup(archive, sshDir, vaultDir, id); err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}

	for _, dir := range []string{sshDir, vaultDir} {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			t.Fatalf("%s is no longer a directory (err %v)", dir, err)
		}
	}
	if got, _ := os.ReadFile(cfg); string(got) != "Host keep\n" {
		t.Errorf("config overwritten by a symlink entry: %q", got)
	}
	if _, err := os.Lstat(filepath.Join(sshDir, "subdir")); err == nil {
		t.Error("directory entry was restored as a file")
	}
	if got, _ := os.ReadFile(filepath.Join(sshDir, "restored")); string(got) != "ok" {
		t.Errorf("regular entry not restored: %q", got)
	}
}
