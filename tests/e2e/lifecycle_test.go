package e2e_test

// End-to-end lifecycle test crossing every package boundary the way the real
// program does: create a vault, generate keys, audit them, store metadata, back
// everything up, wipe the originals, restore, and verify nothing was lost. Uses
// the real filesystem (t.TempDir) and no mocks, matching the rest of tests/.

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
	"github.com/gateway-of-last-resort/keyward/internal/keys"
	"github.com/gateway-of-last-resort/keyward/internal/storage"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

func TestLifecycle_InitGenerateBackupRestore(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	vaultDir := filepath.Join(home, ".keyward")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}

	// 1. Vault: directory structure first (creates ~/.keyward), then the master
	//    key inside it.
	if err := storage.Init(vaultDir); err != nil {
		t.Fatalf("storage.Init: %v", err)
	}
	identity, err := crypto.InitMasterKey(filepath.Join(vaultDir, "master.key"), "correct horse")
	if err != nil {
		t.Fatalf("InitMasterKey: %v", err)
	}

	// 2. Generate two keys: a passphrase-protected ed25519 (clean) and a bare
	//    2048-bit RSA (deliberately weak, so the audit has something to report).
	edKey, err := keys.GenerateKeys(sshDir, keys.GenerateOptions{
		Algorithm:  keys.AlgorithmEd25519,
		Filename:   "id_ed25519",
		Comment:    "e2e@ed25519",
		Passphrase: []byte("hunter2 hunter2"),
	})
	if err != nil {
		t.Fatalf("GenerateKeys ed25519: %v", err)
	}
	if _, err := keys.GenerateKeys(sshDir, keys.GenerateOptions{
		Algorithm:            keys.AlgorithmRSA,
		Filename:             "id_rsa",
		BitSize:              2048,
		Comment:              "e2e@rsa",
		AllowEmptyPassphrase: true,
	}); err != nil {
		t.Fatalf("GenerateKeys rsa: %v", err)
	}

	// 3. Audit the discovered keys. The weak RSA key must make the report
	//    non-empty and the grade computed.
	discovered, err := keys.Parse(sshDir)
	if err != nil {
		t.Fatalf("keys.Parse: %v", err)
	}
	if len(discovered) != 2 {
		t.Fatalf("discovered %d keys, want 2", len(discovered))
	}
	report := audit.Run(discovered, nil, sshDir)
	if report.Grade == "" {
		t.Error("audit produced no grade")
	}
	if len(report.Results) == 0 {
		t.Error("audit of a bare 2048-bit RSA key produced no findings")
	}
	if report.Points < 0 || report.Points > 100 {
		t.Errorf("audit points = %d, out of range", report.Points)
	}

	// 4. Store metadata (tags + note) keyed by the ed25519 fingerprint.
	store := storage.Store{Keys: map[string]storage.KeyMetadata{}}
	if err := storage.Put(&store, storage.KeyMetadata{
		Fingerprint: edKey.Fingerprint,
		Tags:        []string{"work", "laptop"},
		Note:        "primary key",
		LinkedHosts: []string{"github.com"},
	}); err != nil {
		t.Fatalf("storage.Put: %v", err)
	}
	if err := storage.Save(&store, vaultDir, identity); err != nil {
		t.Fatalf("storage.Save: %v", err)
	}

	// Snapshot the private key bytes before wiping, to prove a byte-identical
	// restore later.
	edPrivBefore := readFile(t, edKey.PrivateKeyPath)

	// 5. Back everything up.
	res, err := storage.CreateBackup(sshDir, vaultDir, identity)
	if err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("backup skipped entries: %v", res.Skipped)
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Fatalf("backup archive missing: %v", err)
	}

	// 6. Wipe the private keys and the metadata vault.
	mustRemove(t, edKey.PrivateKeyPath)
	mustRemove(t, filepath.Join(sshDir, "id_rsa"))
	mustRemove(t, filepath.Join(vaultDir, "metadata.age"))

	// 7. Restore.
	if err := storage.RestoreBackup(res.Path, sshDir, vaultDir, identity); err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}

	// 8a. Private key is back, byte-for-byte.
	edPrivAfter := readFile(t, edKey.PrivateKeyPath)
	if !bytes.Equal(edPrivBefore, edPrivAfter) {
		t.Error("restored ed25519 private key differs from the original")
	}

	// 8b. Metadata decrypts and carries the same tags and note.
	loaded, err := storage.Load(vaultDir, identity)
	if err != nil {
		t.Fatalf("storage.Load after restore: %v", err)
	}
	meta, err := storage.Get(loaded, edKey.Fingerprint)
	if err != nil {
		t.Fatalf("Get restored metadata: %v", err)
	}
	if meta.Note != "primary key" || len(meta.Tags) != 2 {
		t.Errorf("restored metadata = %+v, want note+2 tags intact", meta)
	}

	// 8c. Restored private key is not group/world accessible.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(edKey.PrivateKeyPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("restored key perms = %04o, want 0600", info.Mode().Perm())
		}
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
}
