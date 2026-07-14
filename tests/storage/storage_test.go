package storage_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/gateway-of-last-resort/keyward/internal/storage"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

// newIdentity generates a fresh X25519 identity for test use.
func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

// testMeta returns a KeyMetadata with the given fingerprint and populated fields.
func testMeta(fingerprint string) storage.KeyMetadata {
	return storage.KeyMetadata{
		Fingerprint: fingerprint,
		Tags:        []string{"test"},
		Note:        "note for " + fingerprint,
		LinkedHosts: []string{"host1"},
	}
}

// ── Init ─────────────────────────────────────────────────────────────────────

func TestInit_CreatesDirs(t *testing.T) {
	vaultDir := filepath.Join(t.TempDir(), ".keyward")

	if err := storage.Init(vaultDir); err != nil {
		t.Fatalf("Init: %v", err)
	}

	for _, sub := range []string{".", "backups", filepath.Join("backups", "config")} {
		p := filepath.Join(vaultDir, sub)
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("dir %q not created: %v", p, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%q is not a directory", p)
		}
	}
}

func TestInit_DirPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod semantics differ on Windows")
	}

	vaultDir := filepath.Join(t.TempDir(), ".keyward")
	if err := storage.Init(vaultDir); err != nil {
		t.Fatalf("Init: %v", err)
	}

	info, err := os.Stat(vaultDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("vaultDir perms = %04o, want 0700", info.Mode().Perm())
	}
}

// TestInit_TightensExistingDirPermissions ensures Init repairs a pre-existing
// vault directory that was created with laxer permissions.
func TestInit_TightensExistingDirPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod semantics differ on Windows")
	}

	vaultDir := filepath.Join(t.TempDir(), ".keyward")
	if err := os.MkdirAll(vaultDir, 0755); err != nil { // too permissive
		t.Fatal(err)
	}

	if err := storage.Init(vaultDir); err != nil {
		t.Fatalf("Init: %v", err)
	}

	info, err := os.Stat(vaultDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("existing vaultDir perms = %04o, want Init to tighten to 0700", info.Mode().Perm())
	}
}

// ── Save / Load ───────────────────────────────────────────────────────────────

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	id := newIdentity(t)

	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	for _, fp := range []string{"SHA256:aaaa", "SHA256:bbbb"} {
		if err := storage.Put(s, testMeta(fp)); err != nil {
			t.Fatal(err)
		}
	}

	if err := storage.Save(s, dir, id); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := storage.Load(dir, id)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	for _, fp := range []string{"SHA256:aaaa", "SHA256:bbbb"} {
		got, err := storage.Get(loaded, fp)
		if err != nil {
			t.Errorf("Get(%q) after Load: %v", fp, err)
			continue
		}
		want := testMeta(fp)
		if got.Note != want.Note {
			t.Errorf("Note = %q, want %q", got.Note, want.Note)
		}
	}
}

// TestSaveLoad_StampsSchemaVersion checks that Save stamps CurrentSchemaVersion
// onto both the on-disk store and the caller's in-memory Store, and that Load
// reads it back.
func TestSaveLoad_StampsSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	id := newIdentity(t)

	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	if err := storage.Put(s, testMeta("SHA256:aaaa")); err != nil {
		t.Fatal(err)
	}

	if err := storage.Save(s, dir, id); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if s.SchemaVersion != storage.CurrentSchemaVersion {
		t.Errorf("caller SchemaVersion = %d, want %d", s.SchemaVersion, storage.CurrentSchemaVersion)
	}

	loaded, err := storage.Load(dir, id)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.SchemaVersion != storage.CurrentSchemaVersion {
		t.Errorf("loaded SchemaVersion = %d, want %d", loaded.SchemaVersion, storage.CurrentSchemaVersion)
	}
}

// TestLoad_LegacyFileHasZeroSchemaVersion emulates a metadata file written before
// versioning existed (v0.5.x): its JSON has no SchemaVersion field. Load must read
// it successfully and report SchemaVersion 0 — the backward-read guarantee that the
// format-stability policy commits to.
func TestLoad_LegacyFileHasZeroSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	id := newIdentity(t)

	// Encrypt a legacy-shaped store: no SchemaVersion key at all.
	legacyJSON := []byte(`{"Keys":{"SHA256:aaaa":{"Fingerprint":"SHA256:aaaa","Tags":["test"],"Note":"legacy","LastRotatedAt":"0001-01-01T00:00:00Z","LinkedHosts":["host1"]}},"SavedAt":"0001-01-01T00:00:00Z"}`)
	ciphertext, err := crypto.Encrypt(legacyJSON, id.Recipient())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.age"), ciphertext, 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := storage.Load(dir, id)
	if err != nil {
		t.Fatalf("Load legacy file: %v", err)
	}
	if loaded.SchemaVersion != 0 {
		t.Errorf("legacy SchemaVersion = %d, want 0", loaded.SchemaVersion)
	}
	got, err := storage.Get(loaded, "SHA256:aaaa")
	if err != nil {
		t.Fatalf("Get after legacy Load: %v", err)
	}
	if got.Note != "legacy" {
		t.Errorf("Note = %q, want %q", got.Note, "legacy")
	}
}

func TestSave_UpdatesSavedAt(t *testing.T) {
	dir := t.TempDir()
	id := newIdentity(t)
	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}

	before := time.Now().Truncate(time.Second)
	if err := storage.Save(s, dir, id); err != nil {
		t.Fatalf("Save: %v", err)
	}
	after := time.Now().Add(time.Second)

	if s.SavedAt.IsZero() {
		t.Fatal("SavedAt not set on caller Store after Save")
	}
	if s.SavedAt.Before(before) || s.SavedAt.After(after) {
		t.Errorf("SavedAt = %v out of expected range [%v, %v]", s.SavedAt, before, after)
	}
}

// TestSave_FailureKeepsDataAndSavedAt injects a write failure by making the
// vault dir read-only. Save must fail, leave the previously saved metadata
// intact, and NOT advance the caller's SavedAt (which would claim a save that
// never hit disk).
func TestSave_FailureKeepsDataAndSavedAt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only dir does not block writes the same way on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission bits")
	}

	dir := t.TempDir()
	id := newIdentity(t)
	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	if err := storage.Put(s, testMeta("SHA256:first")); err != nil {
		t.Fatal(err)
	}
	if err := storage.Save(s, dir, id); err != nil {
		t.Fatalf("initial Save: %v", err)
	}
	savedAt := s.SavedAt

	// Add another key, then block writes and attempt to persist it.
	if err := storage.Put(s, testMeta("SHA256:second")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	if err := storage.Save(s, dir, id); err == nil {
		t.Fatal("expected Save to fail on a read-only directory")
	}

	// SavedAt must be unchanged: the write did not reach disk.
	if !s.SavedAt.Equal(savedAt) {
		t.Errorf("SavedAt advanced on failed Save: %v -> %v", savedAt, s.SavedAt)
	}

	// The first, successfully-saved state must still be loadable and must not
	// contain the second key.
	os.Chmod(dir, 0700)
	loaded, err := storage.Load(dir, id)
	if err != nil {
		t.Fatalf("Load after failed Save: %v", err)
	}
	if _, err := storage.Get(loaded, "SHA256:first"); err != nil {
		t.Errorf("first key lost after failed Save: %v", err)
	}
	if _, err := storage.Get(loaded, "SHA256:second"); err == nil {
		t.Error("second key must not be present after a failed Save")
	}

	// No orphaned .bak must remain after a rolled-back Save.
	if _, err := os.Stat(filepath.Join(dir, "metadata.age.bak")); !os.IsNotExist(err) {
		t.Errorf("metadata.age.bak should be rolled back, stat err = %v", err)
	}
}

func TestSave_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod semantics differ on Windows")
	}

	dir := t.TempDir()
	id := newIdentity(t)
	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}

	if err := storage.Save(s, dir, id); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "metadata.age"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("metadata.age perms = %04o, want 0600", info.Mode().Perm())
	}
}

func TestLoad_Empty(t *testing.T) {
	dir := t.TempDir()
	id := newIdentity(t)

	s, err := storage.Load(dir, id)
	if err != nil {
		t.Fatalf("Load on empty dir: %v", err)
	}
	if len(s.Keys) != 0 {
		t.Errorf("want empty store, got %d keys", len(s.Keys))
	}
}

func TestLoad_WrongIdentity(t *testing.T) {
	dir := t.TempDir()
	id1 := newIdentity(t)
	id2 := newIdentity(t)

	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	if err := storage.Save(s, dir, id1); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := storage.Load(dir, id2); err == nil {
		t.Fatal("Load with wrong identity: expected error, got nil")
	}
}

// TestLoad_BakRecovery simulates a crash where metadata.age was renamed to .bak
// but the new file was not yet written. Load must recover from .bak.
func TestLoad_BakRecovery(t *testing.T) {
	dir := t.TempDir()
	id := newIdentity(t)

	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	if err := storage.Put(s, testMeta("SHA256:bak1")); err != nil {
		t.Fatal(err)
	}
	if err := storage.Save(s, dir, id); err != nil {
		t.Fatalf("Save: %v", err)
	}

	metaPath := filepath.Join(dir, "metadata.age")
	if err := os.Rename(metaPath, metaPath+".bak"); err != nil {
		t.Fatalf("simulate crash rename: %v", err)
	}

	loaded, err := storage.Load(dir, id)
	if err != nil {
		t.Fatalf("Load after bak recovery: %v", err)
	}
	if _, err := storage.Get(loaded, "SHA256:bak1"); err != nil {
		t.Error("key not recovered from .bak file")
	}
}

// TestLoad_CorruptPrimaryRecoversFromBak covers a crash where the primary file
// exists but is truncated/corrupt while a good .bak is present. Load must
// recover from .bak, promote it, and return the data.
func TestLoad_CorruptPrimaryRecoversFromBak(t *testing.T) {
	dir := t.TempDir()
	id := newIdentity(t)

	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	if err := storage.Put(s, testMeta("SHA256:good")); err != nil {
		t.Fatal(err)
	}
	if err := storage.Save(s, dir, id); err != nil {
		t.Fatalf("Save: %v", err)
	}

	metaPath := filepath.Join(dir, "metadata.age")
	bakPath := metaPath + ".bak"

	// Keep a valid copy as .bak, then corrupt the primary in place.
	good, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bakPath, good, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, []byte("garbage-not-age"), 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := storage.Load(dir, id)
	if err != nil {
		t.Fatalf("Load with corrupt primary: %v", err)
	}
	if _, err := storage.Get(loaded, "SHA256:good"); err != nil {
		t.Error("key not recovered from .bak when primary was corrupt")
	}

	// The good backup should have been promoted to the primary path.
	if _, err := os.Stat(bakPath); !os.IsNotExist(err) {
		t.Errorf(".bak should be promoted (removed); stat err = %v", err)
	}
	if _, err := storage.Load(dir, id); err != nil {
		t.Errorf("primary not usable after promotion: %v", err)
	}
}

// ── Get ───────────────────────────────────────────────────────────────────────

func TestGet(t *testing.T) {
	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	if err := storage.Put(s, testMeta("SHA256:get1")); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		fingerprint string
		wantErr     error
	}{
		{"found", "SHA256:get1", nil},
		{"not_found", "SHA256:missing", storage.ErrNotFound},
		{"empty_fingerprint", "", storage.ErrInvalidFingerprint},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := storage.Get(*s, tc.fingerprint)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && got.Fingerprint != tc.fingerprint {
				t.Errorf("Fingerprint = %q, want %q", got.Fingerprint, tc.fingerprint)
			}
		})
	}
}

// ── Put ───────────────────────────────────────────────────────────────────────

func TestPut_StoresMetadata(t *testing.T) {
	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	meta := testMeta("SHA256:put1")

	if err := storage.Put(s, meta); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := storage.Get(*s, "SHA256:put1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Note != meta.Note {
		t.Errorf("Note = %q, want %q", got.Note, meta.Note)
	}
}

func TestPut_Duplicate(t *testing.T) {
	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	if err := storage.Put(s, testMeta("SHA256:dup")); err != nil {
		t.Fatal(err)
	}

	err := storage.Put(s, testMeta("SHA256:dup"))
	if !errors.Is(err, storage.ErrAlreadyExists) {
		t.Errorf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestPut_EmptyFingerprint(t *testing.T) {
	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	err := storage.Put(s, storage.KeyMetadata{Fingerprint: ""})
	if !errors.Is(err, storage.ErrInvalidFingerprint) {
		t.Errorf("err = %v, want ErrInvalidFingerprint", err)
	}
}

func TestPut_InitializesNilSlices(t *testing.T) {
	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	if err := storage.Put(s, storage.KeyMetadata{Fingerprint: "SHA256:nilslice"}); err != nil {
		t.Fatal(err)
	}

	got, _ := storage.Get(*s, "SHA256:nilslice")
	if got.Tags == nil {
		t.Error("Tags should be initialised to empty slice, not nil")
	}
	if got.LinkedHosts == nil {
		t.Error("LinkedHosts should be initialised to empty slice, not nil")
	}
}

// ── Update ────────────────────────────────────────────────────────────────────

func TestUpdate_ModifiesMetadata(t *testing.T) {
	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	if err := storage.Put(s, testMeta("SHA256:upd1")); err != nil {
		t.Fatal(err)
	}

	err := storage.Update(s, "SHA256:upd1", func(m *storage.KeyMetadata) {
		m.Note = "updated"
		m.Tags = []string{"prod", "infra"}
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := storage.Get(*s, "SHA256:upd1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Note != "updated" {
		t.Errorf("Note = %q, want updated", got.Note)
	}
	if len(got.Tags) != 2 || got.Tags[0] != "prod" {
		t.Errorf("Tags = %v, want [prod infra]", got.Tags)
	}
}

func TestUpdate_Errors(t *testing.T) {
	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	noop := func(m *storage.KeyMetadata) {}

	cases := []struct {
		name        string
		fingerprint string
		wantErr     error
	}{
		{"not_found", "SHA256:missing", storage.ErrNotFound},
		{"empty_fingerprint", "", storage.ErrInvalidFingerprint},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := storage.Update(s, tc.fingerprint, noop)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// ── Delete ────────────────────────────────────────────────────────────────────

func TestDelete_RemovesKey(t *testing.T) {
	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	if err := storage.Put(s, testMeta("SHA256:del1")); err != nil {
		t.Fatal(err)
	}

	if err := storage.Delete(s, "SHA256:del1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := storage.Get(*s, "SHA256:del1")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound after Delete", err)
	}
}

func TestDelete_Errors(t *testing.T) {
	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}

	cases := []struct {
		name        string
		fingerprint string
		wantErr     error
	}{
		{"not_found", "SHA256:missing", storage.ErrNotFound},
		{"empty_fingerprint", "", storage.ErrInvalidFingerprint},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := storage.Delete(s, tc.fingerprint)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// ── List ──────────────────────────────────────────────────────────────────────

func TestList_SortedByFingerprint(t *testing.T) {
	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	for _, fp := range []string{"SHA256:zzz", "SHA256:aaa", "SHA256:mmm"} {
		if err := storage.Put(s, testMeta(fp)); err != nil {
			t.Fatal(err)
		}
	}

	list := storage.List(*s)
	if len(list) != 3 {
		t.Fatalf("want 3 keys, got %d", len(list))
	}

	want := []string{"SHA256:aaa", "SHA256:mmm", "SHA256:zzz"}
	for i, m := range list {
		if m.Fingerprint != want[i] {
			t.Errorf("List[%d] = %q, want %q", i, m.Fingerprint, want[i])
		}
	}
}

func TestList_Empty(t *testing.T) {
	s := storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	if list := storage.List(s); len(list) != 0 {
		t.Errorf("want empty list, got %d items", len(list))
	}
}

// ── CreateBackup / RestoreBackup ──────────────────────────────────────────────

func TestCreateRestoreBackup_RoundTrip(t *testing.T) {
	sshDir := t.TempDir()
	vaultDir := t.TempDir()
	restoreSSH := t.TempDir()
	restoreVault := t.TempDir()
	id := newIdentity(t)

	keyData := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZWtleQ==\n-----END OPENSSH PRIVATE KEY-----\n")
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), keyData, 0600); err != nil {
		t.Fatal(err)
	}

	s := &storage.Store{Keys: make(map[string]storage.KeyMetadata)}
	if err := storage.Put(s, testMeta("SHA256:backup1")); err != nil {
		t.Fatal(err)
	}
	if err := storage.Save(s, vaultDir, id); err != nil {
		t.Fatalf("Save before backup: %v", err)
	}

	res, err := storage.CreateBackup(sshDir, vaultDir, id)
	if err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Fatalf("backup file not created: %v", err)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("unexpected skipped files: %v", res.Skipped)
	}

	if err := storage.RestoreBackup(res.Path, restoreSSH, restoreVault, id); err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}

	// SSH file content preserved
	restoredKey, err := os.ReadFile(filepath.Join(restoreSSH, "id_ed25519"))
	if err != nil {
		t.Fatalf("restored key file missing: %v", err)
	}
	if !bytes.Equal(restoredKey, keyData) {
		t.Error("restored key content differs from original")
	}

	// Metadata restored and loadable
	s2, err := storage.Load(restoreVault, id)
	if err != nil {
		t.Fatalf("Load after restore: %v", err)
	}
	got, err := storage.Get(s2, "SHA256:backup1")
	if err != nil {
		t.Fatalf("Get after restore: %v", err)
	}
	if got.Note != testMeta("SHA256:backup1").Note {
		t.Errorf("restored Note = %q, want %q", got.Note, testMeta("SHA256:backup1").Note)
	}
}

func TestCreateBackup_SkipsKnownHostsAndAuthorizedKeys(t *testing.T) {
	sshDir := t.TempDir()
	vaultDir := t.TempDir()
	restoreSSH := t.TempDir()
	restoreVault := t.TempDir()
	id := newIdentity(t)

	os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte("host data"), 0644)
	os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte("auth data"), 0644)
	os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte("key data"), 0600)

	res, err := storage.CreateBackup(sshDir, vaultDir, id)
	if err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}

	if err := storage.RestoreBackup(res.Path, restoreSSH, restoreVault, id); err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}

	for _, skip := range []string{"known_hosts", "authorized_keys"} {
		if _, err := os.Stat(filepath.Join(restoreSSH, skip)); !os.IsNotExist(err) {
			t.Errorf("%q should not be present after restore", skip)
		}
	}
	if _, err := os.Stat(filepath.Join(restoreSSH, "id_ed25519")); err != nil {
		t.Errorf("id_ed25519 missing from restored backup: %v", err)
	}
}

func TestCreateBackup_ReportsSkippedUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("relies on unix file-permission semantics")
	}
	sshDir := t.TempDir()
	vaultDir := t.TempDir()
	restoreSSH := t.TempDir()
	restoreVault := t.TempDir()
	id := newIdentity(t)

	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte("good key"), 0600); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(sshDir, "id_locked")
	if err := os.WriteFile(locked, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0600) })
	// Root ignores the 0000 mode, so the file wouldn't be skipped — skip then.
	if _, err := os.ReadFile(locked); err == nil {
		t.Skip("cannot make a file unreadable (running as root?)")
	}

	res, err := storage.CreateBackup(sshDir, vaultDir, id)
	if err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "id_locked" {
		t.Fatalf("Skipped = %v, want [id_locked]", res.Skipped)
	}

	// The backup must still succeed and contain the readable key.
	if err := storage.RestoreBackup(res.Path, restoreSSH, restoreVault, id); err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(restoreSSH, "id_ed25519")); err != nil {
		t.Errorf("readable key missing from backup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(restoreSSH, "id_locked")); !os.IsNotExist(err) {
		t.Errorf("unreadable file should not be in the archive")
	}
}

func TestCreateBackup_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod semantics differ on Windows")
	}

	sshDir := t.TempDir()
	vaultDir := t.TempDir()
	id := newIdentity(t)

	res, err := storage.CreateBackup(sshDir, vaultDir, id)
	if err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}

	info, err := os.Stat(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("backup perms = %04o, want 0600", info.Mode().Perm())
	}
}

func TestCreateBackup_InvalidSSHDir(t *testing.T) {
	id := newIdentity(t)
	_, err := storage.CreateBackup("/nonexistent/ssh", t.TempDir(), id)
	if !errors.Is(err, storage.ErrBackupFailed) {
		t.Errorf("err = %v, want ErrBackupFailed", err)
	}
}

func TestRestoreBackup_NotFound(t *testing.T) {
	id := newIdentity(t)
	err := storage.RestoreBackup("/nonexistent/backup.tar.age", t.TempDir(), t.TempDir(), id)
	if !errors.Is(err, storage.ErrBackupNotFound) {
		t.Errorf("err = %v, want ErrBackupNotFound", err)
	}
}

func TestRestoreBackup_WrongIdentity(t *testing.T) {
	sshDir := t.TempDir()
	vaultDir := t.TempDir()
	id1 := newIdentity(t)
	id2 := newIdentity(t)

	res, err := storage.CreateBackup(sshDir, vaultDir, id1)
	if err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}

	err = storage.RestoreBackup(res.Path, t.TempDir(), t.TempDir(), id2)
	if !errors.Is(err, storage.ErrRestoreFailed) {
		t.Errorf("err = %v, want ErrRestoreFailed", err)
	}
}
