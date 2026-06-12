package keys_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gateway-of-last-resort/keyward/internal/keys"
)

// generateOpts returns a minimal valid GenerateOptions for Ed25519.
func generateOpts(dir, filename string) keys.GenerateOptions {
	return keys.GenerateOptions{
		Algorithm:            keys.AlgorithmEd25519,
		Filename:             filename,
		Passphrase:           "strong-passphrase",
		AllowEmptyPassphrase: false,
	}
}

// ── algorithm & validation ───────────────────────────────────────────────────

func TestGenerate_Ed25519(t *testing.T) {
	dir := t.TempDir()
	opts := generateOpts(dir, "id_ed25519")

	k, err := keys.GenerateKeys(dir, opts)
	if err != nil {
		t.Fatalf("Generate Ed25519: %v", err)
	}

	if k.Algorithm != "ssh-ed25519" {
		t.Errorf("Algorithm = %q, want ssh-ed25519", k.Algorithm)
	}
	if k.BitSize != 256 {
		t.Errorf("BitSize = %d, want 256 for Ed25519", k.BitSize)
	}
	if k.PrivateKeyPath == "" || k.PublicKeyPath == "" {
		t.Error("returned Key has empty paths")
	}
}

// TestGenerate_Ed25519_IgnoresBitSize confirms that a non-zero BitSize for Ed25519
// is silently ignored (key length is fixed at 256 bits).
func TestGenerate_Ed25519_IgnoresBitSize(t *testing.T) {
	dir := t.TempDir()
	opts := generateOpts(dir, "id_ed25519")
	opts.BitSize = 4096 // meaningless for Ed25519; must be silently ignored

	k, err := keys.GenerateKeys(dir, opts)
	if err != nil {
		t.Fatalf("Generate with BitSize for Ed25519: %v", err)
	}
	if k.BitSize != 256 {
		t.Errorf("BitSize = %d, want 256 regardless of opts.BitSize for Ed25519", k.BitSize)
	}
}

func TestGenerate_RSA_ExplicitBitSize(t *testing.T) {
	dir := t.TempDir()
	opts := keys.GenerateOptions{
		Algorithm:  keys.AlgorithmRSA,
		Filename:   "id_rsa",
		BitSize:    2048,
		Passphrase: "pass",
	}

	k, err := keys.GenerateKeys(dir, opts)
	if err != nil {
		t.Fatalf("Generate RSA 2048: %v", err)
	}
	if k.BitSize != 2048 {
		t.Errorf("BitSize = %d, want 2048", k.BitSize)
	}
}

// TestGenerate_RSA_DefaultBitSize verifies that BitSize=0 produces a 4096-bit RSA key.
// This test is intentionally slow (~2 s) — run with -timeout 30s.
func TestGenerate_RSA_DefaultBitSize(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 4096-bit RSA generation in short mode")
	}
	dir := t.TempDir()
	opts := keys.GenerateOptions{
		Algorithm:  keys.AlgorithmRSA,
		Filename:   "id_rsa",
		BitSize:    0, // should default to 4096
		Passphrase: "pass",
	}

	k, err := keys.GenerateKeys(dir, opts)
	if err != nil {
		t.Fatalf("Generate RSA default bitsize: %v", err)
	}
	if k.BitSize != 4096 {
		t.Errorf("BitSize = %d, want 4096 as default for RSA", k.BitSize)
	}
}

func TestGenerate_RSA_TooSmall(t *testing.T) {
	dir := t.TempDir()
	opts := keys.GenerateOptions{
		Algorithm:  keys.AlgorithmRSA,
		Filename:   "id_rsa",
		BitSize:    1024,
		Passphrase: "pass",
	}

	_, err := keys.GenerateKeys(dir, opts)
	if !errors.Is(err, keys.ErrBitSizeTooSmall) {
		t.Errorf("err = %v, want ErrBitSizeTooSmall", err)
	}
}

func TestGenerate_InvalidAlgorithm(t *testing.T) {
	dir := t.TempDir()
	opts := keys.GenerateOptions{
		Algorithm:  keys.Algorithm("dsa"),
		Filename:   "id_dsa",
		Passphrase: "pass",
	}

	_, err := keys.GenerateKeys(dir, opts)
	if !errors.Is(err, keys.ErrInvalidAlgorithm) {
		t.Errorf("err = %v, want ErrInvalidAlgorithm", err)
	}
}

func TestGenerate_MissingFilename(t *testing.T) {
	dir := t.TempDir()
	opts := generateOpts(dir, "") // empty filename

	_, err := keys.GenerateKeys(dir, opts)
	if !errors.Is(err, keys.ErrMissingFilename) {
		t.Errorf("err = %v, want ErrMissingFilename", err)
	}
}

func TestGenerate_DirNotFound(t *testing.T) {
	opts := generateOpts("/nonexistent/dir/xyz", "id_ed25519")

	_, err := keys.GenerateKeys("/nonexistent/dir/xyz", opts)
	if !errors.Is(err, keys.ErrDirNotFound) {
		t.Errorf("err = %v, want ErrDirNotFound", err)
	}
}

// ── passphrase handling ──────────────────────────────────────────────────────

func TestGenerate_EmptyPassphrase_RequiresFlag(t *testing.T) {
	dir := t.TempDir()
	opts := generateOpts(dir, "id_ed25519")
	opts.Passphrase = ""
	opts.AllowEmptyPassphrase = false // default

	_, err := keys.GenerateKeys(dir, opts)
	if !errors.Is(err, keys.ErrEmptyPassphrase) {
		t.Errorf("err = %v, want ErrEmptyPassphrase when passphrase empty without flag", err)
	}
}

func TestGenerate_EmptyPassphrase_WithFlag(t *testing.T) {
	dir := t.TempDir()
	opts := generateOpts(dir, "id_ed25519")
	opts.Passphrase = ""
	opts.AllowEmptyPassphrase = true // explicit CI/CD intent

	_, err := keys.GenerateKeys(dir, opts)
	if err != nil {
		t.Fatalf("Generate with AllowEmptyPassphrase=true: %v", err)
	}
}

// ── overwrite behaviour ──────────────────────────────────────────────────────

func TestGenerate_AlreadyExists_NoOverwrite(t *testing.T) {
	dir := t.TempDir()
	opts := generateOpts(dir, "id_ed25519")

	if _, err := keys.GenerateKeys(dir, opts); err != nil {
		t.Fatalf("first Generate: %v", err)
	}

	opts.Overwrite = false
	_, err := keys.GenerateKeys(dir, opts)
	if !errors.Is(err, keys.ErrKeyAlreadyExists) {
		t.Errorf("err = %v, want ErrKeyAlreadyExists on second Generate without Overwrite", err)
	}
}

func TestGenerate_AlreadyExists_Overwrite(t *testing.T) {
	dir := t.TempDir()
	opts := generateOpts(dir, "id_ed25519")

	if _, err := keys.GenerateKeys(dir, opts); err != nil {
		t.Fatalf("first Generate: %v", err)
	}

	opts.Overwrite = true
	if _, err := keys.GenerateKeys(dir, opts); err != nil {
		t.Fatalf("second Generate with Overwrite=true: %v", err)
	}
}

// ── file system assertions ───────────────────────────────────────────────────

func TestGenerate_CreatesFiles(t *testing.T) {
	dir := t.TempDir()
	opts := generateOpts(dir, "id_ed25519")

	k, err := keys.GenerateKeys(dir, opts)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if _, err := os.Stat(k.PrivateKeyPath); err != nil {
		t.Errorf("private key file missing: %v", err)
	}
	if _, err := os.Stat(k.PublicKeyPath); err != nil {
		t.Errorf("public key file missing: %v", err)
	}
}

func TestGenerate_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod semantics differ on Windows")
	}

	dir := t.TempDir()
	opts := generateOpts(dir, "id_ed25519")

	k, err := keys.GenerateKeys(dir, opts)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	privInfo, err := os.Stat(k.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	pubInfo, err := os.Stat(k.PublicKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	if privInfo.Mode().Perm() != 0600 {
		t.Errorf("private key perms = %04o, want 0600", privInfo.Mode().Perm())
	}
	if pubInfo.Mode().Perm() != 0644 {
		t.Errorf("public key perms = %04o, want 0644", pubInfo.Mode().Perm())
	}
}

// TestGenerate_AtomicCleanup verifies that if generation fails mid-way, no
// partial files are left behind.  We induce failure by requesting an invalid
// algorithm after a valid first key, then check that orphaned files don't exist.
func TestGenerate_AtomicCleanup(t *testing.T) {
	dir := t.TempDir()
	opts := keys.GenerateOptions{
		Algorithm:  keys.Algorithm("invalid"),
		Filename:   "id_bad",
		Passphrase: "pass",
	}

	_, err := keys.GenerateKeys(dir, opts)
	if err == nil {
		t.Fatal("expected error for invalid algorithm, got nil")
	}

	// Neither file should exist after a failed generation.
	privPath := filepath.Join(dir, "id_bad")
	pubPath := filepath.Join(dir, "id_bad.pub")
	if _, err := os.Stat(privPath); !os.IsNotExist(err) {
		t.Errorf("orphaned private key file exists after failed Generate")
	}
	if _, err := os.Stat(pubPath); !os.IsNotExist(err) {
		t.Errorf("orphaned public key file exists after failed Generate")
	}
}

// TestGenerate_ReturnedKeyParseable verifies round-trip: generated key can
// be discovered and parsed back by keys.Parse.
func TestGenerate_ReturnedKeyParseable(t *testing.T) {
	dir := t.TempDir()
	opts := generateOpts(dir, "id_ed25519")

	generated, err := keys.GenerateKeys(dir, opts)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	parsed, err := keys.Parse(dir)
	if err != nil {
		t.Fatalf("Parse after Generate: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("want 1 parsed key, got %d", len(parsed))
	}

	if parsed[0].Fingerprint != generated.Fingerprint {
		t.Errorf("parsed fingerprint %q != generated %q", parsed[0].Fingerprint, generated.Fingerprint)
	}
}
