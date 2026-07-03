package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gateway-of-last-resort/keyward/internal/keys"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func writeUnencryptedKey(t *testing.T, dir, name string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func writeEncryptedKey(t *testing.T, dir, name string, passphrase []byte) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", passphrase)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// baseKey возвращает «чистый» ключ без findings.
// Файл реальный и зашифрованный — CheckPassphrase не упадёт.
func baseKey(t *testing.T) keys.Key {
	t.Helper()
	dir := t.TempDir()
	privPath := writeEncryptedKey(t, dir, "id_ed25519", []byte("testpass"))
	pubPath := privPath + ".pub"
	if err := os.WriteFile(pubPath, []byte("ssh-ed25519 AAAA test@host\n"), 0644); err != nil {
		t.Fatalf("WriteFile pub: %v", err)
	}
	return keys.Key{
		PrivateKeyPath: privPath,
		PublicKeyPath:  pubPath,
		HasPassphrase:  true,
		IsPublicOnly:   false,
		PrivatePerm:    0600,
		PublicPerm:     0644,
		Algorithm:      "ssh-ed25519",
		BitSize:        256,
		ModifiedAt:     time.Now(),
		Fingerprint:    "SHA256:test",
		Comment:        "test@host",
	}
}

func hasSeverity(results []AuditResult, sev Severity) bool {
	for _, r := range results {
		if r.Severity == sev {
			return true
		}
	}
	return false
}

// allHaveFix — контракт из спека: каждый AuditResult обязан иметь непустой Fix.
func allHaveFix(t *testing.T, results []AuditResult) {
	t.Helper()
	for _, r := range results {
		if r.Fix == "" {
			t.Errorf("AuditResult{Severity:%s Message:%q} has empty Fix field", r.Severity, r.Message)
		}
	}
}

// ── CheckPassphrase ───────────────────────────────────────────────────────────

func TestCheckPassphrase_NoPassphrase_Critical(t *testing.T) {
	dir := t.TempDir()
	privPath := writeUnencryptedKey(t, dir, "id_ed25519")

	k := baseKey(t)
	k.PrivateKeyPath = privPath

	results := checkPassphrase(k)

	if !hasSeverity(results, Critical) {
		t.Error("unencrypted key should produce Critical finding")
	}
	allHaveFix(t, results)
}

func TestCheckPassphrase_WithPassphrase_Clean(t *testing.T) {
	k := baseKey(t) // зашифрованный ключ

	results := checkPassphrase(k)

	if hasSeverity(results, Critical) || hasSeverity(results, Warning) {
		t.Errorf("encrypted key should produce no findings, got: %v", results)
	}
}

// TestCheckPassphrase_PublicOnly_NoFinding — у публичного ключа нет PrivateKeyPath,
// функция должна вернуть nil без паники.
func TestCheckPassphrase_PublicOnly_NoFinding(t *testing.T) {
	k := baseKey(t)
	k.PrivateKeyPath = "" // публичный ключ — нет приватного файла
	k.IsPublicOnly = true

	results := checkPassphrase(k)

	if hasSeverity(results, Critical) {
		t.Error("public-only key should not produce Critical from CheckPassphrase")
	}
}

// A key that is not public-only but has no recognized private path (junk before
// the PEM header) must not be silently skipped.
func TestCheckPassphrase_UnrecognizedPrivate_Warning(t *testing.T) {
	k := baseKey(t)
	k.PrivateKeyPath = ""  // parse couldn't recognize the private half
	k.IsPublicOnly = false // but it's not a public-only key

	results := checkPassphrase(k)

	if !hasSeverity(results, Warning) {
		t.Error("unrecognized private key should produce a Warning, not silence")
	}
	allHaveFix(t, results)
}

func TestCheckPassphrase_MissingFile_Warning(t *testing.T) {
	k := baseKey(t)
	k.PrivateKeyPath = "/nonexistent/id_ed25519"

	results := checkPassphrase(k)

	if !hasSeverity(results, Warning) {
		t.Error("missing private key file should produce Warning")
	}
	allHaveFix(t, results)
}

// ── CheckAlgorithm ────────────────────────────────────────────────────────────

func TestCheckAlgorithm_DSA_Critical(t *testing.T) {
	k := baseKey(t)
	k.Algorithm = "ssh-dss"

	results := checkAlgorithm(k)

	if !hasSeverity(results, Critical) {
		t.Error("DSA algorithm should produce Critical finding")
	}
	allHaveFix(t, results)
}

func TestCheckAlgorithm_Ed25519_Clean(t *testing.T) {
	k := baseKey(t)
	k.Algorithm = "ssh-ed25519"

	results := checkAlgorithm(k)

	if len(results) != 0 {
		t.Errorf("Ed25519 should produce no algorithm findings, got: %v", results)
	}
}

func TestCheckAlgorithm_RSA_Clean(t *testing.T) {
	k := baseKey(t)
	k.Algorithm = "ssh-rsa"

	results := checkAlgorithm(k)

	if hasSeverity(results, Critical) {
		t.Error("RSA should not produce Critical from CheckAlgorithm")
	}
}

// ── CheckBitSize ──────────────────────────────────────────────────────────────

func TestCheckBitSize_RSA1024_Critical(t *testing.T) {
	k := baseKey(t)
	k.Algorithm = "ssh-rsa"
	k.BitSize = 1024

	results := checkBitSize(k)

	if !hasSeverity(results, Critical) {
		t.Error("RSA 1024 should produce Critical")
	}
	allHaveFix(t, results)
}

func TestCheckBitSize_RSA2048_Warning(t *testing.T) {
	k := baseKey(t)
	k.Algorithm = "ssh-rsa"
	k.BitSize = 2048

	results := checkBitSize(k)

	if !hasSeverity(results, Warning) {
		t.Error("RSA 2048 should produce Warning (recommend higher)")
	}
	if hasSeverity(results, Critical) {
		t.Error("RSA 2048 should NOT produce Critical")
	}
	allHaveFix(t, results)
}

func TestCheckBitSize_RSA3000_Info(t *testing.T) {
	k := baseKey(t)
	k.Algorithm = "ssh-rsa"
	k.BitSize = 3000

	results := checkBitSize(k)

	if !hasSeverity(results, Info) {
		t.Error("RSA between 2048 and 4096 should produce Info")
	}
	if hasSeverity(results, Critical) || hasSeverity(results, Warning) {
		t.Error("RSA 3000 should not produce Critical or Warning")
	}
}

func TestCheckBitSize_RSA4096_Clean(t *testing.T) {
	k := baseKey(t)
	k.Algorithm = "ssh-rsa"
	k.BitSize = 4096

	results := checkBitSize(k)

	if len(results) != 0 {
		t.Errorf("RSA 4096 should produce no findings, got: %v", results)
	}
}

func TestCheckBitSize_Ed25519_NoCheck(t *testing.T) {
	k := baseKey(t)
	k.Algorithm = "ssh-ed25519"
	k.BitSize = 256

	results := checkBitSize(k)

	if len(results) != 0 {
		t.Errorf("Ed25519 should produce no bit-size findings, got: %v", results)
	}
}

func TestCheckBitSize_ZeroBitSize_Nil(t *testing.T) {
	k := baseKey(t)
	k.Algorithm = "ssh-rsa"
	k.BitSize = 0 // неизвестно — не штрафовать

	results := checkBitSize(k)

	if results != nil {
		t.Errorf("BitSize=0 should return nil, got: %v", results)
	}
}

// ── CheckPermissions ──────────────────────────────────────────────────────────

func TestCheckPermissions_WrongPerms_Critical(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(privPath, []byte("placeholder"), 0644); err != nil { // неверные права
		t.Fatal(err)
	}

	k := baseKey(t)
	k.PrivateKeyPath = privPath
	k.IsPublicOnly = false

	results := checkPermissions(k)

	if runtime.GOOS == "windows" {
		// POSIX bits are synthetic on Windows, so no Critical must be raised.
		if hasSeverity(results, Critical) {
			t.Error("Windows: POSIX-bit perm check must not raise Critical")
		}
		return
	}

	if !hasSeverity(results, Critical) {
		t.Error("private key with 0644 should produce Critical")
	}
	allHaveFix(t, results)
}

func TestCheckPermissions_CorrectPerms_Clean(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("baseKey chmod 0600 has no effect on Windows; covered by WrongPerms")
	}

	k := baseKey(t) // файл уже создан с 0600

	results := checkPermissions(k)

	if hasSeverity(results, Critical) {
		t.Error("private key with correct 0600 should not produce Critical")
	}
}

func TestCheckPermissions_PublicOnly_NoCheck(t *testing.T) {
	k := baseKey(t)
	k.IsPublicOnly = true

	results := checkPermissions(k)

	// public-only ключи не имеют приватного файла — CheckPermissions должен пропустить
	if hasSeverity(results, Critical) {
		t.Error("public-only key should not produce Critical from CheckPermissions")
	}
}

func TestCheckSSHDirPermissions_Platform(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil { // wrong on POSIX (want 0700)
		t.Fatal(err)
	}

	results := newCheckSSHDirPermissions(dir)()

	if runtime.GOOS == "windows" {
		// Must not raise a false Critical; instead an Info that it's skipped.
		if hasSeverity(results, Critical) {
			t.Error("Windows: dir perm check must not raise Critical")
		}
		if !hasSeverity(results, Info) {
			t.Error("Windows: expected an Info noting the check is skipped")
		}
		return
	}

	if !hasSeverity(results, Critical) {
		t.Error("0755 ~/.ssh should produce Critical on POSIX")
	}
	allHaveFix(t, results)
}

// ── CheckAge ──────────────────────────────────────────────────────────────────

// maxKeyAge = 12 * 30 * 24 * time.Hour ≈ 360 дней

func TestCheckAge_OldKey_Warning(t *testing.T) {
	k := baseKey(t)
	k.ModifiedAt = time.Now().AddDate(0, -13, 0) // 13 месяцев назад

	results := checkAge(k)

	if !hasSeverity(results, Warning) {
		t.Error("key older than maxKeyAge should produce Warning")
	}
	allHaveFix(t, results)
}

func TestCheckAge_NewKey_Clean(t *testing.T) {
	k := baseKey(t)
	k.ModifiedAt = time.Now().AddDate(0, -3, 0) // 3 месяца назад

	results := checkAge(k)

	if hasSeverity(results, Warning) {
		t.Error("key within maxKeyAge should not produce Warning")
	}
}

func TestCheckAge_JustOverLimit_Warning(t *testing.T) {
	k := baseKey(t)
	k.ModifiedAt = time.Now().Add(-(maxKeyAge + 24*time.Hour))

	results := checkAge(k)

	if !hasSeverity(results, Warning) {
		t.Error("key just over maxKeyAge should produce Warning")
	}
}

func TestCheckAge_ZeroTime_NoFinding(t *testing.T) {
	k := baseKey(t)
	k.ModifiedAt = time.Time{} // zero value

	results := checkAge(k)

	// нулевое время — дата неизвестна, не штрафовать
	if hasSeverity(results, Warning) {
		t.Error("zero ModifiedAt should not produce Warning")
	}
}

// ── calcReport (scoring) ──────────────────────────────────────────────────────

func TestCalcReport_NoResults_GradeA(t *testing.T) {
	points, grade, critical, warning, info := calcReport(nil)

	if points != 100 {
		t.Errorf("calcReport(nil) points = %d, want 100", points)
	}
	if grade != GradeA {
		t.Errorf("calcReport(nil) grade = %v, want GradeA", grade)
	}
	if critical != 0 || warning != 0 || info != 0 {
		t.Errorf("calcReport(nil) counts = %d/%d/%d, want 0/0/0", critical, warning, info)
	}
}

func TestCalcReport_OneCritical(t *testing.T) {
	results := []AuditResult{
		{Severity: Critical, Message: "no passphrase", Fix: "ssh-keygen -p"},
	}
	points, grade, critical, _, _ := calcReport(results)

	if points != 80 { // 100 - 20
		t.Errorf("points = %d, want 80", points)
	}
	if grade != GradeB {
		t.Errorf("grade = %v, want GradeB", grade)
	}
	if critical != 1 {
		t.Errorf("critical count = %d, want 1", critical)
	}
}

func TestCalcReport_Boundaries(t *testing.T) {
	makeResults := func(criticals, warnings, infos int) []AuditResult {
		var r []AuditResult
		for i := 0; i < criticals; i++ {
			r = append(r, AuditResult{Severity: Critical, Message: "c", Fix: "f"})
		}
		for i := 0; i < warnings; i++ {
			r = append(r, AuditResult{Severity: Warning, Message: "w", Fix: "f"})
		}
		for i := 0; i < infos; i++ {
			r = append(r, AuditResult{Severity: Info, Message: "i", Fix: "f"})
		}
		return r
	}

	cases := []struct {
		name      string
		results   []AuditResult
		wantPts   int
		wantGrade Grade
	}{
		// 100 - 20 - 5 - 5 = 70 → B
		{"70pts_GradeB", makeResults(1, 2, 0), 70, GradeB},
		// 100 - 20 - 20 - 5 - 5 = 50 → C
		{"50pts_GradeC", makeResults(2, 2, 0), 50, GradeC},
		// 100 - 60 - 10 = 30 → D
		{"30pts_GradeD", makeResults(3, 2, 0), 30, GradeD},
		// 100 - 100 = 0 → F
		{"0pts_GradeF", makeResults(5, 0, 0), 0, GradeF},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pts, grade, _, _, _ := calcReport(tc.results)
			if pts != tc.wantPts {
				t.Errorf("points = %d, want %d", pts, tc.wantPts)
			}
			if grade != tc.wantGrade {
				t.Errorf("grade = %v, want %v", grade, tc.wantGrade)
			}
		})
	}
}

func TestCalcReport_ScoreNeverNegative(t *testing.T) {
	results := make([]AuditResult, 20) // 20 * (-20) = -300
	for i := range results {
		results[i] = AuditResult{Severity: Critical, Message: "x", Fix: "f"}
	}
	points, _, _, _, _ := calcReport(results)

	if points < 0 {
		t.Errorf("score should not go below 0, got %d", points)
	}
}

// ── Fix field contract ────────────────────────────────────────────────────────

// TestAllFindings_HaveNonEmptyFix гоняет все key-чеки на заведомо плохом ключе
// и проверяет что Fix непустой у каждого результата.
func TestAllFindings_HaveNonEmptyFix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod semantics differ on Windows")
	}

	dir := t.TempDir()
	privPath := writeUnencryptedKey(t, dir, "id_bad")

	// Выставляем неверные права чтобы CheckPermissions тоже сработал
	if err := os.Chmod(privPath, 0644); err != nil {
		t.Fatal(err)
	}

	bad := keys.Key{
		PrivateKeyPath: privPath,
		PublicKeyPath:  privPath + ".pub",
		HasPassphrase:  false,
		Algorithm:      "ssh-dss",
		BitSize:        1024,
		PrivatePerm:    0644,
		ModifiedAt:     time.Now().AddDate(-2, 0, 0),
	}

	checks := []struct {
		name string
		fn   func(keys.Key) []AuditResult
	}{
		{"CheckPassphrase", checkPassphrase},
		{"CheckAlgorithm", checkAlgorithm},
		{"CheckBitSize", checkBitSize},
		{"CheckPermissions", checkPermissions},
		{"CheckAge", checkAge},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			results := c.fn(bad)
			allHaveFix(t, results)
		})
	}
}
