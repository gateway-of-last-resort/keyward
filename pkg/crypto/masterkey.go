package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"filippo.io/age"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrMasterKeyExists    = errors.New("master key already exists")
	ErrMasterKeyNotFound  = errors.New("master key not found")
	ErrWrongPassword      = errors.New("wrong password")
	ErrCorruptedMasterKey = errors.New("master key file is corrupted")
	ErrUnsupportedVersion = errors.New("unsupported master key version")
	ErrWriteFailed        = errors.New("failed to write master key file")
	ErrEmptyPassword      = errors.New("master key password must not be empty")
)

const (
	magic          = "SSHV"
	versionV1 byte = 0x01
	// versionV2 authenticates the file header (magic, version, argon2 params,
	// salt, nonce) as AEAD associated data, so tampering with the KDF parameters
	// is detected on decrypt instead of silently changing the derived key.
	versionV2 byte = 0x02

	argon2idTime    uint32 = 3
	argon2idMemory  uint32 = 64 * 1024 // в KiB
	argon2idThreads byte   = 4
	argon2idKeyLen  uint32 = 32

	// Upper bounds on the argon2 parameters read from an untrusted file header.
	// Keyward always writes the fixed values above; a file requesting far more is
	// corrupt or hostile. Passing an unbounded memory value straight to argon2
	// would let a crafted or bit-flipped master.key allocate gigabytes and hang
	// or OOM the process on unlock. Generous headroom is left for a future bump.
	maxArgon2Time    uint32 = 64
	maxArgon2Memory  uint32 = 1 << 20 // KiB (1 GiB)
	maxArgon2Threads byte   = 64

	saltSize  = 32
	nonceSize = 12

	minFileSize = 74
)

func writeMasterKey(path string, identity *age.X25519Identity, password string) error {

	salt := make([]byte, saltSize)
	nonce := make([]byte, nonceSize)

	_, err := rand.Read(salt)
	if err != nil {
		return err
	}
	_, err = rand.Read(nonce)
	if err != nil {
		return err
	}

	kek := argon2.IDKey([]byte(password), salt, argon2idTime, argon2idMemory, argon2idThreads, argon2idKeyLen)
	defer ZeroBytes(kek)

	cipher, err := chacha20poly1305.New(kek)
	if err != nil {
		return ErrEncryptFailed
	}

	// The header (magic, version, argon2 params, salt, nonce) is authenticated as
	// AEAD associated data, so it can't be altered independently of the ciphertext.
	header := buildHeader(versionV2, argon2idTime, argon2idMemory, argon2idThreads, salt, nonce)
	// identity.String() returns the secret age key as a Go string, whose backing
	// array cannot be zeroed and lingers on the heap until GC. This residual
	// window is imposed by age's string-only API; we minimize it by using the
	// value inline rather than binding it to a variable. See SECURITY.md.
	encrypted := cipher.Seal(nil, nonce, []byte(identity.String()), header)

	tmp, err := os.CreateTemp(filepath.Dir(path), "master.key.tmp*")
	if err != nil {
		return err
	}
	writes := []func() error{
		func() error { return binary.Write(tmp, binary.BigEndian, header) },
		func() error { return binary.Write(tmp, binary.BigEndian, encrypted) },
	}

	for _, w := range writes {
		if err := w(); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			return fmt.Errorf("%w: %w", ErrEncryptFailed, err)
		}
	}

	// fsync the data before the rename so a crash can't leave master.key
	// renamed into place but zero-length or truncated.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}

	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}

	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}

	// fsync the directory so the rename itself is durable.
	return syncDir(filepath.Dir(path))
}

// buildHeader serialises the fixed-size master-key header exactly as it is laid
// out on disk: magic, version, argon2 time/memory/threads, salt, nonce. For v2
// files this same byte slice is passed as the AEAD associated data. Writes to a
// bytes.Buffer never fail, so their errors are intentionally ignored.
func buildHeader(version byte, time, memory uint32, threads byte, salt, nonce []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString(magic)
	buf.WriteByte(version)
	_ = binary.Write(buf, binary.BigEndian, time)
	_ = binary.Write(buf, binary.BigEndian, memory)
	buf.WriteByte(threads)
	buf.Write(salt)
	buf.Write(nonce)
	return buf.Bytes()
}

// syncDir fsyncs a directory so an entry rename/create within it survives a crash.
// Windows has no directory fsync (Open+Sync returns "Access is denied"), so it's
// skipped there; the rename is still atomic.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}
	return nil
}

// InitMasterKey generates a new age X25519 identity, encrypts it with password, and writes it to path.
func InitMasterKey(path, password string) (age.Identity, error) {

	if password == "" {
		return nil, ErrEmptyPassword
	}

	_, err := os.Stat(path)
	if err == nil {
		return nil, ErrMasterKeyExists
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}

	err = writeMasterKey(path, identity, password)
	if err != nil {
		return nil, err
	}

	return identity, nil
}

// MasterKeyExists reports whether a master key is present at path, counting a
// leftover path+".bak" (from a crash during a write or password change) as
// present. Callers use this to decide "unlock" vs "create a new vault"; treating
// a recoverable .bak as absent would create a fresh identity and orphan all
// existing metadata and backups.
func MasterKeyExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	if _, err := os.Stat(path + ".bak"); err == nil {
		return true
	}
	return false
}

// LoadMasterKey reads path, derives the KEK from password via Argon2id, and returns the decrypted identity.
func LoadMasterKey(path, password string) (age.Identity, error) {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		// A crash during a password change or write can leave only the .bak
		// (ChangeMasterKeyPassword renames the current key aside before writing
		// the replacement). Promote it to the primary path and continue, mirroring
		// the metadata store's .bak recovery, so the vault is never lost to an
		// interrupted rewrite.
		bak := path + ".bak"
		if _, bakErr := os.Stat(bak); bakErr != nil {
			return nil, ErrMasterKeyNotFound
		}
		if rnErr := os.Rename(bak, path); rnErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrCorruptedMasterKey, rnErr)
		}
	} else if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	if len(data) < minFileSize {
		return nil, ErrCorruptedMasterKey
	}

	pos := 0

	if string(data[pos:pos+4]) != magic {
		return nil, ErrCorruptedMasterKey
	}
	pos += 4

	version := data[pos]
	if version != versionV1 && version != versionV2 {
		return nil, ErrUnsupportedVersion
	}
	pos++

	time := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4

	memory := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4

	threads := data[pos]
	pos++

	salt := data[pos : pos+saltSize]
	pos += saltSize

	nonce := data[pos : pos+nonceSize]
	pos += nonceSize

	encrypted := data[pos:]

	if time == 0 || memory == 0 || threads == 0 {
		return nil, ErrCorruptedMasterKey
	}
	// Reject implausible KDF parameters before argon2 tries to honour them: an
	// unbounded memory value from a crafted or corrupt file would otherwise hang
	// or exhaust memory on unlock (found by FuzzLoadMasterKey).
	if time > maxArgon2Time || memory > maxArgon2Memory || threads > maxArgon2Threads {
		return nil, ErrCorruptedMasterKey
	}

	kek := argon2.IDKey([]byte(password), salt, time, memory, threads, argon2idKeyLen)
	defer ZeroBytes(kek)

	cipher, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, ErrCorruptedMasterKey
	}

	// v2 authenticates the header (data[:pos]) as associated data; v1 predates
	// that and passes nil, matching how it was written.
	var aad []byte
	if version == versionV2 {
		aad = data[:pos]
	}

	decrypted, err := cipher.Open(nil, nonce, encrypted, aad)
	if err != nil {
		return nil, ErrWrongPassword
	}
	defer ZeroBytes(decrypted)

	// string(decrypted) copies the secret into a Go string that ParseX25519Identity
	// requires; like the write path, that string's backing array can't be zeroed
	// and survives until GC. Same age-API limitation, same residual window — the
	// decrypted []byte itself is still zeroed above. See SECURITY.md.
	identity, err := age.ParseX25519Identity(string(decrypted))
	if err != nil {
		return nil, ErrCorruptedMasterKey
	}

	// Transparently upgrade a legacy v1 file to the authenticated v2 format on
	// first successful unlock. Best-effort: a migration failure must not fail the
	// unlock, so the error is ignored and the still-valid v1 file keeps working.
	if version == versionV1 {
		_ = writeMasterKey(path, identity, password)
	}

	return identity, nil
}

// ChangeMasterKeyPassword re-encrypts the master key at path with newPassword.
// The old file is backed up to path+".bak" and removed on success.
func ChangeMasterKeyPassword(path, oldPassword, newPassword string) error {

	if newPassword == "" {
		return ErrEmptyPassword
	}

	identity, err := LoadMasterKey(path, oldPassword)
	if err != nil {
		return err
	}

	x25519Identity, ok := identity.(*age.X25519Identity)
	if !ok {
		return ErrCorruptedMasterKey
	}

	err = os.Rename(path, path+".bak")
	if err != nil {
		return err
	}

	err = writeMasterKey(path, x25519Identity, newPassword)
	if err != nil {
		rollbackErr := os.Rename(path+".bak", path)
		return errors.Join(err, rollbackErr)
	}

	// The new key is already written; removing the backup is best-effort.
	// A failure here must not be reported as a password-change failure.
	_ = os.Remove(path + ".bak")
	return nil
}
