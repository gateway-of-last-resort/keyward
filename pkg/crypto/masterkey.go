package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

	argon2idTime    uint32 = 3
	argon2idMemory  uint32 = 64 * 1024 // в KiB
	argon2idThreads byte   = 4
	argon2idKeyLen  uint32 = 32

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

	encrypted := cipher.Seal(nil, nonce, []byte(identity.String()), nil)

	tmp, err := os.CreateTemp(filepath.Dir(path), "master.key.tmp*")
	if err != nil {
		return err
	}
	writes := []func() error{
		func() error { return binary.Write(tmp, binary.BigEndian, []byte(magic)) },
		func() error { return binary.Write(tmp, binary.BigEndian, versionV1) },
		func() error { return binary.Write(tmp, binary.BigEndian, argon2idTime) },
		func() error { return binary.Write(tmp, binary.BigEndian, argon2idMemory) },
		func() error { return binary.Write(tmp, binary.BigEndian, argon2idThreads) },
		func() error { return binary.Write(tmp, binary.BigEndian, salt) },
		func() error { return binary.Write(tmp, binary.BigEndian, nonce) },
		func() error { return binary.Write(tmp, binary.BigEndian, encrypted) },
	}

	for _, w := range writes {
		if err := w(); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return fmt.Errorf("%w: %w", ErrEncryptFailed, err)
		}
	}

	// fsync the data before the rename so a crash can't leave master.key
	// renamed into place but zero-length or truncated.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}

	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}

	// fsync the directory so the rename itself is durable.
	return syncDir(filepath.Dir(path))
}

// syncDir fsyncs a directory so an entry rename/create within it survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
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

// LoadMasterKey reads path, derives the KEK from password via Argon2id, and returns the decrypted identity.
func LoadMasterKey(path, password string) (age.Identity, error) {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrMasterKeyNotFound
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

	if data[pos] != versionV1 {
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

	kek := argon2.IDKey([]byte(password), salt, time, memory, threads, argon2idKeyLen)
	defer ZeroBytes(kek)

	cipher, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, ErrCorruptedMasterKey
	}

	decrypted, err := cipher.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, ErrWrongPassword
	}
	defer ZeroBytes(decrypted)

	identity, err := age.ParseX25519Identity(string(decrypted))
	if err != nil {
		return nil, ErrCorruptedMasterKey
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
