package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

var (
	ErrNilRecipient  = errors.New("recipient must not be nil")
	ErrNilIdentity   = errors.New("identity must not be nil")
	ErrEncryptFailed = errors.New("encryption failed")
	ErrDecryptFailed = errors.New("decryption failed")
)

func ZeroBytes(b []byte) {
	clear(b)
}

func Encrypt(data []byte, recipient age.Recipient) ([]byte, error) {

	if recipient == nil {
		return nil, ErrNilRecipient
	}
	if data == nil {
		data = []byte{}
	}

	buffer := new(bytes.Buffer)

	writer, err := age.Encrypt(buffer, recipient)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncryptFailed, err)
	}

	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return nil, fmt.Errorf("%w: %w", ErrEncryptFailed, err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncryptFailed, err)
	}

	return buffer.Bytes(), nil

}

func Decrypt(ciphertext []byte, identity age.Identity) ([]byte, error) {
	if identity == nil {
		return nil, ErrNilIdentity
	}

	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptFailed, err)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptFailed, err)
	}

	return data, nil
}
