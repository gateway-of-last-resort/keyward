// Package knownhosts parses and edits an OpenSSH known_hosts file.
//
// It is deliberately read-mostly: Parse turns the file into a list of Entry
// values for display, and Forget removes a single entry by its 1-based line
// number, rewriting the file atomically while preserving the original mode and
// leaving every other line byte-for-byte unchanged.
package knownhosts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"
)

var (
	// ErrFileNotFound is returned by Forget when path does not exist. Parse
	// treats a missing file as an empty list instead (like keys.Parse).
	ErrFileNotFound = errors.New("known_hosts file not found")
	// ErrLineOutOfRange is returned by Forget when lineNum does not name a line.
	ErrLineOutOfRange = errors.New("line number out of range")
	// ErrReadFailed wraps an underlying read error.
	ErrReadFailed = errors.New("failed to read known_hosts file")
	// ErrWriteFailed wraps an underlying write error.
	ErrWriteFailed = errors.New("failed to write known_hosts file")
)

// Entry is one parsed known_hosts line.
type Entry struct {
	Hosts       []string // host patterns this entry matches (raw; hashed hosts stay as |1|salt|hash)
	Hashed      bool     // true when the host field is a hashed |1|… token
	Marker      string   // "", "cert-authority", or "revoked"
	KeyType     string   // e.g. "ssh-ed25519", "ecdsa-sha2-nistp256"
	Fingerprint string   // SHA256 fingerprint of the public key
	Comment     string   // trailing comment, if any
	LineNum     int      // 1-based line number in the file (for Forget)
	Raw         string   // the original line, verbatim
}

// Parse reads path and returns one Entry per recognised known_hosts line.
//
// Blank lines, comment lines, and lines that fail to parse are skipped. A
// missing file yields an empty slice and a nil error.
func Parse(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}

	var entries []Entry
	for i, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		marker, hosts, pubKey, comment, _, perr := ssh.ParseKnownHosts([]byte(line))
		if perr != nil {
			// Malformed or unsupported line — leave it in the file but don't list it.
			continue
		}

		hashed := len(hosts) > 0 && strings.HasPrefix(hosts[0], "|1|")
		entries = append(entries, Entry{
			Hosts:       hosts,
			Hashed:      hashed,
			Marker:      marker,
			KeyType:     pubKey.Type(),
			Fingerprint: ssh.FingerprintSHA256(pubKey),
			Comment:     comment,
			LineNum:     i + 1,
			Raw:         line,
		})
	}
	return entries, nil
}

// Forget removes the line numbered lineNum (1-based) from path and rewrites the
// file atomically, preserving its mode. Every other line is kept byte-for-byte,
// including the file's trailing-newline shape.
func Forget(path string, lineNum int) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrFileNotFound, path)
		}
		return fmt.Errorf("%w: %w", ErrReadFailed, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrReadFailed, err)
	}

	lines := strings.Split(string(data), "\n")
	if lineNum < 1 || lineNum > len(lines) {
		return fmt.Errorf("%w: %d", ErrLineOutOfRange, lineNum)
	}

	kept := make([]string, 0, len(lines)-1)
	kept = append(kept, lines[:lineNum-1]...)
	kept = append(kept, lines[lineNum:]...)

	if err := atomicWrite(path, []byte(strings.Join(kept, "\n")), info.Mode().Perm()); err != nil {
		return fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}
	return nil
}

// atomicWrite durably writes data to path via temp→fsync→chmod→rename→dir fsync,
// mirroring internal/storage.atomicWriteFile but honouring the caller's perm so
// an existing known_hosts keeps its original mode.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return syncDir(dir)
}

// syncDir fsyncs a directory so a rename within it is durable. Windows has no
// directory fsync, so it's skipped there; the rename is still atomic.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
