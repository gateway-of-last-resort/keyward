package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

// dominantEOL reports which line ending the file uses, for lines that have to be
// re-rendered because they were edited or newly added.
//
// Unchanged lines keep their own bytes (their '\r' lives inside Raw), so this
// only decides what a rewritten line looks like. Without it, editing a single
// parameter in a CRLF file wrote that one line with a bare '\n' and left the
// file mixed, which was reported on Windows 26.07.
func dominantEOL(original []byte) string {
	crlf := bytes.Count(original, []byte("\r\n"))
	lf := bytes.Count(original, []byte("\n")) - crlf
	if crlf > lf {
		return "\r\n"
	}
	return "\n"
}

// renderToken returns the text of one line, without its ending, plus the ending
// that must follow it. An unchanged token reproduces its original bytes exactly
// (Raw already holds any '\r'), so it is only ever separated by '\n'.
func renderToken(t Token, inBlock bool, eol string) (text, ending string) {
	if t.Raw != "" {
		return t.Raw, "\n"
	}
	if inBlock && t.Type == PARAM {
		return "    " + t.Key + t.Sep + t.Value, eol
	}
	return t.Key + t.Sep + t.Value, eol
}

// Serialize renders the config back to bytes, preserving original raw lines where unchanged.
func Serialize(c *Config) []byte {
	eol := dominantEOL(c.Original)

	type line struct{ text, ending string }
	lines := make([]line, 0, len(c.Global.Tokens))

	for _, token := range c.Global.Tokens {
		text, ending := renderToken(token, false, eol)
		lines = append(lines, line{text, ending})
	}
	for _, block := range c.Blocks {
		for _, token := range block.Tokens {
			text, ending := renderToken(token, true, eol)
			lines = append(lines, line{text, ending})
		}
	}

	// The token list already carries the file's trailing newline as a final empty
	// token, so the last line's ending is dropped rather than trimmed off the
	// finished string: trimming cannot tell a content '\r' from a CRLF ending.
	var sb strings.Builder
	for i, l := range lines {
		sb.WriteString(l.text)
		if i < len(lines)-1 {
			sb.WriteString(l.ending)
		}
	}
	return []byte(sb.String())
}

// WriteAtomic writes data to path via a temp file + rename, then sets permissions to 0600.
// A symlinked path is written through to its target, so the link survives.
func WriteAtomic(path string, data []byte) error {

	path, err := resolveSymlink(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)

	tempFile, err := os.CreateTemp(dir, "temp.*.atom")
	if err != nil {
		return err
	}
	_, err = tempFile.Write(data)
	if err != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempFile.Name())
		return err
	}

	// fsync the data before the rename so a crash can't leave the config
	// renamed into place but truncated.
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempFile.Name())
		return err
	}
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempFile.Name())
		return err
	}
	if err := os.Rename(tempFile.Name(), path); err != nil {
		_ = os.Remove(tempFile.Name())
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}

	// fsync the directory so the rename itself is durable. Windows has no
	// directory fsync (Open+Sync returns "Access is denied"), so skip it there.
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

// resolveSymlink returns the file a symlinked path points to, or path itself.
// The rename in an atomic write replaces whatever sits at its destination, so
// writing to the link's own path would swap a dotfiles-managed symlink (stow,
// chezmoi, home-manager) for a regular file and leave its source untouched.
func resolveSymlink(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}
	return filepath.EvalSymlinks(path)
}

func backup(path string) error {

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	backupPath := filepath.Join(filepath.Dir(path), "config.bak")
	err = WriteAtomic(backupPath, data)
	if err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	backupDir := filepath.Join(home, ".keyward", "backups", "config")

	err = os.MkdirAll(backupDir, 0700)
	if err != nil {
		return err
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	historyPath := filepath.Join(backupDir, "config_"+timestamp+".bak")

	return WriteAtomic(historyPath, data)
}

func rotateBackup(dir string) error {

	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	backups := []string{}

	for _, file := range files {
		if !file.IsDir() {
			if strings.HasPrefix(file.Name(), "config_") {
				backups = append(backups, file.Name())
			}
		}
	}

	var errs []error
	if len(backups) > 5 {
		slices.Sort(backups)
		slices.Reverse(backups)
		toDelete := backups[5:]

		for _, name := range toDelete {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// ErrPruneFailed means the config was saved but old history copies could not be
// removed. Callers should report it as a warning, not as a failed save.
var ErrPruneFailed = errors.New("config saved, but old backups could not be removed")

// Save serialises c to disk, creates backups, rotates old backup copies, and clears Modified.
// Once the file is written the save has happened: a pruning failure after that
// comes back wrapped in ErrPruneFailed with Modified and Original already updated.
func Save(c *Config) error {
	data := Serialize(c)
	if err := saveFile(c.Path, data); err != nil {
		return err
	}
	c.Modified = false
	c.Original = data

	if err := pruneHistory(); err != nil {
		return fmt.Errorf("%w: %w", ErrPruneFailed, err)
	}
	return nil
}

// saveFile backs up the current contents of path and atomically replaces them
// with data.
func saveFile(path string, data []byte) error {
	if err := backup(path); err != nil {
		return err
	}
	return WriteAtomic(path, data)
}

// pruneHistory keeps only the newest config history copies.
func pruneHistory() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return rotateBackup(filepath.Join(home, ".keyward", "backups", "config"))
}
