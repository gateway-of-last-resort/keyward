package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func serialize(c *Config) []byte {
	var sb = strings.Builder{}

	newline := "\n"
	if bytes.Contains(c.Original, []byte("\r\n")) {
		newline = "\r\n"
	}

	for _, token := range c.Global.Tokens {
		if token.Raw != "" {
			sb.WriteString(token.Raw)
		} else {
			sb.WriteString(token.Key + token.Sep + token.Value)
		}
		sb.WriteString(newline)
	}

	for _, block := range c.Blocks {
		for _, token := range block.Tokens {
			if token.Raw != "" {
				sb.WriteString(token.Raw)
			} else {
				if token.Type == PARAM {
					sb.WriteString("    " + token.Key + token.Sep + token.Value)
				} else {
					sb.WriteString(token.Key + token.Sep + token.Value)
				}
			}
			sb.WriteString(newline)
		}
	}
	return []byte(sb.String())
}

func WriteAtomic(path string, data []byte) error {

	dir := filepath.Dir(path)

	tempFile, err := os.CreateTemp(dir, "temp.*.atom")
	if err != nil {
		return err
	}
	_, err = tempFile.Write(data)
	if err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		return err
	}

	if err := tempFile.Close(); err != nil {
		os.Remove(tempFile.Name())
		return err
	}
	if err := os.Rename(tempFile.Name(), path); err != nil {
		os.Remove(tempFile.Name())
		return err
	}

	return os.Chmod(path, 0600)
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
	backupDir := filepath.Join(home, ".ssh-vault", "backups", "config")

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

func Save(c *Config) error {

	if err := backup(c.Path); err != nil {
		return err
	}
	data := serialize(c)
	if err := WriteAtomic(c.Path, data); err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	backupDir := filepath.Join(home, ".ssh-vault", "backups", "config")
	if err := rotateBackup(backupDir); err != nil {
		return err
	}

	c.Modified = false
	return nil
}
