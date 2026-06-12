package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const prefsFile = "prefs.json"

// Prefs holds user preferences persisted across sessions.
type Prefs struct {
	SSHDir string `json:"ssh_dir,omitempty"`
}

// LoadPrefs reads preferences from vaultDir. Returns zero Prefs if the file
// doesn't exist or cannot be parsed.
func LoadPrefs(vaultDir string) Prefs {
	data, err := os.ReadFile(filepath.Join(vaultDir, prefsFile))
	if err != nil {
		return Prefs{}
	}
	var p Prefs
	if err := json.Unmarshal(data, &p); err != nil {
		return Prefs{}
	}
	return p
}

// SavePrefs writes preferences to vaultDir atomically.
func SavePrefs(vaultDir string, p Prefs) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	path := filepath.Join(vaultDir, prefsFile)
	tmp, err := os.CreateTemp(vaultDir, "prefs-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Chmod(path, 0600)
}
