package main

import (
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
	"github.com/gateway-of-last-resort/keyward/internal/config"
	"github.com/gateway-of-last-resort/keyward/internal/keys"
	"github.com/gateway-of-last-resort/keyward/internal/storage"
	"github.com/gateway-of-last-resort/keyward/internal/ui"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fatal(err)
	}

	vaultDir := filepath.Join(home, ".keyward")

	sshDir := filepath.Join(home, ".ssh")
	if prefs := storage.LoadPrefs(vaultDir); prefs.SSHDir != "" {
		sshDir = prefs.SSHDir
	}

	cfgPath := filepath.Join(sshDir, "config")

	allKeys, err := keys.Parse(sshDir)
	if err != nil && !os.IsNotExist(err) {
		fatal(err)
	}

	var cfg *config.Config
	if c, err := config.ParseFile(cfgPath); err == nil {
		cfg = &c
	}

	report := audit.Run(allKeys, cfg, sshDir)

	m := ui.New(allKeys, cfg, report, sshDir, vaultDir)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "keyward: %v\n", err)
	os.Exit(1)
}
