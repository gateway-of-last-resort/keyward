package main

import (
	"errors"
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

// version is the build version, overridden at release time via
// -ldflags "-X main.version=...". Defaults to "dev" for local builds.
var version = "dev"

func main() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--version", "-v", "version":
			fmt.Printf("keyward %s\n", version)
			return
		case "--help", "-h", "help":
			fmt.Println("keyward — TUI manager for SSH keys, config, and security audit")
			fmt.Println("\nUsage: keyward [--version] [--help]")
			fmt.Println("\nRunning with no arguments launches the interactive TUI.")
			return
		}
	}

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
	if err != nil && !errors.Is(err, keys.ErrDirNotFound) {
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
