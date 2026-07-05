package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
	"github.com/gateway-of-last-resort/keyward/internal/cli"
	"github.com/gateway-of-last-resort/keyward/internal/ui"
)

// version is the build version, overridden at release time via
// -ldflags "-X main.version=...". Defaults to "dev" for local builds.
var version = "dev"

func main() {
	// Any argument routes to the non-interactive CLI (audit, list, version,
	// help, …). With no arguments, launch the TUI.
	if args := os.Args[1:]; len(args) > 0 {
		os.Exit(cli.Run(version, args, os.Stdout, os.Stderr))
	}

	env, err := cli.LoadEnv()
	if err != nil {
		fatal(err)
	}

	report := audit.Run(env.Keys, env.Cfg, env.SSHDir)

	m := ui.New(env.Keys, env.Cfg, report, env.SSHDir, env.VaultDir)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "keyward: %v\n", err)
	os.Exit(1)
}
