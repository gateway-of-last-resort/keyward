// Package cli implements keyward's non-interactive command-line interface.
// It is a thin hand-rolled router (no external dependency) that dispatches
// subcommands like `audit` and `list`, each reusing the same internal packages
// as the TUI. Running keyward with no arguments launches the TUI instead.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gateway-of-last-resort/keyward/internal/config"
	"github.com/gateway-of-last-resort/keyward/internal/keys"
	"github.com/gateway-of-last-resort/keyward/internal/storage"
)

// osUserHomeDir is a seam so tests can point HOME-derived paths at a temp dir.
var osUserHomeDir = os.UserHomeDir

// Env holds the resolved directories and parsed SSH state shared by every
// subcommand (and by the TUI entrypoint).
type Env struct {
	Keys     []keys.Key
	Cfg      *config.Config
	SSHDir   string
	VaultDir string
}

// LoadEnv resolves ~/.keyward and ~/.ssh (honoring a stored SSHDir preference),
// then parses the keys and config. A missing ~/.ssh or config file is tolerated,
// mirroring the TUI entrypoint.
func LoadEnv() (Env, error) {
	home, err := osUserHomeDir()
	if err != nil {
		return Env{}, err
	}

	vaultDir := filepath.Join(home, ".keyward")
	sshDir := filepath.Join(home, ".ssh")
	if prefs := storage.LoadPrefs(vaultDir); prefs.SSHDir != "" {
		sshDir = prefs.SSHDir
	}

	allKeys, err := keys.Parse(sshDir)
	if err != nil && !errors.Is(err, keys.ErrDirNotFound) {
		return Env{}, err
	}

	var cfg *config.Config
	if c, err := config.ParseFile(filepath.Join(sshDir, "config")); err == nil {
		cfg = &c
	}

	return Env{Keys: allKeys, Cfg: cfg, SSHDir: sshDir, VaultDir: vaultDir}, nil
}

// Run dispatches a subcommand. args is os.Args[1:]; version is the build version
// for the `version` command. It returns the process exit code: 0 on success,
// 1 on a runtime error or a tripped --fail-on threshold, 2 on a usage error.
func Run(version string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}

	switch args[0] {
	case "audit":
		return cmdAudit(args[1:], stdout, stderr)
	case "list", "keys":
		return cmdList(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "keyward %s\n", version)
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "keyward: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `keyward — TUI manager for SSH keys, config, and security audit

Usage:
  keyward                 launch the interactive TUI
  keyward <command> ...   run a non-interactive command

Commands:
  audit [--json] [--fail-on=critical|warning|info]
                          run the security audit; exit 1 if a finding meets
                          the --fail-on threshold
  list [--json]           list discovered SSH keys (alias: keys)
  version                 print the version
  help                    show this help
`)
}
