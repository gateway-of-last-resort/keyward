package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
	"github.com/gateway-of-last-resort/keyward/internal/cli"
	"github.com/gateway-of-last-resort/keyward/internal/ui"
)

// version is the build version, overridden at release time via
// -ldflags "-X main.version=...". Defaults to "dev" for local builds.
var version = "dev"

// devVersion is the placeholder a build without the linker flag carries.
const devVersion = "dev"

// resolveVersion decides what version to report. Release builds carry the
// linker-injected tag and win outright. `go install module@version` gets no
// linker flags, but the toolchain embeds the module version in the binary, so
// use that rather than showing "dev" to everyone who installs that way.
//
// The v-prefix is trimmed because GoReleaser injects the tag without one, and
// both install paths should print the same string for the same release.
func resolveVersion(injected, module string) string {
	if injected != devVersion {
		return injected
	}
	if module == "" || module == "(devel)" {
		return injected
	}
	return strings.TrimPrefix(module, "v")
}

// moduleVersionFrom extracts a release version from embedded build info, or ""
// when the binary has none worth showing.
//
// Builds from a working tree are excluded on purpose: current Go synthesizes a
// pseudo-version for them from the git state ("v1.0.2-0.20260724195949-<sha>",
// plus "+dirty" for uncommitted changes), which reads like a release that does
// not exist. Those builds record VCS settings; module builds fetched by
// `go install` do not, so vcs.revision separates the two.
func moduleVersionFrom(info *debug.BuildInfo) string {
	if info == nil {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return ""
		}
	}
	return info.Main.Version
}

// buildModuleVersion reads this binary's own build info.
func buildModuleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	return moduleVersionFrom(info)
}

func main() {
	version = resolveVersion(version, buildModuleVersion())

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

	ui.Version = version // show the build version in the Settings footer
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
