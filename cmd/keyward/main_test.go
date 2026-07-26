package main

import (
	"runtime/debug"
	"testing"
)

// TestModuleVersionFrom checks which builds are allowed to report a version.
// The distinction matters: current Go synthesizes a git-derived pseudo-version
// for working-tree builds, and reporting that would show a release number that
// does not exist.
func TestModuleVersionFrom(t *testing.T) {
	settings := func(keys ...string) []debug.BuildSetting {
		out := make([]debug.BuildSetting, 0, len(keys))
		for _, k := range keys {
			out = append(out, debug.BuildSetting{Key: k, Value: "x"})
		}
		return out
	}

	tests := []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{
			// go install github.com/...@v1.0.1 — no VCS settings recorded.
			name: "module build reports its version",
			info: &debug.BuildInfo{
				Main:     debug.Module{Version: "v1.0.1"},
				Settings: settings("-buildmode", "-compiler"),
			},
			want: "v1.0.1",
		},
		{
			// Local `go build`: Go fills Main.Version with a pseudo-version.
			name: "working-tree build reports nothing",
			info: &debug.BuildInfo{
				Main:     debug.Module{Version: "v1.0.2-0.20260724195949-058643164e52+dirty"},
				Settings: settings("-buildmode", "vcs", "vcs.revision", "vcs.modified"),
			},
			want: "",
		},
		{
			name: "nil build info reports nothing",
			info: nil,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := moduleVersionFrom(tt.info); got != tt.want {
				t.Errorf("moduleVersionFrom() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestResolveVersion covers the three ways a binary learns its version: the
// linker flag GoReleaser passes, the module version the toolchain embeds for
// `go install module@version`, and neither (a local `go build`).
func TestResolveVersion(t *testing.T) {
	tests := []struct {
		name     string
		injected string
		module   string
		want     string
	}{
		{
			name:     "release build wins over module version",
			injected: "1.0.1",
			module:   "v1.0.1",
			want:     "1.0.1",
		},
		{
			// go install github.com/...@v1.0.1: no linker flags, but the
			// toolchain records the module version. Reported without the v so
			// it matches what a release build prints.
			name:     "go install falls back to module version",
			injected: "dev",
			module:   "v1.0.1",
			want:     "1.0.1",
		},
		{
			name:     "local go build stays dev",
			injected: "dev",
			module:   "(devel)",
			want:     "dev",
		},
		{
			name:     "missing build info stays dev",
			injected: "dev",
			module:   "",
			want:     "dev",
		},
		{
			// A pseudo-version from `go install ...@main` is still better than
			// showing nothing but "dev".
			name:     "pseudo-version is reported as-is",
			injected: "dev",
			module:   "v0.0.0-20260717103413-5ee6c5e1a2b3",
			want:     "0.0.0-20260717103413-5ee6c5e1a2b3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.injected, tt.module); got != tt.want {
				t.Errorf("resolveVersion(%q, %q) = %q, want %q",
					tt.injected, tt.module, got, tt.want)
			}
		})
	}
}
