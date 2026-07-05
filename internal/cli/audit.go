package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
)

// cmdAudit runs the security audit and prints it as text or JSON. With
// --fail-on=<severity> it returns exit code 1 when any finding meets or exceeds
// that severity, so CI and pre-commit hooks can gate on it.
func cmdAudit(args []string, stdout, stderr io.Writer) int {
	var jsonOut bool
	var failOn string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--json":
			jsonOut = true
		case arg == "--fail-on":
			i++
			if i >= len(args) {
				fmt.Fprintln(stderr, "audit: --fail-on needs a value (critical|warning|info)")
				return 2
			}
			failOn = args[i]
		case strings.HasPrefix(arg, "--fail-on="):
			failOn = strings.TrimPrefix(arg, "--fail-on=")
		default:
			fmt.Fprintf(stderr, "audit: unknown argument %q\n", arg)
			return 2
		}
	}

	var failSev audit.Severity
	if failOn != "" {
		sev, ok := parseSeverity(failOn)
		if !ok {
			fmt.Fprintf(stderr, "audit: invalid --fail-on %q (want critical|warning|info)\n", failOn)
			return 2
		}
		failSev = sev
	}

	env, err := LoadEnv()
	if err != nil {
		fmt.Fprintf(stderr, "keyward: %v\n", err)
		return 1
	}

	report := audit.Run(env.Keys, env.Cfg, env.SSHDir)

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "keyward: %v\n", err)
			return 1
		}
	} else {
		writeAuditText(stdout, report)
	}

	if failOn != "" && report.HasSeverity(failSev) {
		return 1
	}
	return 0
}

// parseSeverity maps a --fail-on value to a Severity.
func parseSeverity(s string) (audit.Severity, bool) {
	switch strings.ToLower(s) {
	case "critical":
		return audit.Critical, true
	case "warning":
		return audit.Warning, true
	case "info":
		return audit.Info, true
	default:
		return "", false
	}
}

// writeAuditText renders a human-readable audit report.
func writeAuditText(w io.Writer, r audit.AuditReport) {
	fmt.Fprintf(w, "SSH security audit — grade %s (%d/100)\n", r.Grade, r.Points)
	fmt.Fprintf(w, "%d critical, %d warning, %d info\n", r.CriticalCount, r.WarningCount, r.InfoCount)

	if len(r.Results) == 0 {
		fmt.Fprintln(w, "\nNo findings. 🎉")
		return
	}

	fmt.Fprintln(w)
	for _, res := range r.Results {
		target := res.KeyPath
		if target == "" {
			target = string(res.Category)
		}
		fmt.Fprintf(w, "%-9s %s: %s\n", res.Severity, target, res.Message)
		if res.Fix != "" {
			fmt.Fprintf(w, "          fix: %s\n", res.Fix)
		}
	}
}
