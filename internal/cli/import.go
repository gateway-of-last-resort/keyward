package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/gateway-of-last-resort/keyward/internal/keys"
)

// cmdImport copies an external key into the managed SSH directory with secure
// permissions. Tags/notes are set from the TUI (where the vault is unlocked);
// the CLI import is a pure file operation and needs no master password.
func cmdImport(args []string, stdout, stderr io.Writer) int {
	var overwrite bool
	var srcPath string

	for _, arg := range args {
		switch {
		case arg == "--force" || arg == "-f":
			overwrite = true
		case strings.HasPrefix(arg, "-"):
			fmt.Fprintf(stderr, "import: unknown flag %q\n", arg)
			return 2
		default:
			if srcPath != "" {
				fmt.Fprintln(stderr, "import: expected a single <path>")
				return 2
			}
			srcPath = arg
		}
	}

	if srcPath == "" {
		fmt.Fprintln(stderr, "import: usage: keyward import <path> [--force]")
		return 2
	}

	env, err := LoadEnv()
	if err != nil {
		fmt.Fprintf(stderr, "keyward: %v\n", err)
		return 1
	}

	key, err := keys.ImportKey(env.SSHDir, srcPath, keys.ImportOptions{Overwrite: overwrite})
	if err != nil {
		fmt.Fprintf(stderr, "keyward: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "imported %s\n  %s\n", key.PrivateKeyPath, key.Fingerprint)
	return 0
}
