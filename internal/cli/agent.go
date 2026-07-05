package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	kagent "github.com/gateway-of-last-resort/keyward/internal/agent"
	"github.com/gateway-of-last-resort/keyward/internal/keys"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

// cmdAgent dispatches `keyward agent add|list`.
func cmdAgent(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "agent: usage: keyward agent add <key> | keyward agent list")
		return 2
	}
	switch args[0] {
	case "add":
		return cmdAgentAdd(args[1:], stdout, stderr)
	case "list", "ls":
		return cmdAgentList(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "agent: unknown subcommand %q\n", args[0])
		return 2
	}
}

// resolveKeyArg turns a key argument into a path: an existing file is used as
// given (after ~ expansion), otherwise it's looked up by name in sshDir.
func resolveKeyArg(sshDir, arg string) string {
	p := keys.ExpandTilde(arg)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if !filepath.IsAbs(p) {
		return filepath.Join(sshDir, arg)
	}
	return p
}

func cmdAgentAdd(args []string, stdout, stderr io.Writer) int {
	var passEnv, keyArg string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--passphrase-env":
			i++
			if i >= len(args) {
				fmt.Fprintln(stderr, "agent add: --passphrase-env needs a variable name")
				return 2
			}
			passEnv = args[i]
		case strings.HasPrefix(arg, "--passphrase-env="):
			passEnv = strings.TrimPrefix(arg, "--passphrase-env=")
		case strings.HasPrefix(arg, "-"):
			fmt.Fprintf(stderr, "agent add: unknown flag %q\n", arg)
			return 2
		default:
			if keyArg != "" {
				fmt.Fprintln(stderr, "agent add: expected a single <key>")
				return 2
			}
			keyArg = arg
		}
	}
	if keyArg == "" {
		fmt.Fprintln(stderr, "agent add: usage: keyward agent add <key> [--passphrase-env VAR]")
		return 2
	}

	env, err := LoadEnv()
	if err != nil {
		fmt.Fprintf(stderr, "keyward: %v\n", err)
		return 1
	}

	path := resolveKeyArg(env.SSHDir, keyArg)
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "keyward: cannot read key: %v\n", err)
		return 1
	}
	defer crypto.ZeroBytes(pemBytes)

	comment := filepath.Base(path)

	var passphrase []byte
	if passEnv != "" {
		val := os.Getenv(passEnv)
		if val == "" {
			fmt.Fprintf(stderr, "keyward: --passphrase-env %s is empty or unset "+
				"(export the variable and pass its NAME, not the passphrase itself)\n", passEnv)
			return 2
		}
		passphrase = []byte(val)
	}
	err = kagent.Add(pemBytes, passphrase, comment)

	// If the key is encrypted and we had no passphrase yet, prompt for one.
	if errors.Is(err, kagent.ErrPassphraseRequired) && passEnv == "" {
		pw, perr := readPassword("Passphrase: ", stderr)
		if perr != nil {
			fmt.Fprintln(stderr, "keyward: key is passphrase-protected; use --passphrase-env or run in a terminal")
			return 1
		}
		err = kagent.Add(pemBytes, pw, comment)
		crypto.ZeroBytes(pw)
	}

	if err != nil {
		fmt.Fprintf(stderr, "keyward: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "added %s to ssh-agent\n", path)
	return 0
}

func cmdAgentList(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintf(stderr, "agent list: unexpected argument %q\n", args[0])
		return 2
	}

	loaded, err := kagent.LoadedFingerprints()
	if err != nil {
		fmt.Fprintf(stderr, "keyward: %v\n", err)
		return 1
	}

	env, err := LoadEnv()
	if err != nil {
		fmt.Fprintf(stderr, "keyward: %v\n", err)
		return 1
	}

	for _, k := range env.Keys {
		mark := "  "
		if loaded[k.Fingerprint] {
			mark = "✓ "
		}
		fmt.Fprintf(stdout, "%s%-40s %s\n", mark, k.PrivateKeyPath, k.Fingerprint)
	}
	return 0
}
