package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gateway-of-last-resort/keyward/internal/storage"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

// cmdBackup creates an encrypted backup of ~/.ssh plus key metadata without the
// TUI, so it can run from cron. The master password comes from KEYWARD_PASSWORD
// or an interactive no-echo prompt.
func cmdBackup(args []string, stdout, stderr io.Writer) int {
	var outPath string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--out":
			i++
			if i >= len(args) {
				fmt.Fprintln(stderr, "backup: --out needs a path")
				return 2
			}
			outPath = args[i]
		case strings.HasPrefix(arg, "--out="):
			outPath = strings.TrimPrefix(arg, "--out=")
		default:
			fmt.Fprintf(stderr, "backup: unexpected argument %q\n", arg)
			return 2
		}
	}

	env, err := LoadEnv()
	if err != nil {
		fmt.Fprintf(stderr, "keyward: %v\n", err)
		return 1
	}

	masterKeyPath := filepath.Join(env.VaultDir, "master.key")
	if !crypto.MasterKeyExists(masterKeyPath) {
		fmt.Fprintln(stderr, "keyward: no vault found; run keyward once to set one up")
		return 1
	}

	password, err := resolvePassword(stderr)
	if err != nil {
		fmt.Fprintf(stderr, "keyward: %v\n", err)
		return 1
	}
	defer crypto.ZeroBytes(password)

	identity, err := crypto.LoadMasterKey(masterKeyPath, string(password))
	if err != nil {
		fmt.Fprintf(stderr, "keyward: cannot unlock vault (wrong password?): %v\n", err)
		return 1
	}

	res, err := storage.CreateBackup(env.SSHDir, env.VaultDir, identity)
	if err != nil {
		fmt.Fprintf(stderr, "keyward: %v\n", err)
		return 1
	}

	finalPath := res.Path
	if outPath != "" {
		if err := copyToOut(res.Path, outPath); err != nil {
			fmt.Fprintf(stderr, "keyward: backup created at %s but copy to %s failed: %v\n", res.Path, outPath, err)
			return 1
		}
		finalPath = outPath
	}

	fmt.Fprintf(stdout, "backup written to %s\n", finalPath)
	if len(res.Skipped) > 0 {
		fmt.Fprintf(stderr, "note: skipped unreadable files: %s\n", strings.Join(res.Skipped, ", "))
	}
	if res.PruneErr != nil {
		fmt.Fprintf(stderr, "note: could not prune old backups: %v\n", res.PruneErr)
	}
	return 0
}

// resolvePassword reads the master password from KEYWARD_PASSWORD, falling back
// to an interactive no-echo prompt.
func resolvePassword(stderr io.Writer) ([]byte, error) {
	if v := os.Getenv("KEYWARD_PASSWORD"); v != "" {
		return []byte(v), nil
	}
	return readPassword("Master password: ", stderr)
}

// copyToOut copies the age-encrypted backup to dst with 0600 permissions.
func copyToOut(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}
