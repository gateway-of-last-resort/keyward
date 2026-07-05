package cli

import (
	"encoding/json"
	"fmt"
	"io"
)

// keyInfo is the compact, stable JSON/text shape for `keyward list` — a curated
// projection of keys.Key that avoids leaking internal fields.
type keyInfo struct {
	Path          string `json:"path"`
	Fingerprint   string `json:"fingerprint"`
	Algorithm     string `json:"algorithm"`
	BitSize       int    `json:"bit_size"`
	Comment       string `json:"comment,omitempty"`
	HasPassphrase bool   `json:"has_passphrase"`
	PublicOnly    bool   `json:"public_only"`
}

// cmdList prints the discovered SSH keys as a text table or JSON.
func cmdList(args []string, stdout, stderr io.Writer) int {
	var jsonOut bool
	for _, arg := range args {
		switch arg {
		case "--json":
			jsonOut = true
		default:
			fmt.Fprintf(stderr, "list: unknown argument %q\n", arg)
			return 2
		}
	}

	env, err := LoadEnv()
	if err != nil {
		fmt.Fprintf(stderr, "keyward: %v\n", err)
		return 1
	}

	infos := make([]keyInfo, 0, len(env.Keys))
	for _, k := range env.Keys {
		infos = append(infos, keyInfo{
			Path:          k.PrivateKeyPath,
			Fingerprint:   k.Fingerprint,
			Algorithm:     k.Algorithm,
			BitSize:       k.BitSize,
			Comment:       k.Comment,
			HasPassphrase: k.HasPassphrase,
			PublicOnly:    k.IsPublicOnly,
		})
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(infos); err != nil {
			fmt.Fprintf(stderr, "keyward: %v\n", err)
			return 1
		}
		return 0
	}

	writeKeysText(stdout, infos)
	return 0
}

func writeKeysText(w io.Writer, infos []keyInfo) {
	if len(infos) == 0 {
		fmt.Fprintln(w, "No SSH keys found.")
		return
	}
	for _, k := range infos {
		lock := "no-pass"
		if k.HasPassphrase {
			lock = "encrypted"
		}
		if k.PublicOnly {
			lock = "public-only"
		}
		fmt.Fprintf(w, "%-40s %-12s %5d  %-11s %s\n",
			k.Path, k.Algorithm, k.BitSize, lock, k.Comment)
	}
}
