package audit

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/gateway-of-last-resort/keyward/internal/config"
	"github.com/gateway-of-last-resort/keyward/internal/keys"
	"golang.org/x/crypto/ssh"
)

const maxKeyAge = 12 * 30 * 24 * time.Hour

// posixPermsEnforceable reports whether POSIX permission bits (0600 / 0700 /
// 0o077) are meaningful on this platform. On Windows os.FileMode is synthesized
// from file attributes and never matches these patterns, so real access is
// governed by NTFS ACLs instead. When this returns false the mode-equality
// checks are skipped and checkPlatformPermissionModel emits one Info describing
// the model, rather than each check silently skipping or raising a false alarm.
func posixPermsEnforceable() bool { return runtime.GOOS != "windows" }

// checkPlatformPermissionModel emits a single Info on platforms where Keyward
// cannot verify POSIX permission bits (Windows), so the audit still tells the
// user how their SSH files are actually protected instead of quietly skipping
// the permission checks. It returns nothing where the bits are enforceable.
func checkPlatformPermissionModel() []AuditResult {
	if posixPermsEnforceable() {
		return nil
	}
	return []AuditResult{{
		Severity: Info,
		Category: CategorySystem,
		Message:  "File access on Windows is governed by NTFS ACLs, not POSIX permission bits; the 0600/0700 checks are skipped",
		Fix:      "Verify ~/.ssh and your private keys are restricted to your user account (Properties -> Security)",
	}}
}

func resolveKeyPath(key keys.Key) string {
	keyPath := key.PrivateKeyPath
	if keyPath == "" {
		keyPath = key.PublicKeyPath
	}
	return keyPath
}

func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[2:])
		}
	}
	return os.ExpandEnv(path)
}

func checkPassphrase(key keys.Key) []AuditResult {

	var results []AuditResult

	// A public-only key legitimately has no private half — nothing to check.
	if key.IsPublicOnly {
		return results
	}

	// Not public-only, yet keys.Parse produced no usable private path: it saw a
	// private file it couldn't recognise (junk/BOM before -----BEGIN). Don't
	// stay silent — surface it.
	if key.PrivateKeyPath == "" {
		return append(results, AuditResult{
			KeyPath:  resolveKeyPath(key),
			Severity: Warning,
			Category: CategoryKey,
			Message:  "Private key present but not recognized",
			Fix:      "Ensure the key is valid PEM with no data before -----BEGIN",
		})
	}

	if key.PrivateKeyPath != "" {
		if data, err := os.ReadFile(key.PrivateKeyPath); err != nil {
			results = append(results, AuditResult{
				KeyPath:  key.PrivateKeyPath,
				Severity: Warning,
				Category: CategoryKey,
				Message:  "Make sure file exists and not damaged",
				Fix:      "chmod 600 " + key.PrivateKeyPath + " and make sure file exists",
			})

		} else {
			_, err := ssh.ParseRawPrivateKey(data)

			var passphraseErr *ssh.PassphraseMissingError
			switch {
			case errors.As(err, &passphraseErr):
				// key is protected — OK
			case err == nil:
				results = append(results, AuditResult{
					KeyPath:  key.PrivateKeyPath,
					Severity: Critical,
					Category: CategoryKey,
					Message:  "Private key must have passphrase",
					Fix:      "Use Keyward to generate a new Ed25519 key",
				})
			default:
				results = append(results, AuditResult{
					KeyPath:  key.PrivateKeyPath,
					Severity: Warning,
					Category: CategoryKey,
					Message:  "Could not parse private key",
					Fix:      "Check that the key file is valid and not corrupted",
				})
			}
		}
	}

	return results
}

func checkAlgorithm(key keys.Key) []AuditResult {
	var results []AuditResult

	if key.Algorithm != "" {
		if key.Algorithm == "ssh-dss" {
			keyPath := resolveKeyPath(key)
			results = append(results, AuditResult{
				KeyPath:  keyPath,
				Severity: Critical,
				Category: CategoryKey,
				Message:  "Algorithm is too unreliable",
				Fix:      "Use Keyward to generate a new Ed25519 key", // (press 'g')
			})
		}
	}

	return results
}

func checkBitSize(key keys.Key) []AuditResult {
	var results []AuditResult
	keyPath := resolveKeyPath(key)

	if key.Algorithm == "ssh-rsa" {
		switch {
		case key.BitSize == 0:
			return nil

		case key.BitSize < 2048:
			results = append(results, AuditResult{
				KeyPath:  keyPath,
				Severity: Critical,
				Category: CategoryKey,
				Message:  "Bit size must be at least 2048, better >=4096",
				Fix:      "Use Keyward to generate a new Ed25519 key", // (press 'g')
			})

		case key.BitSize == 2048:
			results = append(results, AuditResult{
				KeyPath:  keyPath,
				Severity: Warning,
				Category: CategoryKey,
				Message:  "Bit size should be greater than 2048",
				Fix:      "Use Keyward to generate a new Ed25519 key", // (press 'g')
			})

		case 2048 < key.BitSize && key.BitSize < 4096:
			results = append(results, AuditResult{
				KeyPath:  keyPath,
				Severity: Info,
				Category: CategoryKey,
				Message:  "Bit size should be >= 4096",
				Fix:      "Use Keyward to regenerate this key with 4096 bits", // (press 'g')
			})

		case key.BitSize >= 4096:
			return nil
		}

	}
	return results
}

func checkPermissions(key keys.Key) []AuditResult {
	var results []AuditResult

	if !key.IsPublicOnly {
		// A private file that exists but could not be parsed (junk or a BOM
		// before -----BEGIN) leaves PrivateKeyPath empty while IsPublicOnly
		// stays false. checkKeyValidity already reports that as "not
		// recognized", so stat("") here would only add a second finding for the
		// same file, and a pathless one at that.
		if key.PrivateKeyPath == "" {
			return results
		}

		if stat, err := os.Stat(key.PrivateKeyPath); err != nil {
			results = append(results, AuditResult{
				KeyPath:  key.PrivateKeyPath,
				Severity: Warning,
				Category: CategoryKey,
				Message:  "Private key does not exist or damaged",
				Fix:      "Make sure file exists and not damaged",
			})
		} else if posixPermsEnforceable() && stat.Mode().Perm() != 0600 {
			// On Windows the mode is synthesized and never equals 0600, so a
			// POSIX-bit comparison would flag every key Critical regardless of
			// the real ACL; posixPermsEnforceable() gates it off there and
			// checkPlatformPermissionModel explains the model once instead.
			results = append(results, AuditResult{
				KeyPath:  key.PrivateKeyPath,
				Severity: Critical,
				Category: CategoryKey,
				Message:  "Permissions must be 0600",
				Fix:      "chmod 600 " + key.PrivateKeyPath,
			})
		}
	}

	return results
}

func checkAge(key keys.Key) []AuditResult {
	var results []AuditResult
	keyPath := resolveKeyPath(key)

	if !key.ModifiedAt.IsZero() {
		if time.Since(key.ModifiedAt) > maxKeyAge {
			results = append(results, AuditResult{
				KeyPath:  keyPath,
				Severity: Warning,
				Category: CategoryKey,
				Message:  "Key is too old",
				Fix:      "Use Keyward to rotate this key", //(press 'r')
			})
		}
	}
	return results
}

func checkStrictHostKeyChecking(cfg *config.Config) []AuditResult {
	var results []AuditResult
	if value, found := config.GetParam(&cfg.Global, "StrictHostKeyChecking"); found {
		if strings.EqualFold(value[0], "no") || strings.EqualFold(value[0], "off") {
			results = append(results, AuditResult{
				Severity: Warning,
				Category: CategoryConfig,
				Message:  "StrictHostKeyChecking is disabled by configuration",
				Fix:      "Set StrictHostKeyChecking to 'accept-new' in config",
			})
		}
	}
	for _, block := range cfg.Blocks {
		if value, found := config.GetParam(&block, "StrictHostKeyChecking"); found {
			if strings.EqualFold(value[0], "no") || strings.EqualFold(value[0], "off") {
				results = append(results, AuditResult{
					Severity: Warning,
					Category: CategoryConfig,
					Message:  "StrictHostKeyChecking is disabled by configuration",
					Fix:      "Set StrictHostKeyChecking to 'accept-new' in config",
				})
			}
		}
	}

	return results
}

func checkIdentityFileExists(cfg *config.Config) []AuditResult {
	var results []AuditResult

	for _, block := range cfg.Blocks {
		if values, found := config.GetParam(&block, "IdentityFile"); found {
			for _, path := range values {
				expandedPath := expandPath(path)
				if _, err := os.Stat(expandedPath); err != nil {
					results = append(results, AuditResult{
						KeyPath:  expandedPath,
						Severity: Warning,
						Category: CategoryConfig,
						Message:  "Identity file does not exist",
						Fix:      "Check that the key exists at " + expandedPath + " or update IdentityFile in config",
					})
				}
			}
		}
	}
	return results
}

func newCheckKeyLinkedToHost(allKeys []keys.Key) ConfigCheck {
	return func(cfg *config.Config) []AuditResult {
		linkedPaths := make(map[string]bool)

		for _, block := range cfg.Blocks {
			if values, found := config.GetParam(&block, "IdentityFile"); found {
				for _, path := range values {
					linkedPaths[expandPath(path)] = true
				}
			}
		}

		var results []AuditResult
		for _, key := range allKeys {
			if !key.IsPublicOnly {
				path := resolveKeyPath(key)
				if !linkedPaths[path] {
					results = append(results, AuditResult{
						KeyPath:  path,
						Severity: Info,
						Category: CategoryKey,
						Message:  "key not linked to any host",
						Fix:      "Link this key to a host in config using IdentityFile", // (press 'e')
					})
				}
			}
		}
		return results
	}
}

func newCheckSSHDirPermissions(dir string) SystemCheck {
	return func() []AuditResult {
		var results []AuditResult

		stat, err := os.Stat(dir)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			results = append(results, AuditResult{
				KeyPath:  dir,
				Severity: Warning,
				Category: CategorySystem,
				Message:  "Can't check permissions on this directory",
				Fix:      "Check that " + dir + " is accessible",
			})
		} else if posixPermsEnforceable() && stat.Mode().Perm() != 0700 {
			results = append(results, AuditResult{
				KeyPath:  dir,
				Severity: Critical,
				Category: CategorySystem,
				Message:  "Permissions must be 0700",
				Fix:      "chmod 0700 " + dir,
			})
		}

		return results
	}
}

func checkSSHAgent() []AuditResult {
	var results []AuditResult

	if os.Getenv("SSH_AUTH_SOCK") == "" {
		results = append(results, AuditResult{
			Severity: Info,
			Category: CategorySystem,
			Message:  "ssh-agent not running",
			Fix:      "Start ssh-agent: eval $(ssh-agent -s)",
		})
	}
	return results
}

// configScopes returns the Global block followed by every Host/Match block so a
// config check can scan the whole file uniformly.
func configScopes(cfg *config.Config) []*config.Block {
	scopes := make([]*config.Block, 0, len(cfg.Blocks)+1)
	scopes = append(scopes, &cfg.Global)
	for i := range cfg.Blocks {
		scopes = append(scopes, &cfg.Blocks[i])
	}
	return scopes
}

func checkForwardAgent(cfg *config.Config) []AuditResult {
	var results []AuditResult
	for _, scope := range configScopes(cfg) {
		if value, found := config.GetParam(scope, "ForwardAgent"); found {
			if strings.EqualFold(value[0], "yes") {
				results = append(results, AuditResult{
					Severity: Warning,
					Category: CategoryConfig,
					Message:  "ForwardAgent is enabled",
					Fix:      "Avoid 'ForwardAgent yes'; forward per-connection with 'ssh -A' only to trusted hosts",
				})
			}
		}
	}
	return results
}

// referencesDevNull reports whether a UserKnownHostsFile value names /dev/null as
// one of its space-separated (and possibly quoted) paths, so a value like
// "/dev/null ~/.ssh/known_hosts" or "\"/dev/null\"" is still caught.
func referencesDevNull(value string) bool {
	for _, f := range strings.Fields(value) {
		if strings.Trim(f, `"'`) == "/dev/null" {
			return true
		}
	}
	return false
}

func checkUserKnownHostsDevNull(cfg *config.Config) []AuditResult {
	var results []AuditResult
	for _, scope := range configScopes(cfg) {
		if values, found := config.GetParam(scope, "UserKnownHostsFile"); found && slices.ContainsFunc(values, referencesDevNull) {
			results = append(results, AuditResult{
				Severity: Critical,
				Category: CategoryConfig,
				Message:  "UserKnownHostsFile is /dev/null (host-key verification disabled)",
				Fix:      "Remove 'UserKnownHostsFile /dev/null'; it disables host-key checking and enables MITM",
			})
		}
	}
	return results
}

// newCheckConfigPermissions verifies that ~/.ssh/config is not readable or
// writable by group/others (it can leak hostnames, usernames, ProxyCommands).
func newCheckConfigPermissions(sshDir string) SystemCheck {
	return func() []AuditResult {
		path := filepath.Join(sshDir, "config")

		stat, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return []AuditResult{{
				KeyPath:  path,
				Severity: Warning,
				Category: CategorySystem,
				Message:  "Can't check permissions on the SSH config",
				Fix:      "Check that " + path + " is accessible",
			}}
		}
		if posixPermsEnforceable() && stat.Mode().Perm()&0o077 != 0 {
			return []AuditResult{{
				KeyPath:  path,
				Severity: Warning,
				Category: CategorySystem,
				Message:  "SSH config is accessible by group/others",
				Fix:      "chmod 600 " + path,
			}}
		}
		return nil
	}
}
