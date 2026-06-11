// TODO: add OpenSSH version compatibility checks
// need to detect installed OpenSSH version via "ssh -V"
// and warn about directives not supported in older versions

// TODO: add additional validation checks:
// - IdentityFile without ~ or / prefix (relative path)
// - PasswordAuthentication yes (security risk)
// - ProxyJump host exists in config
// - ServerAliveInterval, ConnectTimeout, ControlPersist numeric validation

package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func ValidateBlock(b *Block) []ValidationResult {

	results := []ValidationResult{}

	port, found := GetParamWithLine(b, "Port")

	if found {
		portInt, err := strconv.Atoi(port[0].Value)
		if err != nil {
			results = append(results, ValidationResult{
				Block:   b,
				Line:    port[0].Line,
				Field:   "Port",
				Message: "Port must be a number",
				Level:   LevelError,
			})
		} else {
			if portInt > 65535 || portInt < 1 {
				results = append(results, ValidationResult{
					Block:   b,
					Line:    port[0].Line,
					Field:   "Port",
					Message: "Port must be between 1 and 65535",
					Level:   LevelError,
				})
			}
		}
	}

	identityFile, found := GetParamWithLine(b, "IdentityFile")
	if found {
		for _, file := range identityFile {

			path := file.Value
			if strings.HasPrefix(path, "~/") {
				home, err := os.UserHomeDir()
				if err == nil {
					path = filepath.Join(home, path[2:])
				}
			}
			path = os.ExpandEnv(path)
			stat, err := os.Stat(path)

			if os.IsNotExist(err) {
				results = append(results, ValidationResult{
					Block:   b,
					Line:    file.Line,
					Field:   "IdentityFile",
					Message: "IdentityFile does not exist",
					Level:   LevelWarning,
				})
			} else if err == nil {
				perm := stat.Mode().Perm()
				if perm != 0600 && perm != 0400 {
					results = append(results, ValidationResult{
						Block:   b,
						Line:    file.Line,
						Field:   "IdentityFile",
						Message: "IdentityFile permissions should be 0600 or 0400",
						Level:   LevelWarning,
					})
				}
			}

		}
	}

	forwardAgent, found := GetParamWithLine(b, "ForwardAgent")

	if found {
		value := strings.ToLower(forwardAgent[0].Value)
		switch value {
		case "yes", "no", "ask":
		default:
			results = append(results, ValidationResult{
				Block:   b,
				Line:    forwardAgent[0].Line,
				Field:   "ForwardAgent",
				Message: "ForwardAgent must be 'yes', 'no' or 'ask'",
				Level:   LevelWarning,
			})
		}
	}

	strictHostKeyChecking, found := GetParamWithLine(b, "StrictHostKeyChecking")

	if found {
		value := strings.ToLower(strictHostKeyChecking[0].Value)
		switch value {
		case "yes", "no", "ask", "accept-new":
		default:
			results = append(results, ValidationResult{
				Block:   b,
				Line:    strictHostKeyChecking[0].Line,
				Field:   "StrictHostKeyChecking",
				Message: "StrictHostKeyChecking must be 'yes', 'no', 'ask' or 'accept-new'",
				Level:   LevelWarning,
			})
		}
	}

	user, found := GetParamWithLine(b, "User")
	if found {
		value := strings.TrimSpace(user[0].Value)
		if value == "" {
			results = append(results, ValidationResult{
				Block:   b,
				Line:    user[0].Line,
				Field:   "User",
				Message: "No user specified",
				Level:   LevelError,
			})
		}
	}
	return results
}

func ValidateConfig(c *Config) []ValidationResult {
	results := []ValidationResult{}

	globalResults := ValidateBlock(&c.Global)
	results = append(results, globalResults...)

	for _, token := range c.Global.Tokens {
		if token.Type == PARAM &&
			strings.EqualFold(token.Key, "StrictHostKeyChecking") &&
			strings.EqualFold(token.Value, "no") {
			results = append(results, ValidationResult{
				Block:   &c.Global,
				Line:    token.LineNum,
				Field:   "StrictHostKeyChecking",
				Message: "StrictHostKeyChecking no in global block affects all hosts",
				Level:   LevelError,
			})
		}
	}

	hosts := map[string]int{}

	for i := range c.Blocks {
		if _, exists := hosts[c.Blocks[i].Pattern]; !exists {
			hosts[c.Blocks[i].Pattern] = 1
		} else {
			line := 0
			for _, token := range c.Blocks[i].Tokens {
				if token.Type == HOST {
					line = token.LineNum
					break
				}
			}

			results = append(results, ValidationResult{
				Block:   &c.Blocks[i],
				Line:    line,
				Field:   "Host",
				Message: "Host already exists",
				Level:   LevelError,
			})
		}
	}

	var starBlock *Block
	for i := range c.Blocks {
		if c.Blocks[i].Pattern == "*" {
			starBlock = &c.Blocks[i]
			break
		}
	}

	if starBlock != nil {
		starParams := map[string]bool{}
		for _, token := range starBlock.Tokens {
			if token.Type == PARAM {
				starParams[strings.ToLower(token.Key)] = true
				if strings.EqualFold(token.Key, "StrictHostKeyChecking") {
					if strings.EqualFold(token.Value, "no") {
						results = append(results, ValidationResult{
							Block:   starBlock,
							Line:    token.LineNum,
							Field:   "StrictHostKeyChecking",
							Message: "StrictHostKeyChecking can't be 'no'",
							Level:   LevelError,
						})
					}
				}
			}
		}

		for i := range c.Blocks {
			if c.Blocks[i].Pattern == "*" {
				continue
			}
			for _, token := range c.Blocks[i].Tokens {
				if token.Type == PARAM && starParams[strings.ToLower(token.Key)] {
					results = append(results, ValidationResult{
						Block:   &c.Blocks[i],
						Line:    token.LineNum,
						Field:   token.Key,
						Message: "overrides parameter already set in Host *",
						Level:   LevelWarning,
					})
				}
			}
		}
	}

	for i := range c.Blocks {
		blockResults := ValidateBlock(&c.Blocks[i])
		results = append(results, blockResults...)
	}

	return results
}
