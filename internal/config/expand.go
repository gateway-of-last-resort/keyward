package config

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// ExpandPath resolves a path-valued ssh_config argument (IdentityFile and the
// like) the way ssh does for the parts keyward can know without a connection:
// surrounding quotes, a leading ~, ${VAR}, and the %d (home), %u (local user) and
// %% tokens. It returns ok=false for "none" and for values with tokens that
// depend on the connection (%h, %r, %p, ...), which have no fixed path to check.
func ExpandPath(value string) (string, bool) {
	v := strings.TrimSpace(value)
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	if v == "" || strings.EqualFold(v, "none") {
		return "", false
	}

	home, homeErr := os.UserHomeDir()
	if v == "~" || strings.HasPrefix(v, "~/") {
		if homeErr != nil {
			return "", false
		}
		v = filepath.Join(home, v[1:])
	} else if strings.HasPrefix(v, "~") {
		return "", false // ~otheruser
	}

	var sb strings.Builder
	for i := 0; i < len(v); i++ {
		switch {
		case v[i] == '%' && i+1 < len(v):
			i++
			switch v[i] {
			case '%':
				sb.WriteByte('%')
			case 'd':
				if homeErr != nil {
					return "", false
				}
				sb.WriteString(home)
			case 'u':
				u, err := user.Current()
				if err != nil {
					return "", false
				}
				sb.WriteString(u.Username)
			default:
				return "", false
			}
		case v[i] == '$' && i+1 < len(v) && v[i+1] == '{':
			end := strings.IndexByte(v[i:], '}')
			if end < 0 {
				return "", false
			}
			sb.WriteString(os.Getenv(v[i+2 : i+end]))
			i += end
		default:
			sb.WriteByte(v[i])
		}
	}
	return sb.String(), true
}
