package config

import (
	"errors"
	"strings"
)

// ErrControlChars is returned by validation when a config value or host pattern
// contains a newline, carriage return, or other control character. Such a value
// would serialize into extra lines and could inject unrelated directives (up to
// ProxyCommand), so it is rejected at the edge.
var ErrControlChars = errors.New("value must not contain control characters")

// hasControlChars reports whether s contains any ASCII control character
// (0x00–0x1F, including tab, newline and carriage return) or DEL (0x7F). SSH
// config values and patterns are single-line, so none of these are ever valid.
func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// sanitize strips the control characters detected by hasControlChars. It is the
// last-resort guard in the mutation layer: even a caller that bypasses
// ValidateParamValue (e.g. a future import path or programmatic API) cannot
// smuggle a newline into a value and materialize a new config directive.
func sanitize(s string) string {
	if !hasControlChars(s) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
