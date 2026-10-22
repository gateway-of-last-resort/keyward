package cli

import "strings"

// displaySafe strips control characters from text that came off disk (key
// comments, file names) before it is printed. A .pub comment can carry an ESC
// sequence, and printed raw it would drive the terminal: rewrite the clipboard
// (OSC 52), retitle the window, or overwrite what is on screen. C1 controls go
// too, since some terminals act on them as escape introducers. Tabs become
// spaces so the columns stay readable.
func displaySafe(s string) string {
	isControl := func(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) }
	if !strings.ContainsFunc(s, isControl) {
		return s
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case isControl(r):
			return -1
		}
		return r
	}, s)
}
