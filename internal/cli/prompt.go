package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// ErrNoTerminal means a password was needed but stdin is not an interactive
// terminal (so we can't prompt without echoing).
var ErrNoTerminal = errors.New("no terminal available for password prompt")

// readPassword prompts on stderr and reads a line from the terminal without
// echoing it. Callers must zero the returned bytes when done.
func readPassword(prompt string, stderr io.Writer) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, ErrNoTerminal
	}
	fmt.Fprint(stderr, prompt)
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	if err != nil {
		return nil, err
	}
	return pw, nil
}
