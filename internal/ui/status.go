package ui

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// statusLevel is the kind of message shown in the message area above the hints.
type statusLevel int

const (
	statusError   statusLevel = iota // red; stays until the tab changes or a new message replaces it
	statusNotice                     // yellow; fades after statusTimeout
	statusSuccess                    // green; fades after statusTimeout
)

// statusTimeout is how long a notice or success message stays up. Errors have
// no timeout: they stay until the user leaves the tab, so a long one can be read.
const statusTimeout = 6 * time.Second

// maxStatusLines caps a wrapped message; anything longer is cut with an ellipsis.
const maxStatusLines = 3

// statusMsg asks the root model to show text in the message area. Screens send
// it instead of rendering their own result lines, so every result looks the same
// and appears in one place.
type statusMsg struct {
	level statusLevel
	text  string
}

// showStatus returns a command that puts text in the message area.
func showStatus(level statusLevel, text string) tea.Cmd {
	return func() tea.Msg { return statusMsg{level: level, text: text} }
}

// clearStatusMsg dismisses a timed message; token must match the current
// statusToken or the tick is stale and ignored.
type clearStatusMsg struct{ token int }

func clearStatusAfter(token int) tea.Cmd {
	return tea.Tick(statusTimeout, func(time.Time) tea.Msg {
		return clearStatusMsg{token: token}
	})
}

var (
	statusPrefix = map[statusLevel]string{statusError: "✗  ", statusNotice: "⚠  ", statusSuccess: "✓  "}
	statusStyle  = map[statusLevel]lipgloss.Style{
		statusError:   errorBarStyle,
		statusNotice:  warnMsgStyle,
		statusSuccess: savedStyle,
	}
)

// setStatus shows text at level, replacing any current message, and starts the
// fade timer for anything that is not an error.
func (m Model) setStatus(level statusLevel, text string) (Model, tea.Cmd) {
	// errors.Join puts each joined error on its own line; read them as one
	// sentence ("key rotation failed: failed to create key file: ...").
	text = strings.ReplaceAll(strings.TrimSpace(text), "\n", ": ")
	m.status = statusMsg{level: level, text: text}
	m.statusToken++
	m = m.propagateSize().syncScroll()
	if level == statusError {
		return m, nil
	}
	return m, clearStatusAfter(m.statusToken)
}

// clearStatus removes the current message.
func (m Model) clearStatus() Model {
	m.status = statusMsg{}
	return m.propagateSize().syncScroll()
}

// clearError removes the current message if it is an error: called when the
// action that failed has now succeeded, so the old failure no longer applies.
func (m Model) clearError() Model {
	if m.status.text != "" && m.status.level == statusError {
		return m.clearStatus()
	}
	return m
}

// prompt returns the active screen's pending confirmation question, if any.
// Confirmations live in the message area too, next to the hint that answers them.
func (m Model) prompt() string {
	switch m.active {
	case ScreenDetail:
		return m.keyDetail.confirmPrompt()
	case ScreenConfig:
		return m.cfgEditor.confirmPrompt()
	case ScreenKnownHosts:
		return m.knownHosts.confirmPrompt()
	case ScreenBackup:
		return m.backupView.confirmPrompt()
	}
	return ""
}

// messageLines renders the message area: the pending confirmation, else the
// current status message, wrapped to the frame and capped at maxStatusLines.
// It returns nil when there is nothing to show.
func (m Model) messageLines() []string {
	level, text := m.status.level, m.status.text
	if p := m.prompt(); p != "" {
		level, text = statusNotice, p
	}
	if text == "" {
		return nil
	}
	// Continuation lines are indented to start under the text, not the icon.
	// One column of gutter, matching the hints bar.
	prefix := " " + statusPrefix[level]
	indent := lipgloss.Width(prefix)
	w := max(m.innerWidth(), indent+10)
	wrapped := strings.Split(lipgloss.NewStyle().Width(w-indent).Render(text), "\n")
	for i := range wrapped {
		if i == 0 {
			wrapped[i] = prefix + wrapped[i]
		} else {
			wrapped[i] = strings.Repeat(" ", indent) + wrapped[i]
		}
	}
	if len(wrapped) > maxStatusLines {
		wrapped = wrapped[:maxStatusLines]
		last := strings.TrimRight(wrapped[maxStatusLines-1], " ")
		if lipgloss.Width(last) <= w-2 {
			last += " …"
		} else {
			last = fitRight(last, w)
		}
		wrapped[maxStatusLines-1] = last
	}
	for i, l := range wrapped {
		wrapped[i] = statusStyle[level].Render(strings.TrimRight(l, " "))
	}
	return wrapped
}

// messageHeight is how many rows the message area takes from the screen body:
// its lines plus the blank line that separates it from the content above.
func (m Model) messageHeight() int {
	if n := len(m.messageLines()); n > 0 {
		return n + 1
	}
	return 0
}
