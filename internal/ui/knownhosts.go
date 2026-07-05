package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gateway-of-last-resort/keyward/internal/knownhosts"
)

// knownHostsModel renders the known_hosts viewer screen: a scrollable list of
// entries with a two-step "forget" (delete) action.
type knownHostsModel struct {
	width, height int
	entries       []knownhosts.Entry
	cursor        int
	sshDir        string
	path          string
	confirmForget bool
}

func newKnownHostsModel(entries []knownhosts.Entry, sshDir, path string) knownHostsModel {
	return knownHostsModel{entries: entries, sshDir: sshDir, path: path}
}

// khForgotMsg is emitted after an entry is removed from known_hosts.
type khForgotMsg struct{ host string }

// forgetHostCmd removes the entry at lineNum from the known_hosts file.
func forgetHostCmd(path string, lineNum int, host string) tea.Cmd {
	return func() tea.Msg {
		if err := knownhosts.Forget(path, lineNum); err != nil {
			return errMsg{err}
		}
		return khForgotMsg{host: host}
	}
}

func (m knownHostsModel) update(msg tea.Msg) (knownHostsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			m.confirmForget = false
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			m.confirmForget = false
			if m.cursor < len(m.entries)-1 {
				m.cursor++
			}
		case "d":
			if len(m.entries) == 0 {
				return m, nil
			}
			if !m.confirmForget {
				m.confirmForget = true
				return m, nil
			}
			m.confirmForget = false
			e := m.entries[m.cursor]
			return m, forgetHostCmd(m.path, e.LineNum, khHostLabel(e))
		case "esc":
			if m.confirmForget {
				m.confirmForget = false
				return m, nil
			}
			return m, navigate(ScreenKeys)
		}
	}
	return m, nil
}

// khHostLabel returns a short display label for an entry's host field.
func khHostLabel(e knownhosts.Entry) string {
	if e.Hashed {
		return "(hashed host)"
	}
	if len(e.Hosts) == 0 {
		return "(unknown)"
	}
	if len(e.Hosts) == 1 {
		return e.Hosts[0]
	}
	return fmt.Sprintf("%s +%d", e.Hosts[0], len(e.Hosts)-1)
}

// --- known_hosts column widths ---

const (
	khColHost = 34
	khColType = 20
)

var khMarkerStyle = map[string]lipgloss.Style{
	"revoked":        lipgloss.NewStyle().Foreground(colRed).Bold(true),
	"cert-authority": lipgloss.NewStyle().Foreground(colCyan).Bold(true),
}

func (m knownHostsModel) view() string {
	var sb strings.Builder

	hdr := fmt.Sprintf("  %-*s  %-*s  %s", khColHost, "Host", khColType, "Key Type", "Fingerprint")
	sb.WriteString(sectionHeaderStyle.PaddingLeft(0).Width(m.width).Render(hdr) + "\n")

	if len(m.entries) == 0 {
		sb.WriteString(dimStyle.Render("  no known_hosts entries") + "\n")
		return sb.String()
	}

	// available rows = height minus header (1) minus confirm/hint line (2)
	maxRows := m.height - 3
	if maxRows < 1 {
		maxRows = 1
	}
	start := 0
	if m.cursor >= maxRows {
		start = m.cursor - maxRows + 1
	}
	end := start + maxRows
	if end > len(m.entries) {
		end = len(m.entries)
	}

	for i := start; i < end; i++ {
		sb.WriteString(m.renderRow(m.entries[i], i == m.cursor) + "\n")
	}

	if len(m.entries) > maxRows {
		fmt.Fprintf(&sb, "%s\n", dimStyle.Render(fmt.Sprintf(
			"  %d–%d of %d", start+1, end, len(m.entries),
		)))
	}

	if m.confirmForget {
		e := m.entries[m.cursor]
		sb.WriteString("\n" + warnMsgStyle.Render(fmt.Sprintf(
			"forget %s? press d again to confirm · esc to cancel", khHostLabel(e),
		)))
	}

	return sb.String()
}

func (m knownHostsModel) renderRow(e knownhosts.Entry, selected bool) string {
	host := fitRight(khHostLabel(e), khColHost)
	keyType := pad(e.KeyType, khColType)

	fp := e.Fingerprint
	if e.Marker != "" {
		style := khMarkerStyle[e.Marker]
		fp = style.Render("@"+e.Marker) + "  " + fp
	}

	body := fmt.Sprintf("%-*s  %-*s  %s", khColHost, host, khColType, keyType, fp)

	if selected {
		return selectedRow(body)
	}
	return "  " + body
}
