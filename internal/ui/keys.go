package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
	"github.com/gateway-of-last-resort/keyward/internal/keys"
)

// keyListModel renders the main key list screen.
type keyListModel struct {
	width, height int
	items         []keyListItem
	cursor        int
	searching     bool
	query         string
}

type keyListItem struct {
	key      keys.Key
	severity audit.Severity
}

func newKeyListModel(ks []keys.Key, results []audit.AuditResult) keyListModel {
	worst := map[string]audit.Severity{}
	for _, r := range results {
		cur := worst[r.KeyPath]
		switch {
		case r.Severity == audit.Critical:
			worst[r.KeyPath] = audit.Critical
		case r.Severity == audit.Warning && cur != audit.Critical:
			worst[r.KeyPath] = audit.Warning
		case r.Severity == audit.Info && cur == "":
			worst[r.KeyPath] = audit.Info
		}
	}
	items := make([]keyListItem, len(ks))
	for i, k := range ks {
		items[i] = keyListItem{key: k, severity: worst[k.PrivateKeyPath]}
	}
	return keyListModel{items: items}
}

// --- keys-screen-specific styles ---

// --- column widths ---

const (
	colName = 52
	colAlgo = 14
	colBits = 8
	colStat = 12
)

func (m keyListModel) update(msg tea.Msg) (keyListModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.searching {
			return m.updateSearch(msg)
		}
		return m.updateNav(msg)
	}
	return m, nil
}

func (m keyListModel) updateNav(msg tea.KeyMsg) (keyListModel, tea.Cmd) {
	visible := m.visible()
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(visible)-1 {
			m.cursor++
		}
	case "enter":
		if len(visible) > 0 {
			return m, navigateDetail(visible[m.cursor].originalIdx)
		}
	case "/":
		m.searching = true
		m.query = ""
		m.cursor = 0
	case "q":
		return m, tea.Quit
	}
	return m, nil
}

func (m keyListModel) updateSearch(msg tea.KeyMsg) (keyListModel, tea.Cmd) {
	switch msg.String() {
	case "enter":
		m.searching = false
	case "esc":
		m.searching = false
		m.query = ""
		m.cursor = 0
	case "backspace":
		if len(m.query) > 0 {
			r := []rune(m.query)
			m.query = string(r[:len(r)-1])
			m.cursor = 0
		}
	default:
		if len(msg.Runes) > 0 {
			m.query += string(msg.Runes)
			m.cursor = 0
		}
	}
	return m, nil
}

type visibleItem struct {
	keyListItem
	originalIdx int
}

func (m keyListModel) visible() []visibleItem {
	q := strings.ToLower(m.query)
	var out []visibleItem
	for i, item := range m.items {
		if q == "" ||
			strings.Contains(strings.ToLower(item.key.PrivateKeyPath), q) ||
			strings.Contains(strings.ToLower(item.key.Comment), q) ||
			strings.Contains(strings.ToLower(item.key.Algorithm), q) {
			out = append(out, visibleItem{item, i})
		}
	}
	return out
}

func (m keyListModel) view() string {
	visible := m.visible()

	// table header
	hdr := fmt.Sprintf("  %-*s  %-*s  %-*s  %s",
		colName, "Name",
		colAlgo, "Algorithm",
		colBits, "Bits",
		"Status",
	)
	header := sectionHeaderStyle.PaddingLeft(0).Width(m.width - 2).Render(hdr)

	// available rows = height minus header (2) minus search bar (2)
	maxRows := m.height - 4
	if maxRows < 1 {
		maxRows = 1
	}

	// scroll window
	start := 0
	if m.cursor >= maxRows {
		start = m.cursor - maxRows + 1
	}
	end := start + maxRows
	if end > len(visible) {
		end = len(visible)
	}

	var rows strings.Builder
	for i := start; i < end; i++ {
		rows.WriteString(m.renderRow(visible[i], i == m.cursor) + "\n")
	}
	if len(visible) == 0 {
		rows.WriteString(dimStyle.Render("  no keys found") + "\n")
	}

	// scroll indicator
	scrollHint := ""
	if len(visible) > maxRows {
		scrollHint = dimStyle.Render(fmt.Sprintf("  %d–%d of %d", start+1, end, len(visible)))
	}

	// search bar
	searchBar := ""
	if m.searching {
		searchBar = "\n" + labelStyle.Render("/") + " " + m.query + "█"
	} else if m.query != "" {
		searchBar = "\n" + dimStyle.Render("filter: "+m.query+"   (/ to edit · esc clear)")
	}

	return header + "\n" + rows.String() + scrollHint + searchBar
}

func (m keyListModel) renderRow(item visibleItem, selected bool) string {
	name := fitLeft(item.key.PrivateKeyPath, colName)
	algo := pad(item.key.Algorithm, colAlgo)
	bits := pad("—", colBits)
	if item.key.BitSize > 0 {
		bits = pad(fmt.Sprintf("%d", item.key.BitSize), colBits)
	}

	var statusStr string
	if badge, ok := severityBadge[item.severity]; ok {
		icon := map[audit.Severity]string{
			audit.Critical: "✗",
			audit.Warning:  "⚠",
			audit.Info:     "i",
		}[item.severity]
		label := icon + " " + string(item.severity)
		const badgeTextWidth = 10
		if runes := []rune(label); len(runes) < badgeTextWidth {
			label += strings.Repeat(" ", badgeTextWidth-len(runes))
		}
		statusStr = badge.Render(label)
	} else {
		statusStr = okStyle.Render("✓ OK")
	}

	row := fmt.Sprintf("  %-*s  %-*s  %-*s  %s",
		colName, name,
		colAlgo, algo,
		colBits, bits,
		statusStr,
	)

	if selected {
		return selectedRowStyle.Render(row)
	}
	return row
}

// fitLeft shortens s to n runes, prefixing with "…" if truncated.
func fitLeft(s string, n int) string {
	if n <= 1 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return "…" + string(runes[len(runes)-(n-1):])
}

// pad right-pads s to width w.
func pad(s string, w int) string {
	runes := []rune(s)
	if len(runes) >= w {
		return string(runes[:w])
	}
	return s + strings.Repeat(" ", w-len(runes))
}
