package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
)

// auditModel renders the audit dashboard screen.
type auditModel struct {
	width, height int
	report        audit.AuditReport
	cursor        int
	offset        int // first visible finding; see scrollOffset
}

// listRows is the number of finding rows that fit below the summary.
func (m auditModel) listRows() int { return max(m.height-8, 1) }

// syncScroll stores the scroll window for the current cursor.
func (m auditModel) syncScroll() auditModel {
	m.offset = scrollOffset(m.offset, m.cursor, m.listRows(), len(m.report.Results))
	return m
}

func newAuditModel(report audit.AuditReport) auditModel {
	return auditModel{report: report}
}

func gradeColor(g audit.Grade) lipgloss.Color {
	switch g {
	case audit.GradeA:
		return colGreen
	case audit.GradeB:
		return colCyan
	case audit.GradeC:
		return colYellow
	case audit.GradeD:
		return lipgloss.Color("#fb923c")
	default:
		return colRed
	}
}

func (m auditModel) update(msg tea.Msg) (auditModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.report.Results)-1 {
				m.cursor++
			}
		case "esc":
			return m, navigate(ScreenKeys)
		}
	}
	return m, nil
}

func (m auditModel) view() string {
	r := m.report
	var sb strings.Builder

	sb.WriteString(sectionHeaderStyle.Width(m.width).Render("Security Audit") + "\n\n")

	// ── Grade + score bar ──────────────────────────────────────────────────────
	gradeStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(gradeColor(r.Grade)).
		Width(3)

	barWidth := m.width - 30
	if barWidth < 10 {
		barWidth = 10
	}

	fmt.Fprintf(&sb, "  Grade  %s  %s  %3d / 100\n",
		gradeStyle.Render(string(r.Grade)),
		ScoreBar(r.Points, barWidth),
		r.Points,
	)

	// ── Counters ───────────────────────────────────────────────────────────────
	crit := severityStyle[audit.Critical].Render(fmt.Sprintf("%d critical", r.CriticalCount))
	warn := severityStyle[audit.Warning].Render(fmt.Sprintf("%d warnings", r.WarningCount))
	info := severityStyle[audit.Info].Render(fmt.Sprintf("%d info", r.InfoCount))
	fmt.Fprintf(&sb, "         %s  ·  %s  ·  %s\n\n", crit, warn, info)

	if len(r.Results) == 0 {
		sb.WriteString("  " + okStyle.Render("✓  No issues found.") + "\n")
		return sb.String()
	}

	// ── Divider ────────────────────────────────────────────────────────────────
	sb.WriteString(dimStyle.Render(strings.Repeat("─", m.width)) + "\n")

	// ── Findings list ──────────────────────────────────────────────────────────
	maxRows := m.listRows()
	start := scrollOffset(m.offset, m.cursor, maxRows, len(r.Results))
	end := start + maxRows
	if end > len(r.Results) {
		end = len(r.Results)
	}

	for i := start; i < end; i++ {
		res := r.Results[i]
		selected := i == m.cursor

		badge := badgeForSeverity(res.Severity)
		body := badge + "  " + res.Message
		line := "  " + body
		if selected {
			line = selectedRow(body)
		}
		sb.WriteString(line + "\n")

		if selected && res.Fix != "" {
			sb.WriteString("        " + dimStyle.Render("fix: "+safeDisplay(res.Fix)) + "\n")
		}
	}

	// scroll hint
	if len(r.Results) > maxRows {
		fmt.Fprintf(&sb, "\n%s", dimStyle.Render(fmt.Sprintf(
			"  %d–%d of %d  (↑/↓ to scroll)",
			start+1, end, len(r.Results),
		)))
	}

	return sb.String()
}

func badgeForSeverity(s audit.Severity) string {
	icons := map[audit.Severity]string{
		audit.Critical: "✗",
		audit.Warning:  "⚠",
		audit.Info:     "i",
	}
	if style, ok := severityBadge[s]; ok {
		return style.Render(padBadgeLabel(icons[s] + " " + string(s)))
	}
	return okBadgeStyle.Render(padBadgeLabel("✓ OK"))
}
