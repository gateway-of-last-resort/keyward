package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
)

// contentWidth is the standard render width for all screens.
const contentWidth = 120

// ── Colour palette ────────────────────────────────────────────────────────────

var (
	// Base
	ColorBg      = lipgloss.Color("#0F0F13")
	ColorSurface = lipgloss.Color("#1A1A1F")
	ColorBorder  = lipgloss.Color("#2A2A33")
	ColorFg      = lipgloss.Color("#E0E0E8")

	// Accents
	ColorMint     = lipgloss.Color("#00E5A0")
	ColorPurple   = lipgloss.Color("#7C3AED")
	ColorLavender = lipgloss.Color("#C084FC")
	ColorPink     = lipgloss.Color("#FF6B9D")

	// Status
	ColorError   = lipgloss.Color("#FF4D6D")
	ColorWarning = lipgloss.Color("#F59E0B")

	// Derived
	colorDim  = lipgloss.Color("#4A4A5A") // muted secondary text
	colorInfo = ColorLavender             // info severity → lavender
)

// ── Aliases used by screen files ─────────────────────────────────────────────

var (
	colBorder   = ColorBorder
	colText     = ColorFg
	colTextDim  = colorDim
	colLabel    = ColorLavender
	colGreen    = ColorMint
	colYellow   = ColorWarning
	colRed      = ColorError
	colCyan     = colorInfo
	colSelBg    = ColorSurface
	colSelected = ColorFg
)

// ── Shared styles ─────────────────────────────────────────────────────────────

var (
	dimStyle = lipgloss.NewStyle().Foreground(colorDim)

	labelStyle = lipgloss.NewStyle().Foreground(ColorLavender).Bold(true)

	okStyle = lipgloss.NewStyle().Foreground(ColorMint)

	selectedRowStyle = lipgloss.NewStyle().
				Background(ColorSurface).
				Foreground(ColorMint).
				Bold(true)

	sectionHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorLavender).
				PaddingLeft(3).
				BorderStyle(lipgloss.NormalBorder()).
				BorderBottom(true).
				BorderForeground(ColorBorder)

	severityStyle = map[audit.Severity]lipgloss.Style{
		audit.Critical: lipgloss.NewStyle().Foreground(ColorError).Bold(true),
		audit.Warning:  lipgloss.NewStyle().Foreground(ColorWarning),
		audit.Info:     lipgloss.NewStyle().Foreground(ColorLavender),
	}

	severityBadge = map[audit.Severity]lipgloss.Style{
		audit.Critical: lipgloss.NewStyle().
			Background(lipgloss.Color("#3D0A14")).
			Foreground(ColorError).
			Bold(true).
			Padding(0, 1),
		audit.Warning: lipgloss.NewStyle().
			Background(lipgloss.Color("#2D1F00")).
			Foreground(ColorWarning).
			Padding(0, 1),
		audit.Info: lipgloss.NewStyle().
			Background(lipgloss.Color("#1A1030")).
			Foreground(ColorLavender).
			Padding(0, 1),
	}
)

// ── Score bar  (purple → lavender → mint gradient) ────────────────────────────

// ScoreBar renders a progress bar of the given character width using a smooth
// purple→lavender→mint gradient for the filled portion.
func ScoreBar(score, width int) string {
	if width <= 0 {
		return ""
	}
	if score > 100 {
		score = 100
	}
	filled := score * width / 100

	r1, g1, b1 := hexRGB(ColorPurple)
	r2, g2, b2 := hexRGB(ColorLavender)
	r3, g3, b3 := hexRGB(ColorMint)

	var bar strings.Builder
	for i := 0; i < filled; i++ {
		t := 0.0
		if filled > 1 {
			t = float64(i) / float64(filled-1)
		}
		var col lipgloss.Color
		if t <= 0.5 {
			col = lerpColor(r1, g1, b1, r2, g2, b2, t*2)
		} else {
			col = lerpColor(r2, g2, b2, r3, g3, b3, (t-0.5)*2)
		}
		bar.WriteString(lipgloss.NewStyle().Foreground(col).Render("█"))
	}
	bar.WriteString(lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("░", width-filled)))
	return bar.String()
}

// hexRGB parses a "#RRGGBB" lipgloss.Color into r, g, b components.
func hexRGB(c lipgloss.Color) (r, g, b int) {
	fmt.Sscanf(strings.TrimPrefix(string(c), "#"), "%02x%02x%02x", &r, &g, &b)
	return
}

// lerpColor linearly interpolates between two RGB colours at position t ∈ [0,1].
func lerpColor(r1, g1, b1, r2, g2, b2 int, t float64) lipgloss.Color {
	lerp := func(a, b int) int { return a + int(float64(b-a)*t+0.5) }
	return lipgloss.Color(fmt.Sprintf("#%02X%02X%02X", lerp(r1, r2), lerp(g1, g2), lerp(b1, b2)))
}
