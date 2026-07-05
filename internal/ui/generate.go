package ui

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gateway-of-last-resort/keyward/internal/keys"
)

// generateModel is the key generation form.
type generateModel struct {
	width, height int
	sshDir        string

	// algorithm toggle: 0 = ed25519, 1 = rsa
	algoIdx int

	inputs  [5]textinput.Model
	focused int
	// field indices within inputs
	// 0: filename, 1: directory, 2: comment, 3: passphrase, 4: confirm passphrase

	allowEmpty bool // explicit AllowEmptyPassphrase toggle
	formErr    error

	submitting bool // key generation in progress (async)
	spinner    spinner.Model
}

// generateResultMsg carries the outcome of an asynchronous key generation.
type generateResultMsg struct {
	key keys.Key
	err error
}

const (
	inFilename = 0
	inDir      = 1
	inComment  = 2
	inPass     = 3
	inPassConf = 4
	inCount    = 5
)

var algorithms = [2]keys.Algorithm{keys.AlgorithmEd25519, keys.AlgorithmRSA}

func newGenerateModel(sshDir string) generateModel {
	mkInput := func(placeholder string, echo bool) textinput.Model {
		ti := textinput.New()
		ti.Placeholder = placeholder
		if echo {
			ti.EchoMode = textinput.EchoPassword
			ti.EchoCharacter = '•'
		}
		return ti
	}

	var ins [inCount]textinput.Model
	ins[inFilename] = mkInput("id_ed25519", false)
	ins[inDir] = mkInput(sshDir, false)
	ins[inDir].SetValue(sshDir)
	ins[inComment] = mkInput("user@host (optional)", false)
	ins[inPass] = mkInput("leave blank + toggle allow empty", true)
	ins[inPassConf] = mkInput("confirm passphrase", true)

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(ColorMint)

	return generateModel{
		sshDir:  sshDir,
		inputs:  ins,
		focused: inFilename,
		spinner: s,
	}
}

var (
	formLabelStyle = lipgloss.NewStyle().Foreground(colLabel).Bold(true).Width(20)
	formErrorStyle = lipgloss.NewStyle().Foreground(colRed).Bold(true)

	toggleOnStyle  = lipgloss.NewStyle().Foreground(colGreen).Bold(true)
	toggleOffStyle = lipgloss.NewStyle().Foreground(colTextDim)

	focusedHighlight = lipgloss.NewStyle().
				Background(ColorSurface).
				Foreground(ColorMint).
				Bold(true).
				Padding(0, 1)
)

// fieldCount is the total number of focusable fields:
// algorithm toggle + inCount text inputs + allowEmpty toggle.
const fieldCount = 1 + inCount + 1

func (m generateModel) update(msg tea.Msg) (generateModel, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		if m.submitting {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case generateResultMsg:
		m.submitting = false
		if msg.err != nil {
			m.formErr = msg.err
			return m, nil
		}
		// Drop the passphrase from the inputs, then hand the new key to the
		// root model.
		m.inputs[inPass].SetValue("")
		m.inputs[inPassConf].SetValue("")
		key := msg.key
		return m, func() tea.Msg { return keyGeneratedMsg{key: key} }

	case tea.KeyMsg:
		if m.submitting {
			return m, nil
		}
		switch msg.String() {
		case "esc":
			return m, navigate(ScreenKeys)
		case "down":
			m = m.moveFocus(1)
		case "up":
			m = m.moveFocus(-1)
		case "left", "right", " ":
			m = m.toggleCurrent(msg.String())
		case "enter":
			if m.focused == fieldCount-1 {
				return m.submit()
			}
			m = m.moveFocus(1)
		}
	}

	// delegate to focused text input
	if m.focused >= 1 && m.focused <= inCount {
		idx := m.focused - 1
		var cmd tea.Cmd
		m.inputs[idx], cmd = m.inputs[idx].Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m generateModel) moveFocus(delta int) generateModel {
	// blur current text input if focused
	if m.focused >= 1 && m.focused <= inCount {
		m.inputs[m.focused-1].Blur()
	}
	m.focused = (m.focused + delta + fieldCount) % fieldCount
	// focus new text input if applicable
	if m.focused >= 1 && m.focused <= inCount {
		m.inputs[m.focused-1].Focus()
	}
	m.formErr = nil
	return m
}

func (m generateModel) toggleCurrent(key string) generateModel {
	switch m.focused {
	case 0: // algorithm toggle
		if key == "left" {
			m.algoIdx = (m.algoIdx - 1 + len(algorithms)) % len(algorithms)
		} else {
			m.algoIdx = (m.algoIdx + 1) % len(algorithms)
		}
	case fieldCount - 1: // allowEmpty toggle
		if key == " " || key == "left" || key == "right" {
			m.allowEmpty = !m.allowEmpty
		}
	}
	return m
}

func (m generateModel) submit() (generateModel, tea.Cmd) {
	filename := strings.TrimSpace(m.inputs[inFilename].Value())
	dir := strings.TrimSpace(m.inputs[inDir].Value())
	comment := strings.TrimSpace(m.inputs[inComment].Value())
	pass := m.inputs[inPass].Value()
	conf := m.inputs[inPassConf].Value()

	if filename == "" {
		m.formErr = fmt.Errorf("filename is required")
		return m, nil
	}
	if dir == "" {
		dir = m.sshDir
	}
	if pass != conf {
		m.formErr = fmt.Errorf("passphrases do not match")
		return m, nil
	}
	if pass == "" && !m.allowEmpty {
		m.formErr = fmt.Errorf("passphrase is empty — enable 'Allow empty passphrase' to proceed")
		return m, nil
	}

	algo := algorithms[m.algoIdx]
	opts := keys.GenerateOptions{
		Algorithm:            algo,
		Filename:             filename,
		Comment:              comment,
		Passphrase:           []byte(pass),
		AllowEmptyPassphrase: m.allowEmpty,
	}
	if algo == keys.AlgorithmRSA {
		// For RSA the comment field doubles as the bit-size input. If it parses
		// as a number, treat it as the bit size — not as the key comment.
		if bits, err := strconv.Atoi(comment); err == nil {
			opts.BitSize = bits
			opts.Comment = ""
		}
	}

	// Run generation off the event loop so the TUI stays responsive (RSA in
	// particular is slow); a spinner shows progress until generateResultMsg.
	m.submitting = true
	m.formErr = nil
	for i := range m.inputs {
		m.inputs[i].Blur()
	}
	genCmd := func() tea.Msg {
		k, err := keys.GenerateKeys(dir, opts)
		return generateResultMsg{key: k, err: err}
	}
	return m, tea.Batch(m.spinner.Tick, genCmd)
}

var inputLabels = [inCount]string{
	"Filename",
	"Directory",
	"Comment",
	"Passphrase",
	"Confirm passphrase",
}

func (m generateModel) view() string {
	var sb strings.Builder

	sb.WriteString(sectionHeaderStyle.Width(m.width).Render("Generate SSH Key") + "\n\n")

	if m.submitting {
		sb.WriteString(m.spinner.View() + "  " + dimStyle.Render("Generating key...") + "\n")
		return sb.String()
	}

	// ── Algorithm toggle ──────────────────────────────
	algoFocused := m.focused == 0
	sb.WriteString(formLabelStyle.Render("Algorithm"))
	sb.WriteString("  ")
	for i, a := range algorithms {
		style := toggleOffStyle
		if i == m.algoIdx {
			style = toggleOnStyle
		}
		if i > 0 {
			sb.WriteString(dimStyle.Render("  /  "))
		}
		if algoFocused && i == m.algoIdx {
			sb.WriteString(focusedHighlight.Render(style.Render(string(a))))
		} else {
			sb.WriteString(style.Render(string(a)))
		}
	}
	if algoFocused {
		sb.WriteString("  " + dimStyle.Render("← →"))
	}
	sb.WriteString("\n")

	// ── Text inputs ───────────────────────────────────
	// Skip the bit size input for ed25519
	for i := 0; i < inCount; i++ {
		// bit size only makes sense for RSA, reuse comment field label for clarity
		lbl := inputLabels[i]
		if i == inComment && algorithms[m.algoIdx] == keys.AlgorithmRSA {
			lbl = "Bit size / comment"
		}
		sb.WriteString(formLabelStyle.Render(lbl))
		sb.WriteString("  ")
		inp := m.inputs[i].View()
		sb.WriteString(inp + "\n")
	}

	// ── Allow empty passphrase toggle ─────────────────
	emptyFocused := m.focused == fieldCount-1
	sb.WriteString(formLabelStyle.Render("Allow empty pass"))
	sb.WriteString("  ")
	if m.allowEmpty {
		s := toggleOnStyle.Render("[ yes ]")
		if emptyFocused {
			s = focusedHighlight.Render(s)
		}
		sb.WriteString(s)
	} else {
		s := toggleOffStyle.Render("[ no  ]")
		if emptyFocused {
			s = focusedHighlight.Render(s)
		}
		sb.WriteString(s)
	}
	sb.WriteString("  " + dimStyle.Render("space to toggle") + "\n")

	// ── Passphrase risk warning ───────────────────────
	if m.allowEmpty {
		sb.WriteString("\n  " + formErrorStyle.Render("⚠  key will be stored unencrypted — suitable for CI/deploy keys only") + "\n")
	}

	// ── Output dir preview ───────────────────────────
	dir := m.inputs[inDir].Value()
	if dir == "" {
		dir = m.sshDir
	}
	filename := m.inputs[inFilename].Value()
	if filename != "" {
		priv := filepath.Join(dir, filename)
		// Each path on its own indented line so a long path doesn't widen the
		// frame, and the two paths line up under each other.
		sb.WriteString("\n  " + dimStyle.Render("will create:") + "\n")
		sb.WriteString("    " + dimStyle.Render(priv) + "\n")
		sb.WriteString("    " + dimStyle.Render(priv+".pub") + "\n")
	}

	// ── Error ─────────────────────────────────────────
	if m.formErr != nil {
		sb.WriteString("\n  " + formErrorStyle.Render("✗  "+m.formErr.Error()) + "\n")
	}

	// ── Submit hint ───────────────────────────────────
	// Two blank lines above so the hint stands clear of the path preview.
	sb.WriteString("\n\n  " + dimStyle.Render("press enter on last field to generate"))

	return sb.String()
}
