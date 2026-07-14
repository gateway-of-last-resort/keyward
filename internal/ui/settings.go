package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

// ── Settings screen ───────────────────────────────────────────────────────────

type settingsStep int

const (
	settingsMenu       settingsStep = iota
	settingsChangePass              // 3-field password form
)

type settingsModel struct {
	width, height int
	masterKeyPath string
	sshDir        string
	vaultDir      string

	step   settingsStep
	cursor int // menu cursor

	// change password fields
	oldInput  textinput.Model
	newInput  textinput.Model
	confInput textinput.Model
	passFocus int // 0 = old, 1 = new, 2 = conf

	// ssh dir field — edited inline in the menu (no separate screen)
	sshDirInput   textinput.Model
	editingSSHDir bool

	statusMsg string
	isError   bool
	formErr   error
}

// settingsPasswordChangedMsg is emitted on successful password change.
type settingsPasswordChangedMsg struct{}

// settingsSSHDirChangedMsg is emitted when the user saves a new SSH dir path.
type settingsSSHDirChangedMsg struct{ sshDir string }

var settingsOKStyle = lipgloss.NewStyle().Foreground(colGreen)

func (m settingsModel) hints() string {
	nav := "tab / shift+tab  switch screens"
	if m.editingSSHDir {
		return "enter  save  ·  esc  cancel"
	}
	switch m.step {
	case settingsChangePass:
		return "tab / enter  next field  ·  enter on last to save  ·  esc  cancel"
	default:
		return "↑/↓  navigate  ·  enter  select  ·  esc  back  ·  " + nav
	}
}

func newSettingsModel(masterKeyPath, sshDir, vaultDir string) settingsModel {
	old := textinput.New()
	old.Placeholder = "current password"
	old.Prompt = "" // focus shown by the row's accent bar
	old.EchoMode = textinput.EchoPassword
	old.EchoCharacter = '•'

	nw := textinput.New()
	nw.Placeholder = "new password"
	nw.Prompt = ""
	nw.EchoMode = textinput.EchoPassword
	nw.EchoCharacter = '•'

	conf := textinput.New()
	conf.Placeholder = "confirm new password"
	conf.Prompt = ""
	conf.EchoMode = textinput.EchoPassword
	conf.EchoCharacter = '•'

	dir := textinput.New()
	dir.Placeholder = "path to .ssh directory"
	dir.Prompt = "" // edited inline; focus shown by the row's accent bar
	dir.CharLimit = 256

	return settingsModel{
		masterKeyPath: masterKeyPath,
		sshDir:        sshDir,
		vaultDir:      vaultDir,
		oldInput:      old,
		newInput:      nw,
		confInput:     conf,
		sshDirInput:   dir,
	}
}

var settingsMenuItems = []string{
	"Change master password",
	"SSH directory",
}

func (m settingsModel) update(msg tea.Msg) (settingsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case vaultErrMsg:
		// password-change failure
		m.formErr = msg.err
		m.oldInput.SetValue("")
		m.oldInput.Focus()
		m.newInput.Blur()
		m.confInput.Blur()
		m.passFocus = 0
		return m, nil

	case settingsPasswordChangedMsg:
		m.step = settingsMenu
		m.statusMsg = "master password changed"
		m.isError = false
		m = m.clearPassInputs()
		return m, nil

	case tea.KeyMsg:
		m.formErr = nil
		switch m.step {
		case settingsMenu:
			return m.updateMenu(msg)
		case settingsChangePass:
			return m.updateChangePass(msg)
		}
	}
	return m, nil
}

func (m settingsModel) updateMenu(msg tea.KeyMsg) (settingsModel, tea.Cmd) {
	// When editing the SSH directory inline, keys drive the text input.
	if m.editingSSHDir {
		return m.updateEditSSHDir(msg)
	}
	switch msg.String() {
	case "esc":
		return m, navigate(ScreenKeys)
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(settingsMenuItems)-1 {
			m.cursor++
		}
	case "enter":
		m.statusMsg = ""
		switch m.cursor {
		case 0:
			m.step = settingsChangePass
			m = m.clearPassInputs()
			m.oldInput.Focus()
			m.passFocus = 0
		case 1:
			// Edit inline in the menu — no separate screen.
			m.editingSSHDir = true
			m.sshDirInput.Width = m.sshDirWidth()
			m.sshDirInput.SetValue(m.sshDir)
			m.sshDirInput.Focus()
			m.sshDirInput.CursorEnd()
		}
	}
	return m, nil
}

func (m settingsModel) updateChangePass(msg tea.KeyMsg) (settingsModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.step = settingsMenu
		m = m.clearPassInputs()
		return m, nil
	case "tab", "down":
		m = m.focusPass((m.passFocus + 1) % 3)
		return m, nil
	case "shift+tab", "up":
		m = m.focusPass((m.passFocus + 2) % 3)
		return m, nil
	case "enter":
		if m.passFocus < 2 {
			m = m.focusPass(m.passFocus + 1)
			return m, nil
		}
		return m.submitChangePass()
	}
	var cmd tea.Cmd
	switch m.passFocus {
	case 0:
		m.oldInput, cmd = m.oldInput.Update(msg)
	case 1:
		m.newInput, cmd = m.newInput.Update(msg)
	case 2:
		m.confInput, cmd = m.confInput.Update(msg)
	}
	return m, cmd
}

func (m settingsModel) updateEditSSHDir(msg tea.KeyMsg) (settingsModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.editingSSHDir = false
		m.sshDirInput.Blur()
		return m, nil
	case "enter":
		newDir := strings.TrimSpace(m.sshDirInput.Value())
		if newDir == "" {
			m.formErr = fmt.Errorf("SSH directory must not be empty")
			return m, nil
		}
		// Validate before committing: an unreadable or non-directory path
		// must not blank the key list or get persisted to prefs.
		info, err := os.Stat(newDir)
		if err != nil {
			m.formErr = fmt.Errorf("cannot use directory: %w", err)
			return m, nil
		}
		if !info.IsDir() {
			m.formErr = fmt.Errorf("not a directory: %s", newDir)
			return m, nil
		}
		m.sshDir = newDir
		m.editingSSHDir = false
		m.sshDirInput.Blur()
		return m, func() tea.Msg { return settingsSSHDirChangedMsg{sshDir: newDir} }
	}
	// Keep the visible window bounded (like the config editor) so a long path
	// scrolls within its fixed window instead of pushing out the frame.
	m.sshDirInput.Width = m.sshDirWidth()
	var cmd tea.Cmd
	m.sshDirInput, cmd = m.sshDirInput.Update(msg)
	return m, cmd
}

// settingsValueCol is the column where inline values (SSH dir, vault dir) begin,
// leaving a clear gutter past the longest menu label so labels and values read
// as two aligned columns instead of running together.
const settingsValueCol = 28

// settingsValuePad returns the spaces that advance from just after a 2-column
// gutter + label to settingsValueCol.
func settingsValuePad(label string) string {
	n := settingsValueCol - 2 - lipgloss.Width(label)
	if n < 2 {
		n = 2
	}
	return strings.Repeat(" ", n)
}

// valueWidth is how many columns a static value (SSH dir / vault dir) may occupy
// from settingsValueCol before it would reach the frame; longer values are
// truncated with fitLeft so a long path never widens the frame.
func (m settingsModel) valueWidth() int {
	w := m.width - settingsValueCol - 2
	if w < 10 {
		w = 10
	}
	return w
}

// sshDirWidth is the visible window for the inline SSH-dir input, anchored at
// settingsValueCol with a buffer so the value never reaches the frame's edge.
func (m settingsModel) sshDirWidth() int {
	w := m.width - settingsValueCol - 4
	if w < 10 {
		w = 10
	}
	return w
}

// isBusy reports whether a text input inside settings has focus, so the root
// model can suppress global key bindings (tab, q) while typing.
func (m settingsModel) isBusy() bool {
	return m.step != settingsMenu || m.editingSSHDir
}

func (m settingsModel) submitChangePass() (settingsModel, tea.Cmd) {
	old := m.oldInput.Value()
	nw := m.newInput.Value()
	conf := m.confInput.Value()

	if old == "" {
		m.formErr = fmt.Errorf("current password must not be empty")
		return m, nil
	}
	if nw == "" {
		m.formErr = fmt.Errorf("new password must not be empty")
		return m, nil
	}
	if nw != conf {
		m.formErr = fmt.Errorf("passwords do not match")
		m.confInput.SetValue("")
		return m, nil
	}

	masterKeyPath := m.masterKeyPath
	return m, func() tea.Msg {
		if err := crypto.ChangeMasterKeyPassword(masterKeyPath, old, nw); err != nil {
			return vaultErrMsg{err}
		}
		return settingsPasswordChangedMsg{}
	}
}

func (m settingsModel) focusPass(idx int) settingsModel {
	m.passFocus = idx
	if idx == 0 {
		m.oldInput.Focus()
	} else {
		m.oldInput.Blur()
	}
	if idx == 1 {
		m.newInput.Focus()
	} else {
		m.newInput.Blur()
	}
	if idx == 2 {
		m.confInput.Focus()
	} else {
		m.confInput.Blur()
	}
	return m
}

func (m settingsModel) clearPassInputs() settingsModel {
	m.oldInput.SetValue("")
	m.newInput.SetValue("")
	m.confInput.SetValue("")
	m.oldInput.Blur()
	m.newInput.Blur()
	m.confInput.Blur()
	return m
}

// ── view ─────────────────────────────────────────────────────────────────────

func (m settingsModel) view() string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Width(m.width).Render("Settings"))
	sb.WriteString("\n\n")

	switch m.step {
	case settingsMenu:
		sb.WriteString(m.viewMenu())
	case settingsChangePass:
		sb.WriteString(m.viewChangePass())
	}

	if m.statusMsg != "" && m.step == settingsMenu && !m.editingSSHDir {
		style := settingsOKStyle
		if m.isError {
			style = formErrorStyle
		}
		sb.WriteString("\n  ")
		sb.WriteString(style.Render(m.statusMsg))
		sb.WriteString("\n")
	}

	return sb.String()
}

func (m settingsModel) viewMenu() string {
	var sb strings.Builder

	for i, label := range settingsMenuItems {
		if i == m.cursor {
			sb.WriteString(selectedRow(label))
		} else {
			sb.WriteString("  " + dimStyle.Render(label))
		}
		if i == 1 { // SSH directory — value (or inline editor) in the value column
			sb.WriteString(settingsValuePad(label))
			if m.editingSSHDir {
				m.sshDirInput.Width = m.sshDirWidth()
				sb.WriteString(m.sshDirInput.View())
			} else {
				sb.WriteString(dimStyle.Render(fitLeft(m.sshDir, m.valueWidth())))
			}
		}
		sb.WriteString("\n")
	}

	if m.editingSSHDir && m.formErr != nil {
		sb.WriteString("\n  " + formErrorStyle.Render("✗  "+m.formErr.Error()) + "\n")
	}

	sb.WriteString("\n\n")
	sb.WriteString(dimStyle.Render("  vault dir" + settingsValuePad("vault dir") + fitLeft(m.vaultDir, m.valueWidth())))
	sb.WriteString("\n\n\n\n\n")

	const version = "v0.7.0"
	const repo = "github.com/gateway-of-last-resort"
	footer := version + "  ·  " + repo
	pad := (m.width - len(footer)) / 2
	if pad < 0 {
		pad = 0
	}
	sb.WriteString(dimStyle.Render(strings.Repeat(" ", pad) + footer))
	sb.WriteString("\n")
	return sb.String()
}

func (m settingsModel) viewChangePass() string {
	var sb strings.Builder
	sb.WriteString("  " + labelStyle.Render("Change master password"))
	sb.WriteString("\n\n")
	rows := []struct {
		label string
		input string
		focus int
	}{
		{"Current password", m.oldInput.View(), 0},
		{"New password", m.newInput.View(), 1},
		{"Confirm password", m.confInput.View(), 2},
	}
	for _, r := range rows {
		sb.WriteString(rowGutter(m.passFocus == r.focus))
		sb.WriteString(formLabelStyle.Render(r.label))
		sb.WriteString("  ")
		sb.WriteString(r.input)
		sb.WriteString("\n")
	}
	if m.formErr != nil {
		sb.WriteString("\n  ")
		sb.WriteString(formErrorStyle.Render("✗  " + m.formErr.Error()))
		sb.WriteString("\n")
	}
	return sb.String()
}
