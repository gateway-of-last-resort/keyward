package ui

import (
	"fmt"
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
	settingsEditSSHDir              // text input for ssh dir path
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

	// ssh dir field
	sshDirInput textinput.Model

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
	switch m.step {
	case settingsChangePass:
		return "tab / enter  next field  ·  enter on last to save  ·  esc  cancel"
	case settingsEditSSHDir:
		return "enter  save  ·  esc  cancel"
	default:
		return "↑/↓  navigate  ·  enter  select  ·  esc  back  ·  " + nav
	}
}

func newSettingsModel(masterKeyPath, sshDir, vaultDir string) settingsModel {
	old := textinput.New()
	old.Placeholder = "current password"
	old.EchoMode = textinput.EchoPassword
	old.EchoCharacter = '•'

	nw := textinput.New()
	nw.Placeholder = "new password"
	nw.EchoMode = textinput.EchoPassword
	nw.EchoCharacter = '•'

	conf := textinput.New()
	conf.Placeholder = "confirm new password"
	conf.EchoMode = textinput.EchoPassword
	conf.EchoCharacter = '•'

	dir := textinput.New()
	dir.Placeholder = "path to .ssh directory"
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
		case settingsEditSSHDir:
			return m.updateEditSSHDir(msg)
		}
	}
	return m, nil
}

func (m settingsModel) updateMenu(msg tea.KeyMsg) (settingsModel, tea.Cmd) {
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
			m.step = settingsEditSSHDir
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
		m.step = settingsMenu
		return m, nil
	case "enter":
		newDir := strings.TrimSpace(m.sshDirInput.Value())
		if newDir == "" {
			m.formErr = fmt.Errorf("SSH directory must not be empty")
			return m, nil
		}
		m.sshDir = newDir
		m.step = settingsMenu
		return m, func() tea.Msg { return settingsSSHDirChangedMsg{sshDir: newDir} }
	}
	var cmd tea.Cmd
	m.sshDirInput, cmd = m.sshDirInput.Update(msg)
	return m, cmd
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
	sb.WriteString(sectionHeaderStyle.Width(m.width - 2).Render("Settings"))
	sb.WriteString("\n\n")

	switch m.step {
	case settingsMenu:
		sb.WriteString(m.viewMenu())
	case settingsChangePass:
		sb.WriteString(m.viewChangePass())
	case settingsEditSSHDir:
		sb.WriteString(m.viewEditSSHDir())
	}

	if m.statusMsg != "" && m.step == settingsMenu {
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
		sel := i == m.cursor
		prefix := "  "
		labelSt := dimStyle
		if sel {
			prefix = "> "
			labelSt = lipgloss.NewStyle().Foreground(ColorMint).Bold(true)
		}
		sb.WriteString(prefix)
		sb.WriteString(labelSt.Render(label))
		if i == 1 { // SSH directory — show current value inline
			sb.WriteString("  ")
			sb.WriteString(dimStyle.Render(m.sshDir))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("\n\n")
	sb.WriteString(dimStyle.Render("  vault dir  "))
	sb.WriteString(dimStyle.Render(m.vaultDir))
	sb.WriteString("\n\n\n\n\n")

	const version = "v0.1.0"
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
	sb.WriteString(labelStyle.Render("Change master password"))
	sb.WriteString("\n\n")
	sb.WriteString(formLabelStyle.Render("Current password"))
	sb.WriteString("  ")
	sb.WriteString(m.oldInput.View())
	sb.WriteString("\n")
	sb.WriteString(formLabelStyle.Render("New password"))
	sb.WriteString("  ")
	sb.WriteString(m.newInput.View())
	sb.WriteString("\n")
	sb.WriteString(formLabelStyle.Render("Confirm password"))
	sb.WriteString("  ")
	sb.WriteString(m.confInput.View())
	sb.WriteString("\n")
	if m.formErr != nil {
		sb.WriteString("\n  ")
		sb.WriteString(formErrorStyle.Render("✗  " + m.formErr.Error()))
		sb.WriteString("\n")
	}
	return sb.String()
}

func (m settingsModel) viewEditSSHDir() string {
	var sb strings.Builder
	sb.WriteString(labelStyle.Render("SSH directory"))
	sb.WriteString("\n\n")
	sb.WriteString(formLabelStyle.Render("Path"))
	sb.WriteString("  ")
	sb.WriteString(m.sshDirInput.View())
	sb.WriteString("\n")
	if m.formErr != nil {
		sb.WriteString("\n  ")
		sb.WriteString(formErrorStyle.Render("✗  " + m.formErr.Error()))
		sb.WriteString("\n")
	}
	return sb.String()
}
