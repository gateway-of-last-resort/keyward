package ui

import (
	"fmt"
	"strings"

	"filippo.io/age"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gateway-of-last-resort/keyward/internal/storage"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

// vaultReadyMsg is emitted after a successful master key init or unlock.
type vaultReadyMsg struct {
	identity age.Identity
	store    storage.Store
}

// vaultErrMsg is emitted by setup/unlock commands on failure so the form
// can show the error inline rather than in the status bar.
type vaultErrMsg struct{ err error }

// ── Setup screen (first run) ──────────────────────────────────────────────────

type setupModel struct {
	width, height int
	vaultDir      string
	masterKeyPath string

	passInput  textinput.Model
	confInput  textinput.Model
	focused    int // 0 = pass, 1 = conf
	formErr    error
	submitting bool
	spinner    spinner.Model
}

func newSetupModel(vaultDir, masterKeyPath string) setupModel {
	pass := textinput.New()
	pass.Placeholder = "choose a strong password"
	pass.EchoMode = textinput.EchoPassword
	pass.EchoCharacter = '•'
	pass.Focus()

	conf := textinput.New()
	conf.Placeholder = "repeat password"
	conf.EchoMode = textinput.EchoPassword
	conf.EchoCharacter = '•'

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(ColorMint)

	return setupModel{
		vaultDir:      vaultDir,
		masterKeyPath: masterKeyPath,
		passInput:     pass,
		confInput:     conf,
		spinner:       s,
	}
}

func (m setupModel) update(msg tea.Msg) (setupModel, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		if m.submitting {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case vaultErrMsg:
		m.formErr = msg.err
		m.submitting = false
		m.passInput.SetValue("")
		m.confInput.SetValue("")
		m.passInput.Focus()
		m.confInput.Blur()
		m.focused = 0
		return m, nil

	case tea.KeyMsg:
		if m.submitting {
			return m, nil
		}
		m.formErr = nil
		switch msg.String() {
		case "tab", "down":
			m.passInput.Blur()
			m.confInput.Focus()
			m.focused = 1
			return m, nil
		case "shift+tab", "up":
			m.confInput.Blur()
			m.passInput.Focus()
			m.focused = 0
			return m, nil
		case "enter":
			if m.focused == 0 {
				m.passInput.Blur()
				m.confInput.Focus()
				m.focused = 1
				return m, nil
			}
			return m.submit()
		}
	}

	var cmd tea.Cmd
	if m.focused == 0 {
		m.passInput, cmd = m.passInput.Update(msg)
	} else {
		m.confInput, cmd = m.confInput.Update(msg)
	}
	return m, cmd
}

func (m setupModel) submit() (setupModel, tea.Cmd) {
	pass := m.passInput.Value()
	conf := m.confInput.Value()

	if pass == "" {
		m.formErr = fmt.Errorf("password must not be empty")
		return m, nil
	}
	if pass != conf {
		m.formErr = fmt.Errorf("passwords do not match")
		m.confInput.SetValue("")
		return m, nil
	}

	m.submitting = true
	m.passInput.Blur()
	m.confInput.Blur()

	vaultDir := m.vaultDir
	masterKeyPath := m.masterKeyPath
	initCmd := func() tea.Msg {
		if err := storage.Init(vaultDir); err != nil {
			return vaultErrMsg{err}
		}
		identity, err := crypto.InitMasterKey(masterKeyPath, pass)
		if err != nil {
			return vaultErrMsg{err}
		}
		store, err := storage.Load(vaultDir, identity)
		if err != nil {
			return vaultErrMsg{err}
		}
		return vaultReadyMsg{identity: identity, store: store}
	}
	return m, tea.Batch(m.spinner.Tick, initCmd)
}

var setupCenterStyle = lipgloss.NewStyle().Align(lipgloss.Center)

func (m setupModel) view() string {
	var sb strings.Builder

	center := setupCenterStyle.Width(m.width)

	sb.WriteString(center.Render(
		lipgloss.NewStyle().Bold(true).Foreground(ColorMint).Padding(1, 0).Render("Welcome to Keyward"),
	))
	sb.WriteString("\n")
	sb.WriteString(center.Render(
		dimStyle.Render("Create a master password to protect your vault."),
	))
	sb.WriteString("\n\n")

	if m.submitting {
		sb.WriteString(center.Render(
			m.spinner.View() + "  " + dimStyle.Render("Creating vault..."),
		))
		return sb.String()
	}

	sb.WriteString(formLabelStyle.Render("Master password"))
	sb.WriteString("  " + m.passInput.View() + "\n")
	sb.WriteString(formLabelStyle.Render("Confirm password"))
	sb.WriteString("  " + m.confInput.View() + "\n")

	if m.formErr != nil {
		sb.WriteString("\n  " + formErrorStyle.Render("✗  "+m.formErr.Error()) + "\n")
	}

	sb.WriteString("\n  " + dimStyle.Render("tab / enter  next field  ·  enter on confirm to create vault"))
	return sb.String()
}

// ── Unlock screen (subsequent runs) ──────────────────────────────────────────

type unlockModel struct {
	width, height int
	vaultDir      string
	masterKeyPath string

	passInput textinput.Model
	formErr   error
	unlocking bool
	spinner   spinner.Model
}

func newUnlockModel(vaultDir, masterKeyPath string) unlockModel {
	pass := textinput.New()
	pass.Placeholder = "master password"
	pass.EchoMode = textinput.EchoPassword
	pass.EchoCharacter = '•'
	pass.Focus()

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(ColorMint)

	return unlockModel{
		vaultDir:      vaultDir,
		masterKeyPath: masterKeyPath,
		passInput:     pass,
		spinner:       s,
	}
}

func (m unlockModel) update(msg tea.Msg) (unlockModel, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		if m.unlocking {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case vaultErrMsg:
		m.formErr = msg.err
		m.unlocking = false
		m.passInput.SetValue("")
		m.passInput.Focus()
		return m, nil

	case tea.KeyMsg:
		if m.unlocking {
			return m, nil
		}
		m.formErr = nil
		if msg.String() == "enter" {
			return m.submit()
		}
	}

	var cmd tea.Cmd
	m.passInput, cmd = m.passInput.Update(msg)
	return m, cmd
}

func (m unlockModel) submit() (unlockModel, tea.Cmd) {
	pass := m.passInput.Value()
	if pass == "" {
		m.formErr = fmt.Errorf("password must not be empty")
		return m, nil
	}

	m.unlocking = true
	m.passInput.Blur()

	vaultDir := m.vaultDir
	masterKeyPath := m.masterKeyPath
	unlockCmd := func() tea.Msg {
		identity, err := crypto.LoadMasterKey(masterKeyPath, pass)
		if err != nil {
			return vaultErrMsg{err}
		}
		store, err := storage.Load(vaultDir, identity)
		if err != nil {
			return vaultErrMsg{err}
		}
		return vaultReadyMsg{identity: identity, store: store}
	}
	return m, tea.Batch(m.spinner.Tick, unlockCmd)
}

func (m unlockModel) view() string {
	var sb strings.Builder

	center := setupCenterStyle.Width(m.width)

	sb.WriteString(center.Render(
		lipgloss.NewStyle().Bold(true).Foreground(ColorMint).Padding(1, 0).Render("⚿  Keyward"),
	))
	sb.WriteString("\n\n")

	if m.unlocking {
		sb.WriteString(center.Render(
			m.spinner.View() + "  " + dimStyle.Render("Unlocking vault..."),
		))
		return sb.String()
	}

	sb.WriteString(formLabelStyle.Render("Master password"))
	sb.WriteString("  " + m.passInput.View() + "\n")

	if m.formErr != nil {
		sb.WriteString("\n  " + formErrorStyle.Render("✗  "+m.formErr.Error()) + "\n")
	}

	sb.WriteString("\n  " + dimStyle.Render("enter  unlock vault"))
	return sb.String()
}
