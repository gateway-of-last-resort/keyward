package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gateway-of-last-resort/keyward/internal/storage"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
)

// backupModel handles backup creation and restore.
// When identity is non-nil (user already authenticated), no password re-entry is needed.
type backupModel struct {
	width, height int
	sshDir        string
	vaultDir      string
	identity      age.Identity

	// password prompt state (only used when identity is nil)
	passwordInput textinput.Model
	confirmInput  textinput.Model
	promptStep    backupStep

	// result
	statusMsg string
	isError   bool

	backups []string // list of existing backup files
	cursor  int      // selected backup index
}

type backupStep int

const (
	stepIdle    backupStep = iota // showing menu
	stepPasswd                    // prompting for password
	stepConfirm                   // prompting for restore confirmation
	stepRestore                   // prompting which backup to restore (cursor)
)

var backupMsgStyle = lipgloss.NewStyle().Foreground(colGreen)

func newBackupModel(sshDir, vaultDir string, identity age.Identity) backupModel {
	pi := textinput.New()
	pi.Placeholder = "vault password"
	pi.EchoMode = textinput.EchoPassword
	pi.EchoCharacter = '•'
	pi.Focus()

	ci := textinput.New()
	ci.Placeholder = "select backup to restore (number)"

	return backupModel{
		sshDir:        sshDir,
		vaultDir:      vaultDir,
		identity:      identity,
		passwordInput: pi,
		confirmInput:  ci,
		backups:       listBackups(vaultDir),
	}
}

func (m backupModel) update(msg tea.Msg) (backupModel, tea.Cmd) {
	switch msg := msg.(type) {
	case backupResultMsg:
		return m.handleResult(msg), nil
	case tea.KeyMsg:
		m.statusMsg = ""
		switch m.promptStep {
		case stepIdle:
			return m.updateIdle(msg)
		case stepPasswd:
			return m.updatePasswd(msg)
		case stepRestore:
			return m.updateRestore(msg)
		}
	}
	return m, nil
}

func (m backupModel) updateIdle(msg tea.KeyMsg) (backupModel, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if len(m.backups) > 0 {
			m.cursor = (m.cursor - 1 + len(m.backups)) % len(m.backups)
		}
	case "down", "j":
		if len(m.backups) > 0 {
			m.cursor = (m.cursor + 1) % len(m.backups)
		}
	case "b":
		if m.identity != nil {
			return m, m.runBackupDirect("")
		}
		m.promptStep = stepPasswd
		m.passwordInput.SetValue("")
		m.passwordInput.Placeholder = "vault password (for backup)"
		m.passwordInput.Focus()
	case "r":
		if len(m.backups) == 0 {
			m.statusMsg = "no backups found in " + filepath.Join(m.vaultDir, "backups")
			m.isError = true
			return m, nil
		}
		m.promptStep = stepRestore
		m.confirmInput.SetValue("")
		m.confirmInput.Focus()
	case "d":
		if len(m.backups) > 0 {
			if err := os.Remove(m.backups[m.cursor]); err != nil {
				m.statusMsg = "delete failed: " + err.Error()
				m.isError = true
			} else {
				m.backups = listBackups(m.vaultDir)
				if m.cursor >= len(m.backups) && m.cursor > 0 {
					m.cursor--
				}
				m.statusMsg = "backup deleted"
				m.isError = false
			}
		}
	case "esc", "q":
		return m, navigate(ScreenKeys)
	}
	return m, nil
}

func (m backupModel) updatePasswd(msg tea.KeyMsg) (backupModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.promptStep = stepIdle
		return m, nil
	case "enter":
		pass := m.passwordInput.Value()
		if pass == "" {
			m.statusMsg = "password cannot be empty"
			m.isError = true
			return m, nil
		}
		return m, m.runBackup(pass)
	}
	var cmd tea.Cmd
	m.passwordInput, cmd = m.passwordInput.Update(msg)
	return m, cmd
}

func (m backupModel) updateRestore(msg tea.KeyMsg) (backupModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.promptStep = stepIdle
		return m, nil
	case "enter":
		choice := strings.TrimSpace(m.confirmInput.Value())
		if choice == "" {
			m.promptStep = stepIdle
			return m, nil
		}
		var idx int
		if _, err := fmt.Sscanf(choice, "%d", &idx); err != nil || idx < 1 || idx > len(m.backups) {
			m.statusMsg = fmt.Sprintf("enter a number between 1 and %d", len(m.backups))
			m.isError = true
			return m, nil
		}
		backupFile := m.backups[idx-1]
		if m.identity != nil {
			return m, m.runBackupDirect(backupFile)
		}
		m.passwordInput.SetValue("")
		m.passwordInput.Placeholder = "vault password (for restore)"
		m.passwordInput.Focus()
		m.confirmInput.SetValue(choice) // remember selection for runBackup
		m.promptStep = stepPasswd
		return m, nil
	}
	var cmd tea.Cmd
	m.confirmInput, cmd = m.confirmInput.Update(msg)
	return m, cmd
}

// runBackupDirect creates or restores a backup using the already-loaded identity.
// Pass restoreFile="" to create a new backup; pass a path to restore from it.
func (m backupModel) runBackupDirect(restoreFile string) tea.Cmd {
	identity := m.identity
	sshDir := m.sshDir
	vaultDir := m.vaultDir
	return func() tea.Msg {
		if restoreFile == "" {
			path, err := storage.CreateBackup(sshDir, vaultDir, identity)
			if err != nil {
				return backupResultMsg{err: fmt.Errorf("backup failed: %w", err)}
			}
			return backupResultMsg{msg: "backup saved: " + filepath.Base(path)}
		}
		if err := storage.RestoreBackup(restoreFile, sshDir, vaultDir, identity); err != nil {
			return backupResultMsg{err: fmt.Errorf("restore failed: %w", err)}
		}
		return backupResultMsg{msg: "restored from " + filepath.Base(restoreFile)}
	}
}

// runBackup attempts to create or restore a backup with the given password.
func (m backupModel) runBackup(password string) tea.Cmd {
	return func() tea.Msg {
		masterPath := filepath.Join(m.vaultDir, "master.key")

		// initialise vault if master.key doesn't exist yet
		if _, err := os.Stat(masterPath); os.IsNotExist(err) {
			if _, err := crypto.InitMasterKey(masterPath, password); err != nil {
				return backupResultMsg{err: fmt.Errorf("init vault: %w", err)}
			}
		}

		identity, err := crypto.LoadMasterKey(masterPath, password)
		if err != nil {
			return backupResultMsg{err: fmt.Errorf("wrong password or corrupted vault: %w", err)}
		}

		// if a restore was queued, do that; otherwise create backup
		if m.promptStep == stepPasswd && m.confirmInput.Value() != "" {
			var idx int
			fmt.Sscanf(m.confirmInput.Value(), "%d", &idx)
			backupFile := m.backups[idx-1]
			if err := storage.RestoreBackup(backupFile, m.sshDir, m.vaultDir, identity); err != nil {
				return backupResultMsg{err: fmt.Errorf("restore failed: %w", err)}
			}
			return backupResultMsg{msg: "restored from " + filepath.Base(backupFile)}
		}

		path, err := storage.CreateBackup(m.sshDir, m.vaultDir, identity)
		if err != nil {
			return backupResultMsg{err: fmt.Errorf("backup failed: %w", err)}
		}
		return backupResultMsg{msg: "backup saved: " + filepath.Base(path)}
	}
}

type backupResultMsg struct {
	msg string
	err error
}

// Wire backupResultMsg into the model's Update.
// This is handled inside backupModel.update via an extra type switch.
func (m backupModel) handleResult(r backupResultMsg) backupModel {
	m.promptStep = stepIdle
	if r.err != nil {
		m.statusMsg = r.err.Error()
		m.isError = true
	} else {
		m.statusMsg = r.msg
		m.isError = false
		m.backups = listBackups(m.vaultDir)
	}
	return m
}

func (m backupModel) view() string {
	var sb strings.Builder

	sb.WriteString(sectionHeaderStyle.Width(m.width-2).Render("Backup / Restore") + "\n\n")

	// existing backups list
	if len(m.backups) > 0 {
		sb.WriteString(labelStyle.Render("Backups") + "\n")
		for i, b := range m.backups {
			line := fmt.Sprintf("  %d.  %s", i+1, filepath.Base(b))
			if m.promptStep == stepIdle && i == m.cursor {
				sb.WriteString(activeBlockStyle.Render(line) + "\n")
			} else {
				sb.WriteString(line + "\n")
			}
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString(dimStyle.Render("  no backups found") + "\n\n")
	}

	switch m.promptStep {
	case stepIdle:
		sb.WriteString(dimStyle.Render("  b  create backup  ·  r  restore  ·  d  delete selected"))
		sb.WriteString("\n")
	case stepPasswd:
		sb.WriteString(labelStyle.Render("Password") + "  " + m.passwordInput.View() + "\n")
		sb.WriteString(dimStyle.Render("  enter to confirm · esc cancel") + "\n")
	case stepRestore:
		sb.WriteString(labelStyle.Render("Restore #") + "  " + m.confirmInput.View() + "\n")
		sb.WriteString(dimStyle.Render("  enter number · esc cancel") + "\n")
	}

	if m.statusMsg != "" {
		style := backupMsgStyle
		if m.isError {
			style = formErrorStyle
		}
		sb.WriteString("\n  " + style.Render(m.statusMsg) + "\n")
	}

	return sb.String()
}

// listBackups returns .tar.age files in vaultDir/backups, newest first.
func listBackups(vaultDir string) []string {
	dir := filepath.Join(vaultDir, "backups")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".tar.age") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}
