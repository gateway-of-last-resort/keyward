package ui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/gateway-of-last-resort/keyward/internal/storage"
)

// backupModel handles backup creation and restore with the identity unlocked at
// startup; the screen is only reachable after the vault is unlocked.
type backupModel struct {
	width, height int
	sshDir        string
	vaultDir      string
	identity      age.Identity

	confirmInput textinput.Model
	promptStep   backupStep
	inputErr     string // validation error for the restore-number input

	backups       []string // list of existing backup files
	cursor        int      // selected backup index
	confirmDelete bool
	restoreTarget string // backup path pending restore confirmation (stepConfirm)
}

type backupStep int

const (
	stepIdle    backupStep = iota // showing menu
	stepConfirm                   // prompting for restore confirmation
	stepRestore                   // prompting which backup to restore (number)
)

func (m backupModel) hints() string {
	nav := "tab / shift+tab  switch screens"
	switch m.promptStep {
	case stepConfirm:
		return "y  confirm restore  ·  n / esc  cancel"
	case stepRestore:
		return "enter  restore  ·  esc  cancel"
	default:
		if m.confirmDelete {
			return "d  confirm delete  ·  esc  cancel"
		}
		return "↑/↓  navigate  ·  b  backup  ·  r  restore  ·  d  delete  ·  esc  back  ·  " + nav
	}
}

func newBackupModel(sshDir, vaultDir string, identity age.Identity) backupModel {
	ci := textinput.New()
	ci.Placeholder = "select backup to restore (number)"

	return backupModel{
		sshDir:       sshDir,
		vaultDir:     vaultDir,
		identity:     identity,
		confirmInput: ci,
		backups:      listBackups(vaultDir),
	}
}

// errVaultLocked is shown if a backup action runs without an unlocked identity.
// The screen is reached only after unlock, so this guards a state the UI
// should never be in rather than prompting for a password.
var errVaultLocked = errors.New("vault is locked; restart keyward and unlock it")

func (m backupModel) update(msg tea.Msg) (backupModel, tea.Cmd) {
	switch msg := msg.(type) {
	case backupResultMsg:
		return m.handleResult(msg), nil
	case tea.KeyMsg:
		m.inputErr = ""
		switch m.promptStep {
		case stepIdle:
			return m.updateIdle(msg)
		case stepConfirm:
			return m.updateConfirm(msg)
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
			m.confirmDelete = false
			m.cursor = (m.cursor - 1 + len(m.backups)) % len(m.backups)
		}
	case "down", "j":
		if len(m.backups) > 0 {
			m.confirmDelete = false
			m.cursor = (m.cursor + 1) % len(m.backups)
		}
	case "b":
		if m.identity == nil {
			return m, showStatus(statusError, errVaultLocked.Error())
		}
		return m, m.runBackupDirect("")
	case "r":
		if len(m.backups) == 0 {
			return m, showStatus(statusNotice, "no backups found in "+filepath.Join(m.vaultDir, "backups"))
		}
		m.promptStep = stepRestore
		m.confirmInput.SetValue("")
		m.confirmInput.Focus()
	case "d":
		if len(m.backups) > 0 {
			if !m.confirmDelete {
				m.confirmDelete = true
			} else {
				m.confirmDelete = false
				if err := os.Remove(m.backups[m.cursor]); err != nil {
					return m, showStatus(statusError, "delete failed: "+err.Error())
				}
				m.backups = listBackups(m.vaultDir)
				if m.cursor >= len(m.backups) && m.cursor > 0 {
					m.cursor--
				}
				return m, showStatus(statusSuccess, "backup deleted")
			}
		}
	case "esc":
		if m.confirmDelete {
			m.confirmDelete = false
		} else {
			return m, navigate(ScreenKeys)
		}
	}
	return m, nil
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
			m.inputErr = fmt.Sprintf("enter a number between 1 and %d", len(m.backups))
			return m, nil
		}
		// Restore overwrites files in ~/.ssh irreversibly, so require an
		// explicit confirmation before touching anything.
		m.restoreTarget = m.backups[idx-1]
		m.promptStep = stepConfirm
		return m, nil
	}
	var cmd tea.Cmd
	m.confirmInput, cmd = m.confirmInput.Update(msg)
	return m, cmd
}

// updateConfirm handles the restore confirmation prompt. Only an explicit "y"
// proceeds; anything else cancels back to the menu without touching ~/.ssh.
func (m backupModel) updateConfirm(msg tea.KeyMsg) (backupModel, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		m.promptStep = stepIdle
		if m.identity == nil {
			return m, showStatus(statusError, errVaultLocked.Error())
		}
		return m, m.runBackupDirect(m.restoreTarget)
	default:
		m.promptStep = stepIdle
		return m, nil
	}
}

// runBackupDirect creates or restores a backup using the already-loaded identity.
// Pass restoreFile="" to create a new backup; pass a path to restore from it.
func (m backupModel) runBackupDirect(restoreFile string) tea.Cmd {
	identity := m.identity
	sshDir := m.sshDir
	vaultDir := m.vaultDir
	return func() tea.Msg {
		if restoreFile == "" {
			res, err := storage.CreateBackup(sshDir, vaultDir, identity)
			if err != nil {
				return backupResultMsg{err: fmt.Errorf("backup failed: %w", err)}
			}
			return backupResultMsg{msg: backupSavedMsg(res)}
		}
		if err := storage.RestoreBackup(restoreFile, sshDir, vaultDir, identity); err != nil {
			return backupResultMsg{err: fmt.Errorf("restore failed: %w", err)}
		}
		return backupResultMsg{msg: "restored from " + filepath.Base(restoreFile), restored: true}
	}
}

// backupSavedMsg builds the success line, appending honest notes when some files
// were left out of the archive or old backups couldn't be pruned.
func backupSavedMsg(res storage.BackupResult) string {
	msg := "backup saved: " + filepath.Base(res.Path)
	if len(res.Skipped) > 0 {
		msg += fmt.Sprintf(" (skipped %d unreadable: %s)", len(res.Skipped), strings.Join(res.Skipped, ", "))
	}
	if res.PruneErr != nil {
		msg += " (warning: old backups not pruned)"
	}
	return msg
}

type backupResultMsg struct {
	msg      string
	err      error
	restored bool
}

// Wire backupResultMsg into the model's Update.
// This is handled inside backupModel.update via an extra type switch.
// handleResult returns the screen to its menu after a backup or restore; the
// root model shows the outcome in the message area.
func (m backupModel) handleResult(r backupResultMsg) backupModel {
	m.promptStep = stepIdle
	if r.err == nil {
		m.backups = listBackups(m.vaultDir)
	}
	return m
}

func (m backupModel) view() string {
	var sb strings.Builder

	sb.WriteString(sectionHeaderStyle.Width(m.width).Render("Backup / Restore") + "\n\n")

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

	if m.promptStep == stepRestore {
		sb.WriteString(labelStyle.Render("Restore #") + "  " + m.confirmInput.View() + "\n")
		if m.inputErr != "" {
			sb.WriteString("\n  " + formErrorStyle.Render("✗  "+m.inputErr) + "\n")
		}
	}

	return sb.String()
}

// confirmPrompt is the pending delete or restore question, shown in the message
// area; the keys that answer it are in the hints right below.
func (m backupModel) confirmPrompt() string {
	switch {
	case m.promptStep == stepConfirm:
		return fmt.Sprintf("restore from %s? This overwrites files in %s and cannot be undone.",
			filepath.Base(m.restoreTarget), m.sshDir)
	case m.promptStep == stepIdle && m.confirmDelete:
		return "delete backup " + filepath.Base(m.backups[m.cursor]) + "?"
	}
	return ""
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
