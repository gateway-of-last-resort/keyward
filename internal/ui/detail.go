package ui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
	"github.com/gateway-of-last-resort/keyward/internal/keys"
	"github.com/gateway-of-last-resort/keyward/internal/storage"
)

var predefinedTags = []string{"work", "personal", "server", "deploy", "git", "backup"}

// keyDetailModel renders the detail view for a single SSH key.
type keyDetailModel struct {
	width, height int
	key           keys.Key
	findings      []audit.AuditResult
	meta          *storage.KeyMetadata
	copied        bool
	confirmDelete bool

	// rotation form
	confirmRotate bool
	rotInputs     [3]textinput.Model // 0=comment, 1=passphrase, 2=confirm
	rotateFocus   int
	rotFormErr    string

	// metadata edit mode
	editing   bool
	editFocus int // 0 = tags, 1 = note
	tagCursor int
	editTags  []string
	noteInput textarea.Model

	// ssh-agent
	inAgent      bool // key is currently loaded in the agent
	addingAgent  bool // passphrase prompt for "add to agent" is open
	agentPass    textinput.Model
	agentPassErr string
}

func newKeyDetailModel(k keys.Key, results []audit.AuditResult, store *storage.Store, inAgent bool) keyDetailModel {
	var findings []audit.AuditResult
	for _, r := range results {
		if r.KeyPath == k.PrivateKeyPath {
			findings = append(findings, r)
		}
	}
	var meta *storage.KeyMetadata
	if store != nil && k.Fingerprint != "" {
		if m, err := storage.Get(*store, k.Fingerprint); err == nil {
			m2 := m
			meta = &m2
		}
	}
	ta := textarea.New()
	ta.Placeholder = "add a note..."
	ta.ShowLineNumbers = false
	ta.SetHeight(4)
	ta.MaxHeight = 8
	ta.CharLimit = 0
	ta.KeyMap.InsertNewline.SetEnabled(true)
	ta.Blur()
	return keyDetailModel{key: k, findings: findings, meta: meta, noteInput: ta, inAgent: inAgent}
}

var (
	detailLabelStyle = lipgloss.NewStyle().
				Foreground(colLabel).
				Bold(true).
				Width(18)

	detailValueStyle = lipgloss.NewStyle().Foreground(colText)

	copiedStyle  = lipgloss.NewStyle().Foreground(colGreen).Bold(true)
	warnMsgStyle = lipgloss.NewStyle().Foreground(colYellow).Bold(true)

	tagSelectedStyle = lipgloss.NewStyle().Foreground(ColorMint).Bold(true)
	tagCursorStyle   = lipgloss.NewStyle().
				Background(ColorSurface).
				Foreground(ColorFg).
				Bold(true).
				Padding(0, 1)
	tagActiveCursorStyle = lipgloss.NewStyle().
				Background(ColorSurface).
				Foreground(ColorMint).
				Bold(true).
				Padding(0, 1)
	editSectionStyle = lipgloss.NewStyle().
				Foreground(ColorLavender).
				Bold(true)
	editHintStyle = lipgloss.NewStyle().Foreground(colorDim)
)

func (m keyDetailModel) update(msg tea.Msg) (keyDetailModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.editing {
			return m.updateEdit(msg)
		}
		if m.confirmRotate {
			return m.updateRotateForm(msg)
		}
		if m.addingAgent {
			return m.updateAgentPrompt(msg)
		}
		m.copied = false
		switch msg.String() {
		case "e":
			if !m.confirmDelete && m.key.Fingerprint != "" {
				m = m.enterEditMode()
			}
		case "c":
			pubPath := m.key.PublicKeyPath
			if pubPath == "" {
				pubPath = m.key.PrivateKeyPath + ".pub"
			}
			if err := copyPubKey(pubPath); err != nil {
				return m, func() tea.Msg { return errMsg{err} }
			}
			m.copied = true
		case "A":
			if m.confirmDelete || m.key.Fingerprint == "" || m.inAgent {
				break
			}
			if m.key.HasPassphrase {
				return m.enterAgentPrompt(), nil
			}
			return m, addToAgentCmd(m.key, nil)
		case "r":
			m.confirmDelete = false
			m = m.enterRotateForm()
		case "d":
			if !m.confirmDelete {
				m.confirmDelete = true
			} else {
				m.confirmDelete = false
				return m, deleteKeyCmd(m.key)
			}
		case "esc":
			if m.confirmDelete {
				m.confirmDelete = false
			} else {
				return m, navigate(ScreenKeys)
			}
		}
	}
	return m, nil
}

// ── add-to-agent passphrase prompt ──────────────────────────────────────────

func (m keyDetailModel) enterAgentPrompt() keyDetailModel {
	pass := textinput.New()
	pass.Placeholder = "key passphrase"
	pass.EchoMode = textinput.EchoPassword
	pass.EchoCharacter = '•'
	pass.Width = 40
	pass.Focus()
	m.agentPass = pass
	m.agentPassErr = ""
	m.addingAgent = true
	return m
}

func (m keyDetailModel) updateAgentPrompt(msg tea.KeyMsg) (keyDetailModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.addingAgent = false
		m.agentPassErr = ""
		return m, nil
	case "enter":
		pass := m.agentPass.Value()
		if pass == "" {
			m.agentPassErr = "passphrase required"
			return m, nil
		}
		m.addingAgent = false
		return m, addToAgentCmd(m.key, []byte(pass))
	}
	var cmd tea.Cmd
	m.agentPass, cmd = m.agentPass.Update(msg)
	return m, cmd
}

// ── rotation form ─────────────────────────────────────────────────────────────

func (m keyDetailModel) enterRotateForm() keyDetailModel {
	comment := textinput.New()
	comment.Placeholder = "key comment"
	comment.SetValue(m.key.Comment)
	comment.Focus()
	comment.Width = 40

	pass := textinput.New()
	pass.Placeholder = "new passphrase (empty = none)"
	pass.EchoMode = textinput.EchoPassword
	pass.EchoCharacter = '•'
	pass.Width = 40

	conf := textinput.New()
	conf.Placeholder = "confirm passphrase"
	conf.EchoMode = textinput.EchoPassword
	conf.EchoCharacter = '•'
	conf.Width = 40

	m.rotInputs = [3]textinput.Model{comment, pass, conf}
	m.rotateFocus = 0
	m.rotFormErr = ""
	m.confirmRotate = true
	return m
}

func (m keyDetailModel) updateRotateForm(msg tea.KeyMsg) (keyDetailModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.confirmRotate = false
		m.rotFormErr = ""
		return m, nil
	case "enter":
		if m.rotateFocus == 2 {
			return m.submitRotate()
		}
		m.rotInputs[m.rotateFocus].Blur()
		m.rotateFocus++
		m.rotInputs[m.rotateFocus].Focus()
		return m, nil
	case "tab":
		m.rotInputs[m.rotateFocus].Blur()
		m.rotateFocus = (m.rotateFocus + 1) % 3
		m.rotInputs[m.rotateFocus].Focus()
		return m, nil
	case "shift+tab":
		m.rotInputs[m.rotateFocus].Blur()
		m.rotateFocus = (m.rotateFocus + 2) % 3
		m.rotInputs[m.rotateFocus].Focus()
		return m, nil
	}
	var cmd tea.Cmd
	m.rotInputs[m.rotateFocus], cmd = m.rotInputs[m.rotateFocus].Update(msg)
	return m, cmd
}

func (m keyDetailModel) submitRotate() (keyDetailModel, tea.Cmd) {
	pass := m.rotInputs[1].Value()
	conf := m.rotInputs[2].Value()
	if pass != conf {
		m.rotFormErr = "passphrases do not match"
		m.rotInputs[1].SetValue("")
		m.rotInputs[2].SetValue("")
		m.rotInputs[m.rotateFocus].Blur()
		m.rotateFocus = 1
		m.rotInputs[1].Focus()
		return m, nil
	}
	comment := m.rotInputs[0].Value()
	var oldTags []string
	var oldNote string
	if m.meta != nil {
		oldTags = m.meta.Tags
		oldNote = m.meta.Note
	}
	m.confirmRotate = false
	cmd := rotateKeyCmd(m.key, oldTags, oldNote, comment, pass)
	// Clear the passphrase fields immediately so the plaintext isn't retained
	// in the model whether the rotation later succeeds or fails.
	m.rotInputs[1].SetValue("")
	m.rotInputs[2].SetValue("")
	return m, cmd
}

// ── metadata edit mode ────────────────────────────────────────────────────────

func (m keyDetailModel) enterEditMode() keyDetailModel {
	m.editing = true
	m.editFocus = 0
	m.tagCursor = 0
	if m.meta != nil {
		m.editTags = make([]string, len(m.meta.Tags))
		copy(m.editTags, m.meta.Tags)
	} else {
		m.editTags = []string{}
	}
	note := ""
	if m.meta != nil {
		note = m.meta.Note
	}
	w := m.width - 22
	if w < 20 {
		w = 20
	}
	m.noteInput.SetWidth(w)
	m.noteInput.SetValue(note)
	m.noteInput.Blur()
	return m
}

func (m keyDetailModel) updateEdit(msg tea.KeyMsg) (keyDetailModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.editing = false
		m.noteInput.Blur()
		return m, nil
	case "ctrl+s":
		m.editing = false
		m.noteInput.Blur()
		return m, saveMetaCmd(m.key, m.editTags, strings.TrimSpace(m.noteInput.Value()))
	}

	if m.editFocus == 0 {
		switch msg.String() {
		case "left", "h":
			if m.tagCursor > 0 {
				m.tagCursor--
			}
		case "right", "l":
			if m.tagCursor < len(predefinedTags)-1 {
				m.tagCursor++
			}
		case " ":
			tag := predefinedTags[m.tagCursor]
			if slices.Contains(m.editTags, tag) {
				m.editTags = slices.DeleteFunc(m.editTags, func(t string) bool { return t == tag })
			} else {
				m.editTags = append(m.editTags, tag)
			}
		case "down":
			m.editFocus = 1
			return m, m.noteInput.Focus()
		}
		return m, nil
	}

	// editFocus == 1: note textarea
	if msg.String() == "up" && m.noteInput.Line() == 0 {
		m.editFocus = 0
		m.noteInput.Blur()
		return m, nil
	}

	// tab key has empty Runes in bubbletea — insert a tab character explicitly
	if msg.String() == "tab" {
		synth := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'\t'}}
		var cmd tea.Cmd
		m.noteInput, cmd = m.noteInput.Update(synth)
		return m, cmd
	}

	var cmd tea.Cmd
	m.noteInput, cmd = m.noteInput.Update(msg)
	return m, cmd
}

func saveMetaCmd(k keys.Key, tags []string, note string) tea.Cmd {
	return func() tea.Msg {
		return keyMetaUpdatedMsg{key: k, tags: tags, note: note}
	}
}

// ── disk commands ─────────────────────────────────────────────────────────────

func copyPubKey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return clipboard.WriteAll(strings.TrimSpace(string(data)))
}

func rotateKeyCmd(k keys.Key, oldTags []string, oldNote, comment, passphrase string) tea.Cmd {
	return func() tea.Msg {
		opts := keys.GenerateOptions{
			Algorithm:            keys.Algorithm(k.Algorithm),
			Filename:             filepath.Base(k.PrivateKeyPath),
			Overwrite:            true,
			BitSize:              k.BitSize,
			Comment:              comment,
			Passphrase:           []byte(passphrase),
			AllowEmptyPassphrase: passphrase == "",
		}
		newKey, _, err := keys.RotateKey(k, opts)
		if err != nil {
			return errMsg{err}
		}
		return keyRotatedMsg{
			oldPath:        k.PrivateKeyPath,
			oldFingerprint: k.Fingerprint,
			oldTags:        oldTags,
			oldNote:        oldNote,
			newKey:         newKey,
		}
	}
}

func deleteKeyCmd(k keys.Key) tea.Cmd {
	return func() tea.Msg {
		if err := os.Remove(k.PrivateKeyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errMsg{err}
		}
		pubPath := k.PublicKeyPath
		if pubPath == "" {
			pubPath = k.PrivateKeyPath + ".pub"
		}
		_ = os.Remove(pubPath)
		_ = os.Remove(k.PrivateKeyPath + ".bak")
		_ = os.Remove(pubPath + ".bak")
		return keyDeletedMsg{path: k.PrivateKeyPath}
	}
}

// ── view ──────────────────────────────────────────────────────────────────────

func (m keyDetailModel) view() string {
	k := m.key
	var sb strings.Builder

	title := sectionHeaderStyle.Width(m.width - 2).Render(
		"Key: " + fitLeft(k.PrivateKeyPath, m.width-10),
	)
	sb.WriteString(title + "\n\n")

	field := func(lbl, val string) {
		fmt.Fprintf(&sb, "%s  %s\n",
			detailLabelStyle.Render(lbl),
			detailValueStyle.Render(val),
		)
	}

	field("Algorithm", k.Algorithm)
	field("Bit size", fmt.Sprintf("%d", k.BitSize))
	field("Comment", ifEmpty(k.Comment, "—"))
	field("Fingerprint", ifEmpty(k.Fingerprint, "—"))
	field("Modified", k.ModifiedAt.Format("2006-01-02 15:04:05"))
	field("Has passphrase", boolLabel(k.HasPassphrase))
	field("Public only", boolLabel(k.IsPublicOnly))
	if !k.IsPublicOnly {
		agentStatus := dimStyle.Render("not loaded")
		if m.inAgent {
			agentStatus = okStyle.Render("✓ loaded")
		}
		field("In ssh-agent", agentStatus)
	}
	field("Private path", k.PrivateKeyPath)
	if k.PublicKeyPath != "" {
		field("Public path", k.PublicKeyPath)
	}

	if m.confirmRotate {
		sb.WriteString(m.viewRotateForm())
		return sb.String()
	}

	if m.addingAgent {
		sb.WriteString("\n" + sectionHeaderStyle.Width(m.width-2).Render("Add to ssh-agent") + "\n\n")
		fmt.Fprintf(&sb, "%s  %s\n", detailLabelStyle.Render("Passphrase"), m.agentPass.View())
		if m.agentPassErr != "" {
			sb.WriteString("\n" + warnMsgStyle.Render(m.agentPassErr))
		}
		sb.WriteString("\n" + editHintStyle.Render("enter  add · esc  cancel"))
		return sb.String()
	}

	if m.editing {
		sb.WriteString("\n" + sectionHeaderStyle.Width(m.width-2).Render("Edit Metadata") + "\n\n")
		sb.WriteString(m.viewEditTags())
		sb.WriteString("\n\n")
		sb.WriteString(m.viewEditNote())
		sb.WriteString("\n\n")
		sb.WriteString(editHintStyle.Render("↑/↓ switch fields · space toggle tag · tab indent · ctrl+s save · esc cancel"))
		return sb.String()
	}

	if m.meta != nil {
		sb.WriteString("\n" + sectionHeaderStyle.Width(m.width-2).Render("Metadata") + "\n")
		if !m.meta.LastRotatedAt.IsZero() {
			field("Last rotated", m.meta.LastRotatedAt.Format("2006-01-02 15:04:05"))
		}
		if len(m.meta.Tags) > 0 {
			field("Tags", strings.Join(m.meta.Tags, ", "))
		} else {
			field("Tags", dimStyle.Render("none"))
		}
		if m.meta.Note != "" {
			const labelWidth = 18 + 2 // detailLabelStyle.Width + separator
			const rightMargin = 30
			wrapWidth := m.width - labelWidth - rightMargin
			lines := wrapText(m.meta.Note, wrapWidth)
			field("Note", lines[0])
			for _, l := range lines[1:] {
				fmt.Fprintf(&sb, "%s%s\n", strings.Repeat(" ", labelWidth), detailValueStyle.Render(l))
			}
		} else {
			field("Note", dimStyle.Render("none"))
		}
		if len(m.meta.LinkedHosts) > 0 {
			field("Linked hosts", strings.Join(m.meta.LinkedHosts, ", "))
		}
	}

	if len(m.findings) > 0 {
		sb.WriteString("\n" + sectionHeaderStyle.Width(m.width-2).Render("Findings") + "\n")
		for _, f := range m.findings {
			s := severityStyle[f.Severity]
			fmt.Fprintf(&sb, "  %s  %s\n", s.Render(fmt.Sprintf("%-8s", string(f.Severity))), f.Message)
			if f.Fix != "" {
				fmt.Fprintf(&sb, "            %s\n", dimStyle.Render("fix: "+f.Fix))
			}
		}
	}

	switch {
	case m.copied:
		sb.WriteString("\n" + copiedStyle.Render("✓ public key copied to clipboard"))
	case m.confirmDelete:
		sb.WriteString("\n" + warnMsgStyle.Render("delete key files? press d again to confirm · esc to cancel"))
	}

	return sb.String()
}

func (m keyDetailModel) viewRotateForm() string {
	var sb strings.Builder
	sb.WriteString("\n" + sectionHeaderStyle.Width(m.width-2).Render("Rotate Key") + "\n\n")

	inputWidth := m.width - 26
	if inputWidth < 20 {
		inputWidth = 20
	}

	labels := [3]string{"Comment", "Passphrase", "Confirm pass"}
	for i := range m.rotInputs {
		m.rotInputs[i].Width = inputWidth
		focused := m.rotateFocus == i
		var lbl string
		if focused {
			lbl = detailLabelStyle.Foreground(ColorMint).Render("> " + labels[i])
		} else {
			lbl = detailLabelStyle.Render(labels[i])
		}
		fmt.Fprintf(&sb, "%s  %s\n", lbl, m.rotInputs[i].View())
	}

	sb.WriteString("\n")
	if m.rotFormErr != "" {
		sb.WriteString(formErrorStyle.Render("  ✗  "+m.rotFormErr) + "\n\n")
	}
	sb.WriteString(editHintStyle.Render("tab / shift+tab navigate · enter next / confirm · esc cancel"))
	return sb.String()
}

func (m keyDetailModel) viewEditTags() string {
	focusMarker := "  "
	if m.editFocus == 0 {
		focusMarker = "> "
	}
	lbl := editSectionStyle.Render("Tags")

	var tags strings.Builder
	for i, tag := range predefinedTags {
		selected := slices.Contains(m.editTags, tag)
		cursor := i == m.tagCursor && m.editFocus == 0

		text := tag
		if selected {
			text = "[" + tag + "]"
		}
		var rendered string
		switch {
		case cursor && selected:
			rendered = tagActiveCursorStyle.Render(text)
		case cursor:
			rendered = tagCursorStyle.Render(text)
		case selected:
			rendered = tagSelectedStyle.Render(text) + "  "
		default:
			rendered = dimStyle.Render(text) + "  "
		}
		tags.WriteString(rendered)
		if cursor {
			tags.WriteString("  ")
		}
	}

	return focusMarker + lbl + "  " + tags.String()
}

func (m keyDetailModel) viewEditNote() string {
	focusMarker := "  "
	if m.editFocus == 1 {
		focusMarker = "> "
	}
	lbl := editSectionStyle.Render("Note ")
	return focusMarker + lbl + "\n" + m.noteInput.View()
}

// wrapText wraps s to lines of at most width runes.
// It breaks at spaces when possible; long words are split mid-rune.
func wrapText(s string, width int) []string {
	if width <= 0 {
		return []string{s}
	}
	var lines []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}
		line := []rune{}
		for _, word := range words {
			wr := []rune(word)
			// word itself exceeds width — split it
			for len(wr) > 0 {
				space := width - len(line)
				if len(line) > 0 {
					space-- // account for the space before word
				}
				if space <= 0 {
					lines = append(lines, string(line))
					line = []rune{}
					space = width
				}
				if len(line) == 0 {
					if len(wr) <= width {
						line = append(line, wr...)
						wr = nil
					} else {
						lines = append(lines, string(wr[:width]))
						wr = wr[width:]
					}
				} else {
					if len(wr) <= space {
						line = append(line, ' ')
						line = append(line, wr...)
						wr = nil
					} else {
						lines = append(lines, string(line))
						line = []rune{}
					}
				}
			}
		}
		if len(line) > 0 {
			lines = append(lines, string(line))
		}
	}
	return lines
}

func ifEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func boolLabel(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
