package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gateway-of-last-resort/keyward/internal/config"
)

// configModel renders the SSH config editor.
// Left pane: block list. Right pane: selected block's tokens.
type configModel struct {
	width, height int
	cfg           *config.Config
	sshDir        string

	blockCursor int  // selected block index in cfg.Blocks
	paramCursor int  // selected token index in visible paramTokens list
	paneRight   bool // focus is on the right pane (token list)

	// inline value editing
	editing   bool
	editInput textinput.Model
	editErr   string

	// adding a new host block (left pane)
	addingBlock   bool
	addBlockInput textinput.Model

	// renaming an existing host block (left pane)
	renamingBlock bool
	renameInput   textinput.Model

	// adding a new param (right pane)
	addingParam    bool
	addParamFocus  int // 0 = key, 1 = value
	addParamInputs [2]textinput.Model
	addParamErr    string

	confirmDeleteBlock bool
	confirmDeleteParam bool

	saved   bool
	saveErr error
	saveMsg string
}

func newConfigModel(cfg *config.Config, sshDir string) configModel {
	edit := textinput.New()
	edit.CharLimit = 512

	addBlock := textinput.New()
	addBlock.Placeholder = "host pattern  (e.g. myserver)"
	addBlock.CharLimit = 128
	addBlock.Prompt = ""

	rename := textinput.New()
	rename.CharLimit = 128
	rename.Prompt = ""

	addKey := textinput.New()
	addKey.Placeholder = "key (e.g. IdentityFile)"
	addKey.CharLimit = 64

	addVal := textinput.New()
	addVal.Placeholder = "value"
	addVal.CharLimit = 256

	return configModel{
		cfg:            cfg,
		sshDir:         sshDir,
		editInput:      edit,
		addBlockInput:  addBlock,
		renameInput:    rename,
		addParamInputs: [2]textinput.Model{addKey, addVal},
	}
}

var (
	paneHeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colText).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(colBorder)

	activeBlockStyle = lipgloss.NewStyle().
				Background(colSelBg).
				Foreground(colSelected).
				Bold(true)

	activeParamStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("236")).
				Foreground(colText)

	editingParamStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("236")).
				Foreground(ColorMint)

	commentedStyle = lipgloss.NewStyle().Foreground(colBorder)
	paramKeyStyle  = lipgloss.NewStyle().Foreground(colLabel)
	unsavedStyle   = lipgloss.NewStyle().Foreground(colYellow).Bold(true)
	savedStyle     = lipgloss.NewStyle().Foreground(colGreen).Bold(true)
)

func validateParamKey(key string) error {
	if key == "" || strings.ContainsAny(key, " \t") {
		return fmt.Errorf("key must be a single word (e.g. IdentityFile)")
	}
	if !config.IsValidSSHKeyword(key) {
		return fmt.Errorf("unknown SSH keyword %q", key)
	}
	return nil
}

// isBusy returns true when a text input inside the config editor has focus.
// The root model uses this to suppress global key bindings (q, tab) during editing.
func (m configModel) isBusy() bool {
	return m.editing || m.addingBlock || m.renamingBlock || m.addingParam
}

// hints returns context-sensitive key hints for the status bar.
func (m configModel) hints() string {
	nav := "tab/shift+tab  switch screens"
	switch {
	case m.addingBlock, m.renamingBlock, m.editing:
		return "enter  confirm  ·  esc  cancel"
	case m.addingParam:
		return "tab  switch fields  ·  enter  confirm  ·  esc  cancel"
	case m.confirmDeleteBlock:
		return "d  confirm delete host  ·  esc  cancel"
	case m.confirmDeleteParam:
		return "d  confirm delete param  ·  esc  cancel"
	case m.paneRight:
		// Omit the "switch screens" hint here: the parameters pane already has
		// a long bar and the extra text pushes the frame wider than the view.
		return "↑/↓  navigate  ·  a  add  ·  e  edit  ·  t  toggle  ·  d  delete  ·  esc  back  ·  s  save"
	default:
		return "↑/↓  navigate  ·  a  add  ·  r  rename  ·  d  delete  ·  enter  open  ·  s  save  ·  " + nav
	}
}

// ── update ────────────────────────────────────────────────────────────────────

func (m configModel) update(msg tea.Msg) (configModel, tea.Cmd) {
	if m.cfg == nil {
		if k, ok := msg.(tea.KeyMsg); ok {
			switch k.String() {
			case "esc":
				return m, navigate(ScreenKeys)
			case "n":
				return m.createConfig()
			}
		}
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.editing {
			return m.updateEdit(msg)
		}
		if m.addingBlock {
			return m.updateAddBlock(msg)
		}
		if m.renamingBlock {
			return m.updateRenameBlock(msg)
		}
		if m.addingParam {
			return m.updateAddParam(msg)
		}
		m.saveMsg = ""
		switch msg.String() {
		case "esc":
			if m.confirmDeleteBlock || m.confirmDeleteParam {
				m.confirmDeleteBlock = false
				m.confirmDeleteParam = false
			} else if m.paneRight {
				m.paneRight = false
			} else {
				return m, navigate(ScreenKeys)
			}
		case "enter":
			if !m.paneRight && len(m.cfg.Blocks) > 0 {
				m.confirmDeleteBlock = false
				m.paneRight = true
				m.paramCursor = 0
			}
		case "up", "k":
			if m.paneRight {
				m.confirmDeleteParam = false
				m = m.moveParam(-1)
			} else {
				m.confirmDeleteBlock = false
				m = m.moveBlock(-1)
			}
		case "down", "j":
			if m.paneRight {
				m.confirmDeleteParam = false
				m = m.moveParam(1)
			} else {
				m.confirmDeleteBlock = false
				m = m.moveBlock(1)
			}
		case "a":
			if !m.paneRight {
				m.confirmDeleteBlock = false
				m.addBlockInput.SetValue("")
				m.addBlockInput.Focus()
				m.addingBlock = true
			} else if m.blockCursor < len(m.cfg.Blocks) {
				m.confirmDeleteParam = false
				m.addParamInputs[0].SetValue("")
				m.addParamInputs[1].SetValue("")
				m.addParamInputs[0].Focus()
				m.addParamInputs[1].Blur()
				m.addParamFocus = 0
				m.addingParam = true
			}
		case "r":
			if !m.paneRight && len(m.cfg.Blocks) > 0 {
				m.confirmDeleteBlock = false
				m.renameInput.SetValue(m.cfg.Blocks[m.blockCursor].Pattern)
				m.renameInput.Focus()
				m.renamingBlock = true
			}
		case "e":
			if m.paneRight && m.blockCursor < len(m.cfg.Blocks) {
				m.confirmDeleteParam = false
				blk := &m.cfg.Blocks[m.blockCursor]
				tok := m.currentToken(blk)
				if tok != nil && tok.Type == config.PARAM {
					m.editInput.SetValue(tok.Value)
					m.editInput.Focus()
					m.editing = true
				}
			}
		case "t":
			if m.paneRight && m.blockCursor < len(m.cfg.Blocks) {
				blk := &m.cfg.Blocks[m.blockCursor]
				if idx := paramTokenIdx(blk, m.paramCursor); idx >= 0 {
					config.ToggleAt(blk, idx)
					m.cfg.Modified = true
				}
			}
		case "d":
			if !m.paneRight {
				if len(m.cfg.Blocks) > 0 {
					if !m.confirmDeleteBlock {
						m.confirmDeleteBlock = true
					} else {
						m.confirmDeleteBlock = false
						pattern := m.cfg.Blocks[m.blockCursor].Pattern
						config.RemoveBlock(m.cfg, pattern)
						if m.blockCursor >= len(m.cfg.Blocks) && m.blockCursor > 0 {
							m.blockCursor--
						}
						m.paramCursor = 0
					}
				}
			} else if m.blockCursor < len(m.cfg.Blocks) {
				if !m.confirmDeleteParam {
					m.confirmDeleteParam = true
				} else {
					m.confirmDeleteParam = false
					blk := &m.cfg.Blocks[m.blockCursor]
					if idx := paramTokenIdx(blk, m.paramCursor); idx >= 0 {
						config.RemoveParamAt(blk, idx)
						m.cfg.Modified = true
						if m.paramCursor >= len(paramTokens(*blk)) && m.paramCursor > 0 {
							m.paramCursor--
						}
					}
				}
			}
		case "s":
			if m.cfg.Modified {
				if err := config.Save(m.cfg); err != nil {
					m.saveErr = err
					m.saveMsg = "✗  save failed: " + err.Error()
				} else {
					m.saveErr = nil
					m.saveMsg = "✓  saved"
					m.saved = true
				}
			}
		}
	}
	return m, nil
}

func (m configModel) updateEdit(msg tea.KeyMsg) (configModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.editing = false
		m.editErr = ""
		m.editInput.Blur()
		return m, nil
	case "enter":
		newVal := strings.TrimSpace(m.editInput.Value())
		blk := &m.cfg.Blocks[m.blockCursor]
		if idx := paramTokenIdx(blk, m.paramCursor); idx >= 0 {
			if err := config.ValidateParamValue(blk.Tokens[idx].Key, newVal); err != nil {
				m.editErr = err.Error()
				return m, nil
			}
			blk.Tokens[idx].Value = newVal
			blk.Tokens[idx].Raw = ""
			m.editErr = ""
		}
		m.cfg.Modified = true
		m.editing = false
		m.editInput.Blur()
		return m, nil
	}
	var cmd tea.Cmd
	m.editInput, cmd = m.editInput.Update(msg)
	return m, cmd
}

func (m configModel) updateAddBlock(msg tea.KeyMsg) (configModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.addingBlock = false
		m.addBlockInput.Blur()
		return m, nil
	case "enter":
		pattern := strings.TrimSpace(m.addBlockInput.Value())
		if pattern == "" {
			return m, nil
		}
		config.AddBlock(m.cfg, pattern)
		m.cfg.Modified = true
		m.blockCursor = len(m.cfg.Blocks) - 1
		m.paramCursor = 0
		m.addingBlock = false
		m.addBlockInput.Blur()
		return m, nil
	}
	var cmd tea.Cmd
	m.addBlockInput, cmd = m.addBlockInput.Update(msg)
	return m, cmd
}

func (m configModel) updateRenameBlock(msg tea.KeyMsg) (configModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.renamingBlock = false
		m.renameInput.Blur()
		return m, nil
	case "enter":
		pattern := strings.TrimSpace(m.renameInput.Value())
		if pattern == "" {
			return m, nil
		}
		blk := &m.cfg.Blocks[m.blockCursor]
		config.RenameHost(blk, pattern)
		m.cfg.Modified = true
		m.renamingBlock = false
		m.renameInput.Blur()
		return m, nil
	}
	var cmd tea.Cmd
	m.renameInput, cmd = m.renameInput.Update(msg)
	return m, cmd
}

func (m configModel) updateAddParam(msg tea.KeyMsg) (configModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.addingParam = false
		m.addParamErr = ""
		m.addParamInputs[0].Blur()
		m.addParamInputs[1].Blur()
		return m, nil
	case "tab":
		m.addParamErr = ""
		m.addParamInputs[m.addParamFocus].Blur()
		m.addParamFocus = (m.addParamFocus + 1) % 2
		m.addParamInputs[m.addParamFocus].Focus()
		return m, nil
	case "enter":
		if m.addParamFocus == 0 {
			key := strings.TrimSpace(m.addParamInputs[0].Value())
			if err := validateParamKey(key); err != nil {
				m.addParamErr = err.Error()
				return m, nil
			}
			m.addParamErr = ""
			m.addParamInputs[0].Blur()
			m.addParamFocus = 1
			m.addParamInputs[1].Focus()
			return m, nil
		}
		key := strings.TrimSpace(m.addParamInputs[0].Value())
		val := strings.TrimSpace(m.addParamInputs[1].Value())
		if err := validateParamKey(key); err != nil {
			m.addParamErr = err.Error()
			return m, nil
		}
		if err := config.ValidateParamValue(key, val); err != nil {
			m.addParamErr = err.Error()
			return m, nil
		}
		blk := &m.cfg.Blocks[m.blockCursor]
		config.AddParam(blk, key, val)
		m.cfg.Modified = true
		m.paramCursor = len(paramTokens(*blk)) - 1
		m.addingParam = false
		m.addParamInputs[0].Blur()
		m.addParamInputs[1].Blur()
		return m, nil
	}
	var cmd tea.Cmd
	m.addParamInputs[m.addParamFocus], cmd = m.addParamInputs[m.addParamFocus].Update(msg)
	return m, cmd
}

func (m configModel) createConfig() (configModel, tea.Cmd) {
	cfgPath := filepath.Join(m.sshDir, "config")
	if err := os.MkdirAll(m.sshDir, 0700); err != nil {
		m.saveMsg = "✗  " + err.Error()
		m.saveErr = err
		return m, nil
	}
	if err := config.WriteAtomic(cfgPath, []byte("")); err != nil {
		m.saveMsg = "✗  " + err.Error()
		m.saveErr = err
		return m, nil
	}
	c, err := config.ParseFile(cfgPath)
	if err != nil {
		m.saveMsg = "✗  " + err.Error()
		m.saveErr = err
		return m, nil
	}
	m.cfg = &c
	m.saveErr = nil
	m.saveMsg = "✓  created " + cfgPath
	return m, nil
}

// ── navigation helpers ────────────────────────────────────────────────────────

func (m configModel) moveBlock(delta int) configModel {
	n := len(m.cfg.Blocks)
	if n == 0 {
		return m
	}
	m.blockCursor = (m.blockCursor + delta + n) % n
	m.paramCursor = 0
	return m
}

func (m configModel) moveParam(delta int) configModel {
	if m.blockCursor >= len(m.cfg.Blocks) {
		return m
	}
	tokens := paramTokens(m.cfg.Blocks[m.blockCursor])
	n := len(tokens)
	if n == 0 {
		return m
	}
	m.paramCursor = (m.paramCursor + delta + n) % n
	return m
}

func (m configModel) currentToken(blk *config.Block) *config.Token {
	tokens := paramTokens(*blk)
	if m.paramCursor < len(tokens) {
		t := tokens[m.paramCursor]
		return &t
	}
	return nil
}

// paramTokenIdx returns the index in blk.Tokens of the cursor-th visible (PARAM or COMMENT) token.
func paramTokenIdx(blk *config.Block, cursor int) int {
	count := 0
	for i, t := range blk.Tokens {
		if t.Type == config.PARAM || t.Type == config.COMMENT {
			if count == cursor {
				return i
			}
			count++
		}
	}
	return -1
}

func paramTokens(b config.Block) []config.Token {
	var out []config.Token
	for _, t := range b.Tokens {
		if t.Type == config.PARAM || t.Type == config.COMMENT {
			out = append(out, t)
		}
	}
	return out
}

// ── view ──────────────────────────────────────────────────────────────────────

func (m configModel) view() string {
	var sb strings.Builder

	if m.cfg == nil {
		cfgPath := filepath.Join(m.sshDir, "config")
		sb.WriteString(sectionHeaderStyle.Width(m.width-2).Render("SSH Config Editor") + "\n\n")
		sb.WriteString(dimStyle.Render("  No SSH config found at "+cfgPath) + "\n\n")
		sb.WriteString(dimStyle.Render("  n  create empty config file"))
		if m.saveMsg != "" {
			sb.WriteString("\n\n" + formErrorStyle.Render("  "+m.saveMsg))
		}
		return sb.String()
	}

	unsaved := ""
	if m.cfg.Modified {
		unsaved = "  " + unsavedStyle.Render("[unsaved]")
	}
	sb.WriteString(sectionHeaderStyle.Width(m.width-2).Render(
		"SSH Config  "+dimStyle.Render(m.cfg.Path)+unsaved,
	) + "\n\n")

	leftW := (m.width - 3) * 3 / 10
	if leftW < 20 {
		leftW = 20
	}
	rightW := m.width - leftW - 3

	leftPane := m.renderBlocks(leftW)
	rightPane := m.renderParams(rightW)

	leftLines := strings.Split(leftPane, "\n")
	rightLines := strings.Split(rightPane, "\n")
	maxLines := len(leftLines)
	if len(rightLines) > maxLines {
		maxLines = len(rightLines)
	}
	sep := dimStyle.Render(" │ ")
	for i := 0; i < maxLines; i++ {
		l := ""
		if i < len(leftLines) {
			l = leftLines[i]
		}
		r := ""
		if i < len(rightLines) {
			r = rightLines[i]
		}
		if vis := lipgloss.Width(l); vis < leftW {
			l += strings.Repeat(" ", leftW-vis)
		}
		sb.WriteString(l + sep + r + "\n")
	}

	switch {
	case m.confirmDeleteBlock:
		sb.WriteString("\n" + warnMsgStyle.Render("  delete host? press d again to confirm · esc to cancel") + "\n")
	case m.confirmDeleteParam:
		sb.WriteString("\n" + warnMsgStyle.Render("  delete param? press d again to confirm · esc to cancel") + "\n")
	case m.saveMsg != "":
		if m.saveErr != nil {
			sb.WriteString("\n" + formErrorStyle.Render("  "+m.saveMsg) + "\n")
		} else {
			sb.WriteString("\n" + savedStyle.Render("  "+m.saveMsg) + "\n")
		}
	}

	return sb.String()
}

func (m configModel) renderBlocks(width int) string {
	focused := !m.paneRight
	header := paneHeaderStyle.Width(width).Render("Hosts")
	if !focused {
		header = dimStyle.Width(width).Render("Hosts")
	}

	var sb strings.Builder
	sb.WriteString(header + "\n")

	avail := m.height - 4
	if avail < 1 {
		avail = 1
	}
	if m.addingBlock {
		avail-- // reserve one line for the input
	}
	start := 0
	if m.blockCursor >= avail {
		start = m.blockCursor - avail + 1
	}
	end := start + avail
	if end > len(m.cfg.Blocks) {
		end = len(m.cfg.Blocks)
	}

	for i := start; i < end; i++ {
		b := m.cfg.Blocks[i]
		if m.renamingBlock && focused && i == m.blockCursor {
			m.renameInput.Width = width - 2
			sb.WriteString(m.renameInput.View() + "\n")
		} else {
			row := "  " + b.Pattern
			switch {
			case focused && i == m.blockCursor:
				row = activeBlockStyle.Width(width).Render(row)
			case i == m.blockCursor:
				row = lipgloss.NewStyle().Foreground(colSelected).Bold(true).Width(width).Render(row)
			default:
				row = dimStyle.Render(row)
			}
			sb.WriteString(row + "\n")
		}
	}
	if len(m.cfg.Blocks) == 0 && !m.addingBlock {
		sb.WriteString(dimStyle.Render(" (no hosts — press a to add)") + "\n")
	}

	if m.addingBlock {
		m.addBlockInput.Width = width - 2
		sb.WriteString(m.addBlockInput.View() + "\n")
	}

	return sb.String()
}

func (m configModel) renderParams(width int) string {
	focused := m.paneRight
	header := paneHeaderStyle.Width(width).Render("Parameters")
	if !focused {
		header = dimStyle.Width(width).Render("Parameters")
	}

	var sb strings.Builder
	sb.WriteString(header + "\n")

	if m.blockCursor >= len(m.cfg.Blocks) {
		sb.WriteString(dimStyle.Render(" select a Host block") + "\n")
		return sb.String()
	}

	blk := m.cfg.Blocks[m.blockCursor]
	tokens := paramTokens(blk)

	avail := m.height - 4
	if avail < 1 {
		avail = 1
	}
	if m.addingParam {
		avail -= 2 // reserve two lines for key+value inputs
	}
	start := 0
	if m.paramCursor >= avail {
		start = m.paramCursor - avail + 1
	}
	end := start + avail
	if end > len(tokens) {
		end = len(tokens)
	}

	valueW := width - 24
	if valueW < 10 {
		valueW = 10
	}

	for i := start; i < end; i++ {
		t := tokens[i]
		isSelected := focused && i == m.paramCursor
		isEditing := m.editing && i == m.paramCursor

		var row string
		switch {
		case isEditing:
			m.editInput.Width = valueW
			row = fmt.Sprintf(" %s  %s",
				editingParamStyle.Render(fmt.Sprintf("%-20s", t.Key)),
				m.editInput.View(),
			)
		case t.Type == config.COMMENT:
			row = fmt.Sprintf(" %s", commentedStyle.Render(t.Raw))
		default:
			row = fmt.Sprintf(" %s  %s",
				paramKeyStyle.Render(fmt.Sprintf("%-20s", t.Key)),
				t.Value,
			)
		}

		if isSelected && !isEditing {
			row = activeParamStyle.Width(width).Render(row)
		}
		sb.WriteString(row + "\n")
		if isEditing && m.editErr != "" {
			sb.WriteString(formErrorStyle.Render("  ✗  "+m.editErr) + "\n")
		}
	}

	if len(tokens) == 0 && !m.addingParam {
		sb.WriteString(dimStyle.Render(" (no params — press a to add)") + "\n")
	}

	if m.addingParam {
		inputW := width - 10
		if inputW < 10 {
			inputW = 10
		}
		m.addParamInputs[0].Width = inputW
		m.addParamInputs[1].Width = inputW
		fmt.Fprintf(&sb, " %s %s\n",
			labelStyle.Render("+ Key  "),
			m.addParamInputs[0].View(),
		)
		fmt.Fprintf(&sb, " %s %s\n",
			labelStyle.Render("  Value"),
			m.addParamInputs[1].View(),
		)
		if m.addParamErr != "" {
			sb.WriteString(formErrorStyle.Render("  ✗  "+m.addParamErr) + "\n")
		}
	}

	return sb.String()
}
