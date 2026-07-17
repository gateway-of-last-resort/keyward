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
	edit.Prompt = ""
	edit.CharLimit = 512

	// add-host / rename: mint accent bar on the left, no "> " prompt, no bg fill.
	addBlock := textinput.New()
	addBlock.Prompt = ""
	addBlock.Placeholder = "host pattern (e.g. myserv)"
	addBlock.CharLimit = 128

	rename := textinput.New()
	rename.Prompt = ""
	rename.CharLimit = 128

	addKey := textinput.New()
	addKey.Prompt = ""
	addKey.Placeholder = "key (e.g. IdentityFile)"
	addKey.CharLimit = 64

	addVal := textinput.New()
	addVal.Prompt = ""
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

	// paneHeaderDimStyle keeps the underline on the unfocused pane so both
	// headers always carry their rule.
	paneHeaderDimStyle = lipgloss.NewStyle().
				Foreground(colorDim).
				BorderStyle(lipgloss.NormalBorder()).
				BorderBottom(true).
				BorderForeground(colBorder)

	activeBlockStyle = lipgloss.NewStyle().
				Background(ColorSelBg).
				Foreground(ColorMint).
				Bold(true)

	// nameStyle is the bright-white default for host names and parameter values.
	nameStyle = lipgloss.NewStyle().Foreground(colText)

	activeParamStyle = lipgloss.NewStyle().
				Background(ColorSelBg).
				Foreground(colText)

	// editingParamStyle marks the key while its value is being edited in place:
	// mint text, no bg fill (the mint accent bar carries the selection).
	editingParamStyle = lipgloss.NewStyle().Foreground(ColorMint)

	commentedStyle = lipgloss.NewStyle().Foreground(colorComment)
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
				m.addBlockInput.Width = m.blockEditWidth()
				m.addBlockInput.SetValue("")
				m.addBlockInput.Focus()
				m.addingBlock = true
			} else if m.blockCursor < len(m.cfg.Blocks) {
				m.confirmDeleteParam = false
				// Width before use so both inputs scroll inside a fixed window.
				m.addParamInputs[0].Width = m.addParamInputWidth()
				m.addParamInputs[1].Width = m.addParamInputWidth()
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
				// Width before SetValue so scroll offsets use the real window.
				m.renameInput.Width = m.blockEditWidth()
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
					// Width must be set before SetValue so the input computes
					// its horizontal scroll offsets against the real window.
					m.editInput.Width = m.paramEditWidth()
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
	// Keep the window width current (the pane may have been resized mid-edit)
	// so the input scrolls horizontally instead of overflowing the frame.
	m.editInput.Width = m.paramEditWidth()
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
	// Keep the window width current so typing scrolls instead of overflowing.
	m.addBlockInput.Width = m.blockEditWidth()
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
	// Keep the window width current so typing scrolls instead of overflowing.
	m.renameInput.Width = m.blockEditWidth()
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
	// Keep the window width current so typing scrolls instead of overflowing.
	m.addParamInputs[m.addParamFocus].Width = m.addParamInputWidth()
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
		sb.WriteString(sectionHeaderStyle.Width(m.width).Render("SSH Config Editor") + "\n\n")
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
	sb.WriteString(sectionHeaderStyle.Width(m.width).Render(
		"SSH Config  "+dimStyle.Render(m.cfg.Path)+unsaved,
	) + "\n\n")

	leftW, rightW := m.paneWidths()

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

// paneWidths returns the widths of the Hosts and Parameters panes.
func (m configModel) paneWidths() (leftW, rightW int) {
	leftW = (m.width - 3) * 3 / 10
	if leftW < 20 {
		leftW = 20
	}
	return leftW, m.width - leftW - 3
}

// wallBuffer keeps every input/value at least this many columns away from the
// right edge of the pane so nothing ever touches the frame.
const wallBuffer = 4

// paramValueWidth is the visible window for a parameter value — shared by the
// static row truncation and the edit input so the value column never moves
// and never overflows the frame. Layout: 1 (lead) + 20 (key) + 2 (gap) +
// value + wallBuffer = pane width.
func (m configModel) paramValueWidth() int {
	_, rightW := m.paneWidths()
	w := rightW - 23 - wallBuffer
	if w < 10 {
		w = 10
	}
	return w
}

// paramEditWidth is the edit-input window. The accent bar replaces the row's
// leading space rather than eating into the value column, so the edit input
// spans the full value window and the row ends where the static row ends.
func (m configModel) paramEditWidth() int {
	return m.paramValueWidth()
}

// addParamInputWidth sizes the add-param key/value inputs. Layout: 2 (accent
// gutter) + 7 (label) + 1 (gap) + input + wallBuffer = pane width.
func (m configModel) addParamInputWidth() int {
	_, rightW := m.paneWidths()
	w := rightW - 10 - wallBuffer
	if w < 10 {
		w = 10
	}
	return w
}

// blockNameWidth is the visible window for a host pattern in the Hosts pane.
// Layout: 2 (indent) + name + 2 (buffer to the pane divider) = pane width.
func (m configModel) blockNameWidth() int {
	leftW, _ := m.paneWidths()
	w := leftW - 4
	if w < 8 {
		w = 8
	}
	return w
}

// blockEditWidth is the rename/add input window: the "> " prompt takes its
// 2 columns out of the name window, so the row ends where a static row does.
func (m configModel) blockEditWidth() int {
	return m.blockNameWidth() - 2
}

func (m configModel) renderBlocks(width int) string {
	focused := !m.paneRight
	header := paneHeaderStyle.Width(width).Render("Hosts")
	if !focused {
		header = paneHeaderDimStyle.Width(width).Render("Hosts")
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
			// Rename in place: the mint accent bar stays but the bg fill drops,
			// and there is no "> " prompt. The bar takes the same 2 columns.
			m.renameInput.Width = m.blockEditWidth()
			sb.WriteString(rowGutter(true) + m.renameInput.View() + "\n")
		} else {
			name := fitRight(b.Pattern, m.blockNameWidth())
			var row string
			switch {
			case focused && i == m.blockCursor && !m.addingBlock:
				// Selected while the Hosts pane is focused: bar + bright fill.
				// (While adding, no existing row is highlighted — only the new one.)
				row = selAccentStyle.Render("▎") + activeBlockStyle.Width(width-1).Render(" "+name)
			case i == m.blockCursor && !m.addingBlock:
				// Selected while the Params pane is focused: bar + bold name (the
				// anchor stays bright) while the rest of the Hosts list dims.
				row = selAccentStyle.Render("▎") + " " + nameStyle.Bold(true).Render(name)
			case focused:
				// Hosts pane focused: names are bright white.
				row = nameStyle.Render("  " + name)
			default:
				// Params pane focused: the unselected Hosts dim.
				row = dimStyle.Render("  " + name)
			}
			sb.WriteString(row + "\n")
		}
	}
	if len(m.cfg.Blocks) == 0 && !m.addingBlock {
		sb.WriteString(dimStyle.Render(" (no hosts — press a to add)") + "\n")
	}

	if m.addingBlock {
		// The new row shows only the mint accent bar (no bg fill), so it's the
		// single highlighted row while typing the pattern.
		m.addBlockInput.Width = m.blockEditWidth()
		sb.WriteString(rowGutter(true) + m.addBlockInput.View() + "\n")
	}

	return sb.String()
}

func (m configModel) renderParams(width int) string {
	focused := m.paneRight
	header := paneHeaderStyle.Width(width).Render("Parameters")
	if !focused {
		header = paneHeaderDimStyle.Width(width).Render("Parameters")
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

	valueW := m.paramValueWidth()

	for i := start; i < end; i++ {
		t := tokens[i]
		isCursor := i == m.paramCursor
		isEditing := m.editing && isCursor

		var row string
		switch {
		case isEditing:
			// Edit in place: mint bar replaces the leading space, no "> " prompt,
			// no bg fill; the value input spans the full value window.
			m.editInput.Width = m.paramEditWidth()
			row = selAccentStyle.Render("▎") + fmt.Sprintf("%s  %s",
				editingParamStyle.Render(fmt.Sprintf("%-20s", t.Key)),
				m.editInput.View(),
			)
		case t.Type == config.COMMENT && focused && isCursor && !m.addingParam:
			// A comment row holds the cursor like any other — 't' toggles it back
			// into a live param — so it needs the same bar + fill. Without this the
			// cursor disappeared whenever it stepped onto a commented-out line.
			row = selAccentStyle.Render("▎") + activeParamStyle.Width(width-1).Render(fitRight(t.Raw, width-1))
		case t.Type == config.COMMENT:
			row = fmt.Sprintf(" %s", commentedStyle.Render(fitRight(t.Raw, width-1)))
		case focused && isCursor && !m.addingParam:
			// Selected while the Params pane is focused: bar + bright fill. The
			// bar shows only while Params is the active column — when focus is on
			// Hosts this row falls through to the plain bright style below.
			body := fmt.Sprintf("%-20s  %s", t.Key, fitRight(t.Value, valueW))
			row = selAccentStyle.Render("▎") + activeParamStyle.Width(width-1).Render(body)
		default:
			// Every other param row: lavender key + bright value — no bar, no dim.
			row = fmt.Sprintf(" %s  %s",
				paramKeyStyle.Render(fmt.Sprintf("%-20s", t.Key)),
				nameStyle.Render(fitRight(t.Value, valueW)),
			)
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
		inputW := m.addParamInputWidth()
		m.addParamInputs[0].Width = inputW
		m.addParamInputs[1].Width = inputW
		fmt.Fprintf(&sb, "%s%s %s\n",
			rowGutter(m.addParamFocus == 0),
			labelStyle.Render("+ Key  "),
			m.addParamInputs[0].View(),
		)
		fmt.Fprintf(&sb, "%s%s %s\n",
			rowGutter(m.addParamFocus == 1),
			labelStyle.Render("  Value"),
			m.addParamInputs[1].View(),
		)
		if m.addParamErr != "" {
			sb.WriteString(formErrorStyle.Render("  ✗  "+m.addParamErr) + "\n")
		}
	}

	return sb.String()
}
