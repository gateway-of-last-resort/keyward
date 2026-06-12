// Package ui implements the TUI for Keyward using Bubble Tea.
package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
	"github.com/gateway-of-last-resort/keyward/internal/config"
	"github.com/gateway-of-last-resort/keyward/internal/keys"
	"github.com/gateway-of-last-resort/keyward/internal/storage"
)

// Screen identifies the active TUI screen.
type Screen int

const (
	ScreenSetup    Screen = iota // first-run: create master password
	ScreenUnlock                 // subsequent runs: enter master password
	ScreenKeys                   // list of SSH keys
	ScreenDetail                 // key detail view
	ScreenAudit                  // audit dashboard
	ScreenGenerate               // key generation form
	ScreenConfig                 // SSH config editor
	ScreenBackup                 // backup / restore
	ScreenSettings               // settings (password change, ssh dir, etc.)
)

// Model is the root Bubble Tea model.
// All application state lives here; screens read from it and emit Msgs to mutate it.
type Model struct {
	active Screen
	width  int
	height int

	// paths
	sshDir        string
	vaultDir      string
	masterKeyPath string

	// data
	keys     []keys.Key
	identity age.Identity
	store    *storage.Store
	cfg      *config.Config
	report   audit.AuditReport

	// sub-models
	setupView    setupModel
	unlockView   unlockModel
	keyList      keyListModel
	keyDetail    keyDetailModel
	auditView    auditModel
	genForm      generateModel
	cfgEditor    configModel
	backupView   backupModel
	settingsView settingsModel

	// non-fatal error shown in status bar
	err error
}

// New creates a ready-to-run Model.
// It checks for an existing master key in vaultDir and starts with ScreenSetup
// (first run) or ScreenUnlock (vault already initialised).
func New(k []keys.Key, cfg *config.Config, report audit.AuditReport, sshDir, vaultDir string) Model {
	masterKeyPath := filepath.Join(vaultDir, "master.key")

	var initialScreen Screen
	var setupView setupModel
	var unlockView unlockModel

	if _, err := os.Stat(masterKeyPath); os.IsNotExist(err) {
		initialScreen = ScreenSetup
		setupView = newSetupModel(vaultDir, masterKeyPath)
	} else {
		initialScreen = ScreenUnlock
		unlockView = newUnlockModel(vaultDir, masterKeyPath)
	}

	m := Model{
		active:        initialScreen,
		keys:          k,
		cfg:           cfg,
		report:        report,
		sshDir:        sshDir,
		vaultDir:      vaultDir,
		masterKeyPath: masterKeyPath,
		setupView:     setupView,
		unlockView:    unlockView,
		settingsView:  newSettingsModel(masterKeyPath, sshDir, vaultDir),
	}
	m.keyList = newKeyListModel(k, report.Results)
	return m
}

// --- messages ---

// navigateMsg switches the active screen, carrying optional context.
type navigateMsg struct {
	to       Screen
	keyIndex int // used when navigating to ScreenDetail
}

// errMsg delivers a non-fatal error to the status bar.
type errMsg struct{ err error }

// keysReloadedMsg carries refreshed keys, config, and audit report after an SSH dir change.
type keysReloadedMsg struct {
	keys   []keys.Key
	cfg    *config.Config
	report audit.AuditReport
}

// keyGeneratedMsg is emitted when a new key has been created.
type keyGeneratedMsg struct{ key keys.Key }

// keyRotatedMsg is emitted after a successful key rotation.
type keyRotatedMsg struct {
	oldPath        string
	oldFingerprint string
	oldTags        []string
	oldNote        string
	newKey         keys.Key
}

// keyDeletedMsg is emitted after key files are removed from disk.
type keyDeletedMsg struct{ path string }

// keyMetaUpdatedMsg carries updated tags and note for a key.
type keyMetaUpdatedMsg struct {
	key  keys.Key
	tags []string
	note string
}

func navigate(s Screen) tea.Cmd {
	return func() tea.Msg { return navigateMsg{to: s} }
}

func navigateDetail(idx int) tea.Cmd {
	return func() tea.Msg { return navigateMsg{to: ScreenDetail, keyIndex: idx} }
}

// tabScreens is the ordered list of screens shown in the tab bar.
// ScreenDetail is intentionally excluded — it's a sub-screen of ScreenKeys.
var tabScreens = []Screen{
	ScreenKeys,
	ScreenAudit,
	ScreenConfig,
	ScreenGenerate,
	ScreenBackup,
	ScreenSettings,
}

var tabLabels = map[Screen]string{
	ScreenKeys:     "SSH Keys",
	ScreenAudit:    "Audit",
	ScreenConfig:   "Config",
	ScreenGenerate: "Generate",
	ScreenBackup:   "Backup",
	ScreenSettings: "Settings",
}

// tabIndex returns the position of the active screen in tabScreens.
// Returns 0 for sub-screens (e.g. ScreenDetail).
func (m Model) tabIndex() int {
	for i, s := range tabScreens {
		if s == m.active {
			return i
		}
	}
	return 0
}

func (m Model) nextTab() tea.Cmd {
	idx := (m.tabIndex() + 1) % len(tabScreens)
	return navigate(tabScreens[idx])
}

func (m Model) prevTab() tea.Cmd {
	idx := (m.tabIndex() - 1 + len(tabScreens)) % len(tabScreens)
	return navigate(tabScreens[idx])
}

// --- Bubble Tea interface ---

// Init satisfies tea.Model.
func (m Model) Init() tea.Cmd { return nil }

// Update satisfies tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m = m.propagateSize()
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "q":
			// quit everywhere except when typing in the keys search field
			// or when a config editor input has focus
			cfgBusy := m.active == ScreenConfig && m.cfgEditor.isBusy()
			if !cfgBusy && !(m.active == ScreenKeys && m.keyList.searching) {
				return m, tea.Quit
			}
		}
		// Tab / Shift+Tab cycle tabs globally, but not on auth or detail screens,
		// and not when a config editor input is active (Tab switches key↔value fields there).
		cfgBusy := m.active == ScreenConfig && m.cfgEditor.isBusy()
		if !cfgBusy && m.active != ScreenDetail && m.active != ScreenSetup && m.active != ScreenUnlock {
			switch msg.String() {
			case "tab":
				return m, m.nextTab()
			case "shift+tab":
				return m, m.prevTab()
			}
		}
		m.err = nil

	case vaultReadyMsg:
		s := msg.store
		m.identity = msg.identity
		m.store = &s
		return m, navigate(ScreenKeys)

	case vaultErrMsg:
		return m.updateActive(msg)

	case navigateMsg:
		return m.navigate(msg)

	case errMsg:
		m.err = msg.err
		return m, nil

	case keyGeneratedMsg:
		m.keys = append(m.keys, msg.key)
		m.report = audit.Run(m.keys, m.cfg, m.sshDir)
		m.keyList = newKeyListModel(m.keys, m.report.Results)
		if m.store != nil && msg.key.Fingerprint != "" {
			_ = storage.Put(m.store, storage.KeyMetadata{
				Fingerprint: msg.key.Fingerprint,
				Tags:        []string{},
				LinkedHosts: []string{},
			})
			return m, tea.Batch(m.saveStore(), navigate(ScreenKeys))
		}
		return m, navigate(ScreenKeys)

	case keyRotatedMsg:
		for i, k := range m.keys {
			if k.PrivateKeyPath == msg.oldPath {
				m.keys[i] = msg.newKey
				break
			}
		}
		if m.store != nil {
			if msg.oldFingerprint != "" {
				_ = storage.Delete(m.store, msg.oldFingerprint)
			}
			if msg.newKey.Fingerprint != "" {
				tags := msg.oldTags
				if tags == nil {
					tags = []string{}
				}
				_ = storage.Put(m.store, storage.KeyMetadata{
					Fingerprint:   msg.newKey.Fingerprint,
					Tags:          tags,
					Note:          msg.oldNote,
					LinkedHosts:   []string{},
					LastRotatedAt: time.Now(),
				})
			}
		}
		m.report = audit.Run(m.keys, m.cfg, m.sshDir)
		m.keyList = newKeyListModel(m.keys, m.report.Results)
		var rotCmds []tea.Cmd
		if m.store != nil {
			rotCmds = append(rotCmds, m.saveStore())
		}
		for i, k := range m.keys {
			if k.PrivateKeyPath == msg.newKey.PrivateKeyPath {
				rotCmds = append(rotCmds, navigateDetail(i))
				return m, tea.Batch(rotCmds...)
			}
		}
		rotCmds = append(rotCmds, navigate(ScreenKeys))
		return m, tea.Batch(rotCmds...)

	case keyMetaUpdatedMsg:
		fp := msg.key.Fingerprint
		if m.store != nil && fp != "" {
			if _, err := storage.Get(*m.store, fp); err == nil {
				_ = storage.Update(m.store, fp, func(meta *storage.KeyMetadata) {
					meta.Tags = msg.tags
					meta.Note = msg.note
				})
			} else {
				_ = storage.Put(m.store, storage.KeyMetadata{
					Fingerprint: fp,
					Tags:        msg.tags,
					Note:        msg.note,
					LinkedHosts: []string{},
				})
			}
			// refresh detail with updated metadata
			for _, k := range m.keys {
				if k.PrivateKeyPath == msg.key.PrivateKeyPath {
					m.keyDetail = newKeyDetailModel(k, m.report.Results, m.store)
					break
				}
			}
			m = m.propagateSize()
			return m, m.saveStore()
		}
		return m, nil

	case keyDeletedMsg:
		for i, k := range m.keys {
			if k.PrivateKeyPath == msg.path {
				if m.store != nil && k.Fingerprint != "" {
					_ = storage.Delete(m.store, k.Fingerprint)
				}
				m.keys = append(m.keys[:i], m.keys[i+1:]...)
				break
			}
		}
		m.report = audit.Run(m.keys, m.cfg, m.sshDir)
		m.keyList = newKeyListModel(m.keys, m.report.Results)
		var delCmds []tea.Cmd
		if m.store != nil {
			delCmds = append(delCmds, m.saveStore())
		}
		delCmds = append(delCmds, navigate(ScreenKeys))
		return m, tea.Batch(delCmds...)

	case settingsSSHDirChangedMsg:
		m.sshDir = msg.sshDir
		m.settingsView.sshDir = msg.sshDir
		return m, tea.Batch(m.reloadKeys(), m.savePrefs())

	case keysReloadedMsg:
		m.keys = msg.keys
		m.report = msg.report
		m.cfg = msg.cfg // nil if no config found at new SSH dir
		m.cfgEditor = newConfigModel(m.cfg, m.sshDir)
		m.keyList = newKeyListModel(m.keys, m.report.Results)
		return m, nil

	case backupResultMsg:
		// forward to backupView so it can update its status
		m.backupView, _ = m.backupView.update(msg)
		return m, nil
	}

	return m.updateActive(msg)
}

var frameStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(ColorBorder)

// View satisfies tea.Model.
func (m Model) View() string {
	title := m.titleBar()
	body := m.viewActive()
	status := m.statusBar()

	// border takes 1 line top + 1 line bottom; pin status bar to the bottom
	used := lipgloss.Height(title) + lipgloss.Height(status)
	avail := m.height - used - 2
	bodyLines := lipgloss.Height(body)
	if bodyLines < avail {
		body += strings.Repeat("\n", avail-bodyLines)
	}

	content := title + "\n" + body + status
	return frameStyle.Render(content)
}

// --- navigation ---

func (m Model) navigate(msg navigateMsg) (Model, tea.Cmd) {
	m.active = msg.to
	switch msg.to {
	case ScreenDetail:
		if msg.keyIndex >= 0 && msg.keyIndex < len(m.keys) {
			m.keyDetail = newKeyDetailModel(m.keys[msg.keyIndex], m.report.Results, m.store)
		}
	case ScreenAudit:
		m.auditView = newAuditModel(m.report)
	case ScreenGenerate:
		m.genForm = newGenerateModel(m.sshDir)
	case ScreenConfig:
		m.cfgEditor = newConfigModel(m.cfg, m.sshDir)
	case ScreenBackup:
		m.backupView = newBackupModel(m.sshDir, m.vaultDir, m.identity)
	case ScreenSettings:
		m.settingsView = newSettingsModel(m.masterKeyPath, m.sshDir, m.vaultDir)
	}
	m = m.propagateSize()
	return m, nil
}

// --- delegation ---

func (m Model) updateActive(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch m.active {
	case ScreenSetup:
		m.setupView, cmd = m.setupView.update(msg)
	case ScreenUnlock:
		m.unlockView, cmd = m.unlockView.update(msg)
	case ScreenKeys:
		m.keyList, cmd = m.keyList.update(msg)
	case ScreenDetail:
		m.keyDetail, cmd = m.keyDetail.update(msg)
	case ScreenAudit:
		m.auditView, cmd = m.auditView.update(msg)
	case ScreenGenerate:
		m.genForm, cmd = m.genForm.update(msg)
	case ScreenConfig:
		m.cfgEditor, cmd = m.cfgEditor.update(msg)
		if m.cfgEditor.saved {
			m.cfgEditor.saved = false
		}
	case ScreenBackup:
		m.backupView, cmd = m.backupView.update(msg)
	case ScreenSettings:
		m.settingsView, cmd = m.settingsView.update(msg)
	}
	return m, cmd
}

func (m Model) viewActive() string {
	switch m.active {
	case ScreenSetup:
		return m.setupView.view()
	case ScreenUnlock:
		return m.unlockView.view()
	case ScreenKeys:
		return m.keyList.view()
	case ScreenDetail:
		return m.keyDetail.view()
	case ScreenAudit:
		return m.auditView.view()
	case ScreenGenerate:
		return m.genForm.view()
	case ScreenConfig:
		return m.cfgEditor.view()
	case ScreenBackup:
		return m.backupView.view()
	case ScreenSettings:
		return m.settingsView.view()
	}
	return ""
}

// renderWidth returns the effective outer width — capped at contentWidth.
func (m Model) renderWidth() int {
	if m.width < contentWidth {
		return m.width
	}
	return contentWidth
}

// innerWidth returns the content width available inside the border frame.
func (m Model) innerWidth() int {
	w := m.renderWidth() - 2
	if w < 0 {
		return 0
	}
	return w
}

func (m Model) propagateSize() Model {
	w := m.innerWidth()
	// chrome: border(2) + app line + blank + tab bar + top sep + bottom sep + status hint = 8 lines
	avail := m.height - 8
	if avail < 1 {
		avail = 1
	}
	m.setupView.width, m.setupView.height = w, avail
	m.unlockView.width, m.unlockView.height = w, avail
	m.keyList.width, m.keyList.height = w, avail
	m.keyDetail.width, m.keyDetail.height = w, avail
	m.auditView.width, m.auditView.height = w, avail
	m.genForm.width, m.genForm.height = w, avail
	m.cfgEditor.width, m.cfgEditor.height = w, avail
	m.backupView.width, m.backupView.height = w, avail
	m.settingsView.width, m.settingsView.height = w, avail
	return m
}

// --- title bar + tab bar ---

var (
	titleAppStyle   = lipgloss.NewStyle().Bold(true).Foreground(colText)
	titleRightStyle = lipgloss.NewStyle().Foreground(colTextDim)
	titleSepStyle   = lipgloss.NewStyle().Foreground(colBorder)

	tabActiveStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorMint).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(ColorMint).
			Padding(0, 1)

	tabInactiveStyle = lipgloss.NewStyle().
				Foreground(colorDim).
				Padding(0, 1)
)

func (m Model) titleBar() string {
	w := m.innerWidth()
	sep := titleSepStyle.Render(strings.Repeat("─", w))

	// Auth screens get a minimal single-line header with no tab bar.
	if m.active == ScreenSetup || m.active == ScreenUnlock {
		return titleAppStyle.Render("Keyward") + "\n" + sep
	}

	// ── app name line ───────────────────────────────────────────
	left := titleAppStyle.Render("Keyward")
	extra := ""
	switch m.active {
	case ScreenKeys, ScreenDetail:
		extra = fmt.Sprintf("%d keys", len(m.keys))
	case ScreenAudit:
		extra = fmt.Sprintf("grade %s  ·  %d/100", m.report.Grade, m.report.Points)
	}
	right := titleRightStyle.Render(extra)
	gap := w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	appLine := left + strings.Repeat(" ", gap) + right + "\n"

	// ── tab bar ─────────────────────────────────────────────────
	activeIdx := m.tabIndex()
	tabItems := make([]string, len(tabScreens))
	for i, s := range tabScreens {
		label := tabLabels[s]
		if i == activeIdx {
			tabItems[i] = tabActiveStyle.Render(label)
		} else {
			tabItems[i] = tabInactiveStyle.Render(label)
		}
	}
	tabBar := lipgloss.JoinHorizontal(lipgloss.Top, tabItems...)

	return appLine + "\n" + tabBar + "\n" + sep
}

// --- status bar ---

var (
	statusSepStyle = lipgloss.NewStyle().Foreground(colBorder)
	statusBarStyle = lipgloss.NewStyle().Foreground(colTextDim)
	errorBarStyle  = lipgloss.NewStyle().Foreground(colRed).Bold(true)
)

func (m Model) statusBar() string {
	w := m.innerWidth()
	sep := statusSepStyle.Render(strings.Repeat("─", w))
	if m.err != nil {
		return sep + "\n" + errorBarStyle.Render("✗  "+m.err.Error())
	}
	if m.active == ScreenConfig {
		return sep + "\n" + statusBarStyle.Render(m.cfgEditor.hints())
	}
	return sep + "\n" + statusBarStyle.Render(screenHint(m.active))
}

func screenHint(s Screen) string {
	nav := "tab / shift+tab  switch screens"
	switch s {
	case ScreenSetup:
		return "tab / enter  next field  ·  ctrl+c quit"
	case ScreenUnlock:
		return "enter  unlock  ·  ctrl+c quit"
	case ScreenKeys:
		return "↑/↓ navigate  ·  enter detail  ·  / search  ·  q quit  ·  " + nav
	case ScreenDetail:
		return "c copy pubkey  ·  e edit metadata  ·  r rotate  ·  d delete  ·  esc back  ·  q quit"
	case ScreenAudit:
		return "↑/↓ navigate  ·  " + nav
	case ScreenGenerate:
		return "↑/↓ next field  ·  space toggle  ·  enter confirm  ·  esc cancel  ·  " + nav
	case ScreenConfig:
		return "↑/↓ j/k navigate  ·  enter open  ·  a add  ·  e edit  ·  t toggle  ·  s save  ·  " + nav
	case ScreenBackup:
		return "↑/↓  navigate  ·  b  backup  ·  r  restore  ·  d  delete  ·  esc  back  ·  " + nav
	case ScreenSettings:
		return "↑/↓  navigate  ·  enter  select  ·  esc  back  ·  " + nav
	}
	return nav
}

// saveStore encrypts and writes the metadata store to disk in a background command.
func (m Model) saveStore() tea.Cmd {
	store := m.store
	identity := m.identity
	vaultDir := m.vaultDir
	return func() tea.Msg {
		if store == nil {
			return nil
		}
		if err := storage.Save(store, vaultDir, identity); err != nil {
			return errMsg{err}
		}
		return nil
	}
}

// savePrefs persists current preferences (SSH dir) to disk in a background command.
func (m Model) savePrefs() tea.Cmd {
	vaultDir := m.vaultDir
	sshDir := m.sshDir
	return func() tea.Msg {
		storage.SavePrefs(vaultDir, storage.Prefs{SSHDir: sshDir})
		return nil
	}
}

// reloadKeys re-scans sshDir, reloads SSH config, and re-runs the audit in a background command.
func (m Model) reloadKeys() tea.Cmd {
	sshDir := m.sshDir
	return func() tea.Msg {
		ks, _ := keys.Parse(sshDir)
		var newCfg *config.Config
		if c, err := config.ParseFile(filepath.Join(sshDir, "config")); err == nil {
			newCfg = &c
		}
		report := audit.Run(ks, newCfg, sshDir)
		return keysReloadedMsg{keys: ks, cfg: newCfg, report: report}
	}
}
