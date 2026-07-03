package ui

// Headless TUI tests. They drive the Bubble Tea sub-models' update/view methods
// directly with synthesised key messages and assert on the resulting state —
// no terminal is involved. Each test maps to one or more items from
// docs/manual-testing.md; the section numbers are referenced in test names.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gateway-of-last-resort/keyward/internal/config"
	"github.com/gateway-of-last-resort/keyward/internal/keys"
)

// k builds a tea.KeyMsg whose String() matches what the update funcs switch on.
func k(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "space", " ":
		return tea.KeyMsg{Type: tea.KeySpace}
	case "ctrl+s":
		return tea.KeyMsg{Type: tea.KeyCtrlS}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

// writeDummyBackups creates placeholder backup files in dir (newest behaviour
// is irrelevant for bounds testing — only the count and ordering matter).
func writeDummyBackups(dir string, names ...string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0600); err != nil {
			return err
		}
	}
	return nil
}

// runCmd executes a tea.Cmd and returns its message (nil for a nil cmd).
func runCmd(cmd tea.Cmd) tea.Msg {
	if cmd == nil {
		return nil
	}
	return cmd()
}

// sendRoot feeds a key into the root Model and, if the resulting command is a
// single navigateMsg, applies it so the active screen actually switches.
func sendRoot(t *testing.T, m Model, key string) (Model, tea.Cmd) {
	t.Helper()
	next, cmd := m.Update(k(key))
	m = next.(Model)
	if cmd != nil {
		if nav, ok := cmd().(navigateMsg); ok {
			n2, _ := m.Update(nav)
			return n2.(Model), nil
		}
	}
	return m, cmd
}

// ── §3 global navigation ────────────────────────────────────────────────────

func TestNav_TabCyclesForward(t *testing.T) {
	m := Model{active: ScreenKeys}
	want := []Screen{ScreenAudit, ScreenConfig, ScreenGenerate, ScreenBackup, ScreenSettings, ScreenKeys}
	for i, w := range want {
		m, _ = sendRoot(t, m, "tab")
		if m.active != w {
			t.Fatalf("tab #%d: active = %v, want %v", i+1, m.active, w)
		}
	}
}

func TestNav_ShiftTabCyclesBackward(t *testing.T) {
	m := Model{active: ScreenKeys}
	m, _ = sendRoot(t, m, "shift+tab")
	if m.active != ScreenSettings {
		t.Fatalf("shift+tab from Keys: active = %v, want Settings", m.active)
	}
}

func TestNav_QQuitsFromKeys(t *testing.T) {
	m := Model{active: ScreenKeys}
	_, cmd := m.Update(k("q"))
	if _, ok := runCmd(cmd).(tea.QuitMsg); !ok {
		t.Fatalf("q on keys screen should quit; got %T", runCmd(cmd))
	}
}

// §4.8 — q while searching types the letter instead of quitting.
func TestNav_QDoesNotQuitWhileSearching(t *testing.T) {
	m := Model{active: ScreenKeys}
	m.keyList = newKeyListModel(nil, nil)
	m.keyList.searching = true
	next, cmd := m.Update(k("q"))
	m = next.(Model)
	if _, ok := runCmd(cmd).(tea.QuitMsg); ok {
		t.Fatal("q while searching must not quit")
	}
	if m.keyList.query != "q" {
		t.Fatalf("q while searching should be typed; query = %q", m.keyList.query)
	}
}

// ── §4 key list search ──────────────────────────────────────────────────────

func keyFixture() []keys.Key {
	return []keys.Key{
		{PrivateKeyPath: "/home/u/.ssh/id_ed25519", Algorithm: "ssh-ed25519", BitSize: 256},
		{PrivateKeyPath: "/home/u/.ssh/id_rsa", Algorithm: "ssh-rsa", BitSize: 2048},
	}
}

func TestKeys_SearchFilters(t *testing.T) { // §4.4
	m := newKeyListModel(keyFixture(), nil)
	m.searching = true
	m, _ = m.update(k("rsa"))
	vis := m.visible()
	if len(vis) != 1 || !strings.HasSuffix(vis[0].key.PrivateKeyPath, "id_rsa") {
		t.Fatalf("search 'rsa' should leave only id_rsa; got %d items", len(vis))
	}
}

// §4.5 — backspace deletes whole runes (UTF-8), never panics on multibyte input.
func TestKeys_SearchBackspaceByRune(t *testing.T) {
	m := newKeyListModel(keyFixture(), nil)
	m.searching = true
	m, _ = m.update(k("rs😀"))
	if m.query != "rs😀" {
		t.Fatalf("query after typing = %q", m.query)
	}
	m, _ = m.update(k("backspace"))
	if m.query != "rs" {
		t.Fatalf("after one backspace = %q, want %q", m.query, "rs")
	}
	m, _ = m.update(k("backspace"))
	if m.query != "r" {
		t.Fatalf("after two backspaces = %q, want %q", m.query, "r")
	}
}

func TestKeys_SearchEscClearsEnterKeeps(t *testing.T) { // §4.6
	// Enter exits search but keeps the filter.
	m := newKeyListModel(keyFixture(), nil)
	m.searching = true
	m, _ = m.update(k("rsa"))
	m, _ = m.update(k("enter"))
	if m.searching || m.query != "rsa" {
		t.Fatalf("enter should keep filter: searching=%v query=%q", m.searching, m.query)
	}
	// Esc clears the filter entirely.
	m, _ = m.update(k("esc"))
	if m.query != "" {
		t.Fatalf("esc should clear filter; query=%q", m.query)
	}
	if len(m.visible()) != 2 {
		t.Fatalf("after clear, all keys visible; got %d", len(m.visible()))
	}
}

// ── §1/§2 setup & unlock validation ─────────────────────────────────────────

func TestSetup_EmptyPassword(t *testing.T) { // §1.2
	m := newSetupModel(t.TempDir(), "master.key")
	m, _ = m.update(k("enter")) // pass -> conf
	m, _ = m.update(k("enter")) // submit
	if m.formErr == nil || !strings.Contains(m.formErr.Error(), "must not be empty") {
		t.Fatalf("expected empty-password error; got %v", m.formErr)
	}
}

func TestSetup_PasswordsMismatch(t *testing.T) { // §1.3
	m := newSetupModel(t.TempDir(), "master.key")
	m, _ = m.update(k("hunter2")) // type into pass (focused 0)
	m, _ = m.update(k("tab"))     // -> conf
	m, _ = m.update(k("nope"))    // type into conf
	m, _ = m.update(k("enter"))   // submit (focused 1)
	if m.formErr == nil || !strings.Contains(m.formErr.Error(), "do not match") {
		t.Fatalf("expected mismatch error; got %v", m.formErr)
	}
	if m.confInput.Value() != "" {
		t.Fatalf("confirm field should be cleared after mismatch; got %q", m.confInput.Value())
	}
}

func TestSetup_FocusNavigation(t *testing.T) { // §1.4
	m := newSetupModel(t.TempDir(), "master.key")
	if m.focused != 0 {
		t.Fatalf("initial focus = %d, want 0", m.focused)
	}
	m, _ = m.update(k("tab"))
	if m.focused != 1 {
		t.Fatalf("after tab focus = %d, want 1", m.focused)
	}
	m, _ = m.update(k("shift+tab"))
	if m.focused != 0 {
		t.Fatalf("after shift+tab focus = %d, want 0", m.focused)
	}
}

func TestUnlock_EmptyPassword(t *testing.T) { // §2.3
	m := newUnlockModel(t.TempDir(), "master.key")
	m, _ = m.update(k("enter"))
	if m.formErr == nil || !strings.Contains(m.formErr.Error(), "must not be empty") {
		t.Fatalf("expected empty-password error; got %v", m.formErr)
	}
}

// ── §7 generate ─────────────────────────────────────────────────────────────

// genType navigates to a text field by index (1..inCount) and types a value.
func genType(m generateModel, field int, val string) generateModel {
	for m.focused < field {
		m = m.moveFocus(1)
	}
	for m.focused > field {
		m = m.moveFocus(-1)
	}
	m, _ = m.update(k(val))
	return m
}

func TestGenerate_FilenameRequired(t *testing.T) { // §7.5
	m := newGenerateModel(t.TempDir())
	got, _ := m.submit()
	if got.formErr == nil || !strings.Contains(got.formErr.Error(), "filename is required") {
		t.Fatalf("expected filename error; got %v", got.formErr)
	}
}

func TestGenerate_PassphraseMismatch(t *testing.T) { // §7.6
	m := newGenerateModel(t.TempDir())
	m = genType(m, inFilename+1, "id_x")
	m = genType(m, inPass+1, "aaa")
	m = genType(m, inPassConf+1, "bbb")
	got, _ := m.submit()
	if got.formErr == nil || !strings.Contains(got.formErr.Error(), "do not match") {
		t.Fatalf("expected passphrase mismatch; got %v", got.formErr)
	}
}

func TestGenerate_EmptyPassphraseRequiresToggle(t *testing.T) { // §7.7
	m := newGenerateModel(t.TempDir())
	m = genType(m, inFilename+1, "id_x")
	got, _ := m.submit()
	if got.formErr == nil || !strings.Contains(got.formErr.Error(), "Allow empty passphrase") {
		t.Fatalf("expected allow-empty hint; got %v", got.formErr)
	}
}

func TestGenerate_RSALabelChanges(t *testing.T) { // §7.2
	m := newGenerateModel(t.TempDir())
	m = m.toggleCurrent("right") // focused 0 = algo -> rsa
	if !strings.Contains(m.view(), "Bit size / comment") {
		t.Fatal("RSA view should relabel comment field to 'Bit size / comment'")
	}
}

func TestGenerate_Ed25519Creates(t *testing.T) { // §7.8
	dir := t.TempDir()
	m := newGenerateModel(dir)
	m = genType(m, inFilename+1, "id_test1")
	// move to allow-empty toggle (last field) and enable it
	for m.focused != fieldCount-1 {
		m = m.moveFocus(1)
	}
	m = m.toggleCurrent(" ")
	if !m.allowEmpty {
		t.Fatal("allow-empty toggle did not enable")
	}
	got, cmd := m.submit()
	if got.formErr != nil {
		t.Fatalf("generate failed: %v", got.formErr)
	}
	msg, ok := runCmd(cmd).(keyGeneratedMsg)
	if !ok {
		t.Fatalf("expected keyGeneratedMsg; got %T", runCmd(cmd))
	}
	if msg.key.Algorithm != string(keys.AlgorithmEd25519) {
		t.Fatalf("algorithm = %q", msg.key.Algorithm)
	}
	if _, err := keys.Parse(dir); err != nil {
		t.Fatalf("generated key not parseable: %v", err)
	}
}

// §7.9 — for RSA a numeric value in the comment field is the bit size and must
// NOT leak into the key comment.
func TestGenerate_RSABitSizeNotLeakedToComment(t *testing.T) {
	dir := t.TempDir()
	m := newGenerateModel(dir)
	m = m.toggleCurrent("right") // -> rsa
	m = genType(m, inFilename+1, "id_rsa4096")
	m = genType(m, inComment+1, "4096")
	m = genType(m, inPass+1, "secret")
	m = genType(m, inPassConf+1, "secret")
	got, cmd := m.submit()
	if got.formErr != nil {
		t.Fatalf("generate failed: %v", got.formErr)
	}
	msg := runCmd(cmd).(keyGeneratedMsg)
	if msg.key.BitSize != 4096 {
		t.Fatalf("bit size = %d, want 4096", msg.key.BitSize)
	}
	if msg.key.Comment != "" {
		t.Fatalf("comment should be empty (number must not leak); got %q", msg.key.Comment)
	}
}

func TestGenerate_RSABitSizeTooSmall(t *testing.T) { // §7.10
	m := newGenerateModel(t.TempDir())
	m = m.toggleCurrent("right") // -> rsa
	m = genType(m, inFilename+1, "id_small")
	m = genType(m, inComment+1, "1024")
	m = genType(m, inPass+1, "secret")
	m = genType(m, inPassConf+1, "secret")
	got, _ := m.submit()
	if got.formErr == nil || !strings.Contains(got.formErr.Error(), "at least 2048") {
		t.Fatalf("expected bit-size error; got %v", got.formErr)
	}
}

func TestGenerate_DuplicateFilename(t *testing.T) { // §7.11
	dir := t.TempDir()
	if _, err := keys.GenerateKeys(dir, keys.GenerateOptions{
		Algorithm: keys.AlgorithmEd25519, Filename: "id_dup", AllowEmptyPassphrase: true,
	}); err != nil {
		t.Fatalf("setup key: %v", err)
	}
	m := newGenerateModel(dir)
	m = genType(m, inFilename+1, "id_dup")
	for m.focused != fieldCount-1 {
		m = m.moveFocus(1)
	}
	m = m.toggleCurrent(" ") // allow empty
	got, _ := m.submit()
	if got.formErr == nil || !strings.Contains(got.formErr.Error(), "already exists") {
		t.Fatalf("expected already-exists error; got %v", got.formErr)
	}
}

func TestGenerate_AlgoToggle(t *testing.T) { // §7.1
	m := newGenerateModel(t.TempDir())
	if m.algoIdx != 0 {
		t.Fatalf("initial algo = %d", m.algoIdx)
	}
	m = m.toggleCurrent("right")
	if algorithms[m.algoIdx] != keys.AlgorithmRSA {
		t.Fatalf("after right, algo = %v", algorithms[m.algoIdx])
	}
	m = m.toggleCurrent("left")
	if algorithms[m.algoIdx] != keys.AlgorithmEd25519 {
		t.Fatalf("after left, algo = %v", algorithms[m.algoIdx])
	}
}

// ── §8 config editor ────────────────────────────────────────────────────────

func loadConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	body := "Host *\n    StrictHostKeyChecking no\n\nHost myserver\n    HostName 10.0.0.1\n    User admin\n"
	if err := config.WriteAtomic(path, []byte(body)); err != nil {
		t.Fatal(err)
	}
	c, err := config.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return &c, dir
}

func TestConfig_AddHost(t *testing.T) { // §8.4
	cfg, dir := loadConfig(t)
	m := newConfigModel(cfg, dir)
	before := len(cfg.Blocks)
	m, _ = m.update(k("a")) // add host
	m, _ = m.update(k("staging"))
	m, _ = m.update(k("enter"))
	if len(m.cfg.Blocks) != before+1 {
		t.Fatalf("blocks = %d, want %d", len(m.cfg.Blocks), before+1)
	}
	if !m.cfg.Modified {
		t.Fatal("config should be marked modified")
	}
	if m.cfg.Blocks[len(m.cfg.Blocks)-1].Pattern != "staging" {
		t.Fatalf("new block pattern = %q", m.cfg.Blocks[len(m.cfg.Blocks)-1].Pattern)
	}
}

func TestConfig_AddParam(t *testing.T) { // §8.6
	cfg, dir := loadConfig(t)
	m := newConfigModel(cfg, dir)
	m, _ = m.update(k("enter")) // focus right pane (block 0)
	m, _ = m.update(k("a"))     // add param
	m, _ = m.update(k("Port"))
	m, _ = m.update(k("enter")) // key -> value
	m, _ = m.update(k("2222"))
	m, _ = m.update(k("enter")) // confirm
	if m.addingParam {
		t.Fatal("still in add-param mode after confirm")
	}
	if !m.cfg.Modified {
		t.Fatal("config should be modified after add param")
	}
	found := false
	for _, tok := range m.cfg.Blocks[0].Tokens {
		if tok.Type == config.PARAM && tok.Key == "Port" && tok.Value == "2222" {
			found = true
		}
	}
	if !found {
		t.Fatal("Port 2222 not added to block")
	}
}

func TestConfig_AddParamUnknownKeyword(t *testing.T) { // §8.7
	cfg, dir := loadConfig(t)
	m := newConfigModel(cfg, dir)
	m, _ = m.update(k("enter"))
	m, _ = m.update(k("a"))
	m, _ = m.update(k("Foobar"))
	m, _ = m.update(k("enter"))
	if !strings.Contains(m.addParamErr, "unknown SSH keyword") {
		t.Fatalf("expected unknown-keyword error; got %q", m.addParamErr)
	}
}

func TestConfig_PortValidation(t *testing.T) { // §8.8
	for _, tc := range []struct{ val, want string }{
		{"abc", "must be a number"},
		{"99999", "between 1 and 65535"},
	} {
		if err := config.ValidateParamValue("Port", tc.val); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("Port=%q: got %v, want substring %q", tc.val, err, tc.want)
		}
	}
	if err := config.ValidateParamValue("Port", "2222"); err != nil {
		t.Fatalf("Port=2222 should be valid; got %v", err)
	}
}

// §8.9 — ForwardAgent/AddKeysToAgent accept ask/confirm in addition to yes/no.
func TestConfig_ForwardAgentAccepts(t *testing.T) {
	for _, v := range []string{"yes", "no", "ask"} {
		if err := config.ValidateParamValue("ForwardAgent", v); err != nil {
			t.Fatalf("ForwardAgent=%q should be valid; got %v", v, err)
		}
	}
	if err := config.ValidateParamValue("AddKeysToAgent", "confirm"); err != nil {
		t.Fatalf("AddKeysToAgent=confirm should be valid; got %v", err)
	}
	if err := config.ValidateParamValue("ForwardAgent", "maybe"); err == nil {
		t.Fatal("ForwardAgent=maybe should be rejected")
	}
}

func TestConfig_ToggleComment(t *testing.T) { // §8.11
	cfg, dir := loadConfig(t)
	m := newConfigModel(cfg, dir)
	m, _ = m.update(k("enter")) // right pane, block 0 (Host *) has 1 param
	m, _ = m.update(k("t"))     // toggle comment
	if !m.cfg.Modified {
		t.Fatal("toggle should mark config modified")
	}
	blk := m.cfg.Blocks[0]
	if blk.Tokens[paramTokenIdx(&blk, 0)].Type != config.COMMENT {
		t.Fatal("param should be commented out after toggle")
	}
	m, _ = m.update(k("t")) // toggle back
	blk = m.cfg.Blocks[0]
	if blk.Tokens[paramTokenIdx(&blk, 0)].Type != config.PARAM {
		t.Fatal("param should be uncommented after second toggle")
	}
}

func TestConfig_CreateEmptyWhenMissing(t *testing.T) { // §8.16
	dir := t.TempDir()
	m := newConfigModel(nil, dir)
	m, _ = m.update(k("n"))
	if m.cfg == nil {
		t.Fatal("'n' should create an empty config")
	}
	if _, err := config.ParseFile(filepath.Join(dir, "config")); err != nil {
		t.Fatalf("config file not created: %v", err)
	}
}

// ── §9 backup restore bounds ────────────────────────────────────────────────

// §9.5 — out-of-range restore selection reports an error, never crashes.
func TestBackup_RestoreBounds(t *testing.T) {
	vaultDir := t.TempDir()
	backupsDir := filepath.Join(vaultDir, "backups")
	if err := writeDummyBackups(backupsDir, "a.tar.age", "b.tar.age"); err != nil {
		t.Fatal(err)
	}
	m := newBackupModel(t.TempDir(), vaultDir, nil)
	if len(m.backups) != 2 {
		t.Fatalf("expected 2 backups discovered; got %d", len(m.backups))
	}
	m, _ = m.update(k("r")) // enter restore prompt
	if m.promptStep != stepRestore {
		t.Fatalf("expected stepRestore; got %v", m.promptStep)
	}
	for _, bad := range []string{"0", "99"} {
		mm := m
		mm.confirmInput.SetValue(bad)
		mm, _ = mm.update(k("enter"))
		if !mm.isError || !strings.Contains(mm.statusMsg, "between 1 and 2") {
			t.Fatalf("restore %q: isError=%v msg=%q", bad, mm.isError, mm.statusMsg)
		}
	}
}

// ── §10 settings ────────────────────────────────────────────────────────────

func enterChangePass(m settingsModel) settingsModel {
	m, _ = m.updateMenu(k("enter")) // cursor 0 -> change password
	return m
}

func TestSettings_ChangePassMismatch(t *testing.T) { // §10.4
	m := newSettingsModel("master.key", "/ssh", "/vault")
	m = enterChangePass(m)
	m, _ = m.update(k("old"))
	m, _ = m.update(k("enter")) // -> new
	m, _ = m.update(k("aaa"))
	m, _ = m.update(k("enter")) // -> conf
	m, _ = m.update(k("bbb"))
	m, _ = m.update(k("enter")) // submit
	if m.formErr == nil || !strings.Contains(m.formErr.Error(), "do not match") {
		t.Fatalf("expected mismatch; got %v", m.formErr)
	}
}

func TestSettings_ChangePassEmptyFields(t *testing.T) { // §10.5
	m := newSettingsModel("master.key", "/ssh", "/vault")
	m = enterChangePass(m)
	got, _ := m.submitChangePass()
	if got.formErr == nil || !strings.Contains(got.formErr.Error(), "current password") {
		t.Fatalf("expected current-password error; got %v", got.formErr)
	}

	m2 := enterChangePass(newSettingsModel("master.key", "/ssh", "/vault"))
	m2, _ = m2.update(k("old")) // fill old only
	got2, _ := m2.submitChangePass()
	if got2.formErr == nil || !strings.Contains(got2.formErr.Error(), "new password") {
		t.Fatalf("expected new-password error; got %v", got2.formErr)
	}
}

func TestSettings_SSHDirEmpty(t *testing.T) { // §10.10
	m := newSettingsModel("master.key", "/ssh", "/vault")
	m, _ = m.updateMenu(k("down"))  // cursor -> SSH directory
	m, _ = m.updateMenu(k("enter")) // open editor
	m.sshDirInput.SetValue("")
	m, _ = m.update(k("enter"))
	if m.formErr == nil || !strings.Contains(m.formErr.Error(), "must not be empty") {
		t.Fatalf("expected empty-dir error; got %v", m.formErr)
	}
}

func TestSettings_SSHDirChangeEmitsMsg(t *testing.T) { // §10.9
	dir := t.TempDir() // must be a real, existing directory to pass validation
	m := newSettingsModel("master.key", "/ssh", "/vault")
	m, _ = m.updateMenu(k("down"))
	m, _ = m.updateMenu(k("enter"))
	m.sshDirInput.SetValue(dir)
	_, cmd := m.update(k("enter"))
	msg, ok := runCmd(cmd).(settingsSSHDirChangedMsg)
	if !ok || msg.sshDir != dir {
		t.Fatalf("expected SSH-dir-changed msg; got %#v", runCmd(cmd))
	}
}

// A nonexistent path must be rejected in the form and must NOT emit a
// dir-changed message — otherwise the key list would be blanked and a bad
// path persisted to prefs.
func TestSettings_SSHDirNonexistentRejected(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	m := newSettingsModel("master.key", "/ssh", "/vault")
	m, _ = m.updateMenu(k("down"))
	m, _ = m.updateMenu(k("enter"))
	m.sshDirInput.SetValue(missing)
	m2, cmd := m.update(k("enter"))
	if m2.formErr == nil {
		t.Fatal("expected form error for nonexistent SSH dir")
	}
	if msg := runCmd(cmd); msg != nil {
		t.Fatalf("nonexistent dir must not emit a message; got %#v", msg)
	}
}

// A path that exists but is a file (not a directory) must also be rejected.
func TestSettings_SSHDirNotADirectoryRejected(t *testing.T) {
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	m := newSettingsModel("master.key", "/ssh", "/vault")
	m, _ = m.updateMenu(k("down"))
	m, _ = m.updateMenu(k("enter"))
	m.sshDirInput.SetValue(file)
	m2, cmd := m.update(k("enter"))
	if m2.formErr == nil || !strings.Contains(m2.formErr.Error(), "not a directory") {
		t.Fatalf("expected not-a-directory error; got %v", m2.formErr)
	}
	if msg := runCmd(cmd); msg != nil {
		t.Fatalf("file path must not emit a message; got %#v", msg)
	}
}

// When a reload scan fails, the model must keep the existing keys and surface
// the error rather than blanking the list.
func TestModel_KeysReloadedErrorKeepsList(t *testing.T) {
	existing := []keys.Key{{PrivateKeyPath: "/ssh/id_ed25519", Algorithm: "ssh-ed25519"}}
	m := Model{active: ScreenKeys, keys: existing, sshDir: "/ssh"}

	next, _ := m.Update(keysReloadedMsg{sshDir: "/bad", err: os.ErrNotExist})
	m = next.(Model)

	if len(m.keys) != 1 || m.keys[0].PrivateKeyPath != "/ssh/id_ed25519" {
		t.Fatalf("keys were altered on reload error: %#v", m.keys)
	}
	if m.err == nil {
		t.Fatal("expected m.err to be set on reload error")
	}
	if m.sshDir != "/ssh" {
		t.Fatalf("sshDir must not change on reload error; got %q", m.sshDir)
	}
}

// ── §5 key detail metadata edit ─────────────────────────────────────────────

func TestDetail_EditMetadataSaveWithCtrlS(t *testing.T) { // §5.4/5.5
	kd := newKeyDetailModel(keys.Key{
		PrivateKeyPath: "/ssh/id_rsa", Algorithm: "ssh-rsa", Fingerprint: "SHA256:test",
	}, nil, nil)
	kd.width = 100
	kd, _ = kd.update(k("e")) // enter edit mode
	if !kd.editing {
		t.Fatal("'e' should enter edit mode")
	}
	kd, _ = kd.update(k("right")) // tag cursor -> predefinedTags[1]
	kd, _ = kd.update(k(" "))     // toggle that tag on
	kd, _ = kd.update(k("down"))  // move to note field
	if kd.editFocus != 1 {
		t.Fatalf("down should move focus to note; editFocus=%d", kd.editFocus)
	}
	kd, _ = kd.update(k("hello"))
	_, cmd := kd.update(k("ctrl+s"))
	msg, ok := runCmd(cmd).(keyMetaUpdatedMsg)
	if !ok {
		t.Fatalf("ctrl+s should emit keyMetaUpdatedMsg; got %T", runCmd(cmd))
	}
	if len(msg.tags) != 1 || msg.tags[0] != predefinedTags[1] {
		t.Fatalf("tags = %v, want [%s]", msg.tags, predefinedTags[1])
	}
	if msg.note != "hello" {
		t.Fatalf("note = %q, want %q", msg.note, "hello")
	}
}

// Guards the doc/impl divergence noted for checklist §5.5: Enter does NOT save
// metadata (it inserts a newline into the note); only ctrl+s saves.
func TestDetail_EnterDoesNotSaveMetadata(t *testing.T) {
	kd := newKeyDetailModel(keys.Key{
		PrivateKeyPath: "/ssh/id_rsa", Algorithm: "ssh-rsa", Fingerprint: "SHA256:test",
	}, nil, nil)
	kd.width = 100
	kd, _ = kd.update(k("e"))
	kd, _ = kd.update(k("down")) // focus note
	_, cmd := kd.update(k("enter"))
	if _, ok := runCmd(cmd).(keyMetaUpdatedMsg); ok {
		t.Fatal("enter in note field must not save metadata (use ctrl+s)")
	}
}
