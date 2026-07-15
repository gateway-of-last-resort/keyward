package ui

// Headless TUI tests. They drive the Bubble Tea sub-models' update/view methods
// directly with synthesised key messages and assert on the resulting state —
// no terminal is involved. Each test maps to one or more items from
// docs/manual-testing.md; the section numbers are referenced in test names.

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/crypto/ssh"

	"github.com/gateway-of-last-resort/keyward/internal/audit"
	"github.com/gateway-of-last-resort/keyward/internal/config"
	"github.com/gateway-of-last-resort/keyward/internal/keys"
	"github.com/gateway-of-last-resort/keyward/internal/knownhosts"
	"github.com/gateway-of-last-resort/keyward/internal/storage"
	"github.com/gateway-of-last-resort/keyward/pkg/crypto"
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
	want := []Screen{ScreenAudit, ScreenConfig, ScreenGenerate, ScreenKnownHosts, ScreenBackup, ScreenSettings, ScreenKeys}
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

// fullModel builds a realistically-constructed root Model via New (the same
// constructor cmd/keyward uses), sized and landed on the Keys screen, so a test
// can drive the whole program instead of an isolated sub-model.
func fullModel(t *testing.T) Model {
	t.Helper()
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	vaultDir := filepath.Join(dir, ".keyward")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfgBytes := []byte("Host x\n    HostName example.com\n    User git\n")
	if err := os.WriteFile(filepath.Join(sshDir, "config"), cfgBytes, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.ParseBytes("config", cfgBytes)
	report := audit.Run(keyFixture(), &cfg, sshDir)

	m := New(keyFixture(), &cfg, report, sshDir, vaultDir)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	m = next.(Model)
	m.active = ScreenKeys // simulate an unlocked vault landing on the key list
	return m
}

// TestFullProgram_RendersEveryScreen tabs through the whole program end to end and
// asserts each screen both becomes active in the expected order and renders a
// non-empty view without panicking — the full-program complement to the isolated
// sub-model tests. Colour is not asserted (lipgloss strips it under `go test`).
func TestFullProgram_RendersEveryScreen(t *testing.T) {
	m := fullModel(t)

	for i, want := range tabScreens {
		if i > 0 {
			m, _ = sendRoot(t, m, "tab")
		}
		if m.active != want {
			t.Fatalf("after %d tabs: active = %v, want %v", i, m.active, want)
		}
		if strings.TrimSpace(m.View()) == "" {
			t.Errorf("screen %v rendered an empty view", want)
		}
	}
}

// TestFullProgram_DrillIntoDetailAndBack drives the Keys -> Detail -> Keys action
// path through the root model, verifying the sub-screen navigation and that the
// detail view renders.
func TestFullProgram_DrillIntoDetailAndBack(t *testing.T) {
	m := fullModel(t)

	m, _ = sendRoot(t, m, "enter")
	if m.active != ScreenDetail {
		t.Fatalf("enter on a key should open Detail, active = %v", m.active)
	}
	if strings.TrimSpace(m.View()) == "" {
		t.Error("detail screen rendered an empty view")
	}

	m, _ = sendRoot(t, m, "esc")
	if m.active != ScreenKeys {
		t.Fatalf("esc from Detail should return to Keys, active = %v", m.active)
	}
}

// TestRestore_ReloadsStore guards against silent metadata loss: after a restore
// overwrites metadata.age, the in-memory store must be reloaded from it, otherwise
// the restored entries are invisible and the next Save clobbers the restored file.
func TestRestore_ReloadsStore(t *testing.T) {
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, ".keyward")
	if err := storage.Init(vaultDir); err != nil {
		t.Fatal(err)
	}
	id, err := crypto.InitMasterKey(filepath.Join(vaultDir, "master.key"), "pw")
	if err != nil {
		t.Fatal(err)
	}

	// The on-disk metadata.age (as if just restored) carries an entry.
	restored := storage.Store{Keys: map[string]storage.KeyMetadata{}}
	if err := storage.Put(&restored, storage.KeyMetadata{Fingerprint: "SHA256:x", Note: "restored"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.Save(&restored, vaultDir, id); err != nil {
		t.Fatal(err)
	}

	// The model still holds the stale, empty store it loaded at unlock.
	stale := storage.Store{Keys: map[string]storage.KeyMetadata{}}
	m := Model{
		active:     ScreenBackup,
		identity:   id,
		vaultDir:   vaultDir,
		sshDir:     dir,
		store:      &stale,
		backupView: newBackupModel(dir, vaultDir, id),
	}

	next, _ := m.Update(backupResultMsg{restored: true})
	m = next.(Model)

	if _, err := storage.Get(*m.store, "SHA256:x"); err != nil {
		t.Fatalf("store not reloaded after restore: %v", err)
	}
}

// TestRotateBitSize_ClampsWeakRSA covers the fix that lets an audit-flagged weak
// RSA key actually rotate: the size is clamped up to 4096 for RSA (preserving an
// already-strong size), and ignored for other algorithms.
func TestRotateBitSize_ClampsWeakRSA(t *testing.T) {
	cases := []struct {
		algo string
		in   int
		want int
	}{
		{"ssh-rsa", 1024, 4096},
		{"ssh-rsa", 2048, 4096},
		{"ssh-rsa", 4096, 4096},
		{"ssh-rsa", 8192, 8192},
		{"ssh-ed25519", 256, 256},
	}
	for _, c := range cases {
		if got := rotateBitSize(c.algo, c.in); got != c.want {
			t.Errorf("rotateBitSize(%q, %d) = %d, want %d", c.algo, c.in, got, c.want)
		}
	}
}

// TestDeleteKey_PublicOnly deletes a public-only key (empty private path): the
// public file is removed, and the emitted keyDeletedMsg carries the public path
// as identity rather than an empty string.
func TestDeleteKey_PublicOnly(t *testing.T) {
	dir := t.TempDir()
	pub := filepath.Join(dir, "orphan.pub")
	if err := os.WriteFile(pub, []byte("ssh-ed25519 AAAA orphan\n"), 0644); err != nil {
		t.Fatal(err)
	}
	k := keys.Key{PublicKeyPath: pub, IsPublicOnly: true}

	del, ok := runCmd(deleteKeyCmd(k)).(keyDeletedMsg)
	if !ok {
		t.Fatalf("want keyDeletedMsg")
	}
	if del.path != pub {
		t.Errorf("keyDeletedMsg.path = %q, want %q", del.path, pub)
	}
	if _, err := os.Stat(pub); !os.IsNotExist(err) {
		t.Error("public key file not removed")
	}
}

// TestKeyDeleted_RemovesCorrectPublicOnly ensures deletion targets the identified
// key, not the first public-only entry (which all shared an empty private path).
func TestKeyDeleted_RemovesCorrectPublicOnly(t *testing.T) {
	a := keys.Key{PublicKeyPath: "/ssh/a.pub", IsPublicOnly: true}
	b := keys.Key{PublicKeyPath: "/ssh/b.pub", IsPublicOnly: true}
	m := Model{active: ScreenKeys, keys: []keys.Key{a, b}, sshDir: "/ssh"}
	m.keyList = newKeyListModel(m.keys, nil, "/ssh")

	next, _ := m.Update(keyDeletedMsg{path: keyID(b)})
	m = next.(Model)

	if len(m.keys) != 1 || keyID(m.keys[0]) != keyID(a) {
		t.Fatalf("wrong key removed; remaining = %+v", m.keys)
	}
}

// TestSaveStore_SnapshotsBeforeSave proves the background save marshals a snapshot:
// mutating the live store after saveStore() is called must not change what lands
// on disk, so a concurrent metadata edit cannot race the Save's map read.
func TestSaveStore_SnapshotsBeforeSave(t *testing.T) {
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, ".keyward")
	if err := storage.Init(vaultDir); err != nil {
		t.Fatal(err)
	}
	id, err := crypto.InitMasterKey(filepath.Join(vaultDir, "master.key"), "pw")
	if err != nil {
		t.Fatal(err)
	}

	st := storage.Store{Keys: map[string]storage.KeyMetadata{}}
	if err := storage.Put(&st, storage.KeyMetadata{Fingerprint: "SHA256:x", Note: "snapshot"}); err != nil {
		t.Fatal(err)
	}
	m := Model{store: &st, identity: id, vaultDir: vaultDir}

	cmd := m.saveStore()
	// Mutate the live store after the snapshot is taken but before the save runs.
	delete(st.Keys, "SHA256:x")
	st.Keys["SHA256:y"] = storage.KeyMetadata{Fingerprint: "SHA256:y"}

	runCmd(cmd)

	loaded, err := storage.Load(vaultDir, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Get(loaded, "SHA256:x"); err != nil {
		t.Error("snapshot should have saved the pre-mutation entry SHA256:x")
	}
	if _, err := storage.Get(loaded, "SHA256:y"); err == nil {
		t.Error("post-snapshot mutation SHA256:y must not appear in the saved store")
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
	m.keyList = newKeyListModel(nil, nil, "")
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
	m := newKeyListModel(keyFixture(), nil, "")
	m.searching = true
	m, _ = m.update(k("rsa"))
	vis := m.visible()
	if len(vis) != 1 || !strings.HasSuffix(vis[0].key.PrivateKeyPath, "id_rsa") {
		t.Fatalf("search 'rsa' should leave only id_rsa; got %d items", len(vis))
	}
}

// §4.5 — backspace deletes whole runes (UTF-8), never panics on multibyte input.
func TestKeys_SearchBackspaceByRune(t *testing.T) {
	m := newKeyListModel(keyFixture(), nil, "")
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
	m := newKeyListModel(keyFixture(), nil, "")
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

// §4.9 — 'i' opens an inline import prompt; typing edits the path, esc cancels.
func TestKeys_ImportModeToggle(t *testing.T) {
	m := newKeyListModel(keyFixture(), nil, "/tmp/ssh")
	m, _ = m.update(k("i"))
	if !m.importing {
		t.Fatal("'i' should enter import mode")
	}
	m, _ = m.update(k("key"))
	if m.importPath != "key" {
		t.Fatalf("import path = %q, want %q", m.importPath, "key")
	}
	m, _ = m.update(k("esc"))
	if m.importing || m.importPath != "" {
		t.Fatalf("esc should cancel import: importing=%v path=%q", m.importing, m.importPath)
	}
}

// Enter with an empty path just closes the prompt without running a command.
func TestKeys_ImportEmptyPathCancels(t *testing.T) {
	m := newKeyListModel(keyFixture(), nil, "/tmp/ssh")
	m, _ = m.update(k("i"))
	m, cmd := m.update(k("enter"))
	if m.importing {
		t.Fatal("enter should exit import mode")
	}
	if cmd != nil {
		t.Fatalf("empty path should not trigger a command; got %T", runCmd(cmd))
	}
}

// Regression: rebuilding the key list after an import must not collapse its
// viewport to a single row (it lost width/height before propagateSize was added).
func TestKeys_ImportKeepsListSize(t *testing.T) {
	m := Model{active: ScreenKeys, width: 100, height: 40, keys: keyFixture()}
	m.keyList = newKeyListModel(m.keys, nil, "")
	m = m.propagateSize()
	baseline := m.keyList.height
	if baseline <= 1 {
		t.Fatalf("baseline list height = %d, want > 1", baseline)
	}

	next, _ := m.Update(keyImportedMsg{key: keys.Key{
		PrivateKeyPath: "/home/u/.ssh/imported", Algorithm: "ssh-ed25519", BitSize: 256,
	}})
	m = next.(Model)

	if m.keyList.height != baseline {
		t.Fatalf("list height after import = %d, want %d", m.keyList.height, baseline)
	}
	if len(m.keyList.items) != 3 {
		t.Fatalf("imported key not added: %d items", len(m.keyList.items))
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

// generateResult drives the async generation: it runs the batch that submit()
// returns and extracts the generateResultMsg produced by the generation cmd.
func generateResult(t *testing.T, cmd tea.Cmd) generateResultMsg {
	t.Helper()
	if cmd == nil {
		t.Fatal("submit returned a nil command")
	}
	msg := cmd()
	if r, ok := msg.(generateResultMsg); ok {
		return r
	}
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		t.Fatalf("expected batch or generateResultMsg, got %T", msg)
	}
	for _, c := range batch {
		if c == nil {
			continue
		}
		if r, ok := c().(generateResultMsg); ok {
			return r
		}
	}
	t.Fatal("no generateResultMsg in batch")
	return generateResultMsg{}
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
	if !got.submitting {
		t.Fatal("submit should mark the model as submitting")
	}
	// Feed the async result back into the model; success emits keyGeneratedMsg.
	got, cmd = got.update(generateResult(t, cmd))
	if got.submitting {
		t.Fatal("submitting should be cleared after the result arrives")
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
	res := generateResult(t, cmd)
	if res.err != nil {
		t.Fatalf("generate failed: %v", res.err)
	}
	if res.key.BitSize != 4096 {
		t.Fatalf("bit size = %d, want 4096", res.key.BitSize)
	}
	if res.key.Comment != "" {
		t.Fatalf("comment should be empty (number must not leak); got %q", res.key.Comment)
	}
}

func TestGenerate_RSABitSizeTooSmall(t *testing.T) { // §7.10
	m := newGenerateModel(t.TempDir())
	m = m.toggleCurrent("right") // -> rsa
	m = genType(m, inFilename+1, "id_small")
	m = genType(m, inComment+1, "1024")
	m = genType(m, inPass+1, "secret")
	m = genType(m, inPassConf+1, "secret")
	got, cmd := m.submit()
	got, _ = got.update(generateResult(t, cmd))
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
	got, cmd := m.submit()
	got, _ = got.update(generateResult(t, cmd))
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

// A successful save must clear a saveErr left by an earlier failure, otherwise
// the "✓ saved" message renders in the error style.
func TestConfig_SaveClearsPriorError(t *testing.T) {
	cfg, dir := loadConfig(t)
	m := newConfigModel(cfg, dir)
	m, _ = m.update(k("a")) // add a host so the config is modified
	m, _ = m.update(k("staging"))
	m, _ = m.update(k("enter"))
	if !m.cfg.Modified {
		t.Fatal("expected modified config")
	}

	m.saveErr = os.ErrInvalid // simulate a prior failed save
	m, _ = m.update(k("s"))

	if m.saveErr != nil {
		t.Fatalf("saveErr should be cleared after a successful save; got %v", m.saveErr)
	}
	if !strings.Contains(m.saveMsg, "saved") {
		t.Fatalf("saveMsg = %q, want a success message", m.saveMsg)
	}
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

// Restore must not touch ~/.ssh without an explicit confirmation. A valid
// selection lands on stepConfirm; only "y" proceeds, anything else cancels.
func TestBackup_RestoreRequiresConfirmation(t *testing.T) {
	vaultDir := t.TempDir()
	backupsDir := filepath.Join(vaultDir, "backups")
	if err := writeDummyBackups(backupsDir, "a.tar.age", "b.tar.age"); err != nil {
		t.Fatal(err)
	}
	m := newBackupModel(t.TempDir(), vaultDir, nil)
	m, _ = m.update(k("r"))
	m.confirmInput.SetValue("1")
	m, cmd := m.update(k("enter"))

	// Selecting a backup must NOT immediately restore — it asks to confirm.
	if m.promptStep != stepConfirm {
		t.Fatalf("expected stepConfirm after selection; got %v", m.promptStep)
	}
	if cmd != nil {
		t.Fatalf("no command should run before confirmation; got %#v", runCmd(cmd))
	}
	if m.restoreTarget == "" {
		t.Fatal("restoreTarget should hold the chosen backup path")
	}

	// A non-y key cancels back to the menu without restoring.
	cancelled, cmd := m.update(k("n"))
	if cancelled.promptStep != stepIdle {
		t.Fatalf("n should cancel to stepIdle; got %v", cancelled.promptStep)
	}
	if cmd != nil {
		t.Fatalf("cancel must not run a command; got %#v", runCmd(cmd))
	}

	// "y" with a locked vault (identity nil) proceeds to the password prompt,
	// not straight into RestoreBackup.
	confirmed, _ := m.update(k("y"))
	if confirmed.promptStep != stepPasswd {
		t.Fatalf("y with locked vault should go to stepPasswd; got %v", confirmed.promptStep)
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

// The SSH directory is edited inline in the menu (no separate screen): enter
// starts editing and marks the model busy so global tab/q are suppressed; esc
// cancels back to the menu without navigating away.
func TestSettings_SSHDirInlineEditCancel(t *testing.T) {
	m := newSettingsModel("master.key", "/ssh", "/vault")
	m, _ = m.updateMenu(k("down"))  // cursor -> SSH directory
	m, _ = m.updateMenu(k("enter")) // start inline edit
	if !m.editingSSHDir {
		t.Fatal("enter on SSH directory should start inline edit")
	}
	if m.step != settingsMenu {
		t.Fatalf("inline edit must stay on the menu step; got %v", m.step)
	}
	if !m.isBusy() {
		t.Fatal("inline edit should mark settings busy so tab/q are suppressed")
	}
	m, cmd := m.update(k("esc"))
	if m.editingSSHDir || m.isBusy() {
		t.Fatal("esc should cancel inline edit and clear busy")
	}
	if cmd != nil {
		if _, ok := runCmd(cmd).(navigateMsg); ok {
			t.Fatal("esc that only cancels inline edit must not navigate away")
		}
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
	}, nil, nil, false)
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
	}, nil, nil, false)
	kd.width = 100
	kd, _ = kd.update(k("e"))
	kd, _ = kd.update(k("down")) // focus note
	_, cmd := kd.update(k("enter"))
	if _, ok := runCmd(cmd).(keyMetaUpdatedMsg); ok {
		t.Fatal("enter in note field must not save metadata (use ctrl+s)")
	}
}

// 'A' on an encrypted key opens a passphrase prompt; empty enter errors, esc cancels.
func TestDetail_AddToAgentPromptsForPassphrase(t *testing.T) {
	kd := newKeyDetailModel(keys.Key{
		PrivateKeyPath: "/ssh/id", Fingerprint: "SHA256:x", HasPassphrase: true,
	}, nil, nil, false)
	kd.width = 100

	kd, cmd := kd.update(k("A"))
	if !kd.addingAgent {
		t.Fatal("'A' on an encrypted key should open the passphrase prompt")
	}
	if cmd != nil {
		t.Fatal("no command should run until the passphrase is entered")
	}

	kd, _ = kd.update(k("enter")) // empty passphrase
	if kd.agentPassErr == "" {
		t.Fatal("empty passphrase should set an error")
	}

	kd, _ = kd.update(k("esc"))
	if kd.addingAgent {
		t.Fatal("esc should cancel the prompt")
	}
}

// 'A' on an unencrypted key issues the add command directly (no prompt).
func TestDetail_AddToAgentNoPassphrase(t *testing.T) {
	kd := newKeyDetailModel(keys.Key{
		PrivateKeyPath: "/ssh/id", Fingerprint: "SHA256:x", HasPassphrase: false,
	}, nil, nil, false)
	kd.width = 100

	kd, cmd := kd.update(k("A"))
	if kd.addingAgent {
		t.Fatal("an unencrypted key should not open a prompt")
	}
	if cmd == nil {
		t.Fatal("'A' should return an add-to-agent command")
	}
}

// 'A' on a key already in the agent is a no-op.
func TestDetail_AddToAgentAlreadyLoaded(t *testing.T) {
	kd := newKeyDetailModel(keys.Key{
		PrivateKeyPath: "/ssh/id", Fingerprint: "SHA256:x", HasPassphrase: true,
	}, nil, nil, true)
	kd.width = 100

	kd, cmd := kd.update(k("A"))
	if kd.addingAgent || cmd != nil {
		t.Fatal("'A' on an already-loaded key should do nothing")
	}
}

// fitRight keeps the head of a string and appends "…" only when it overflows.
func TestFitRight(t *testing.T) {
	cases := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"fits exactly", "82.70.50.109", 12, "82.70.50.109"},
		{"shorter than n", "60", 12, "60"},
		{"truncated", "/Users/weiqur/.ssh/some-really-long-identity-file", 12, "/Users/weiq…"},
		{"n too small returns input", "value", 1, "value"},
		{"empty", "", 12, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fitRight(tc.s, tc.n)
			if got != tc.want {
				t.Fatalf("fitRight(%q, %d) = %q, want %q", tc.s, tc.n, got, tc.want)
			}
			if tc.n > 1 && len([]rune(got)) > tc.n {
				t.Fatalf("result %q exceeds width %d", got, tc.n)
			}
		})
	}
}

// Editing an overlong value must scroll horizontally inside a fixed window —
// no rendered line may ever exceed the pane width and push the frame out.
func TestConfig_LongValueNeverOverflows(t *testing.T) {
	cfg, dir := loadConfig(t)
	m := newConfigModel(cfg, dir)
	m.width, m.height = 100, 20

	long := strings.Repeat("very-long-proxy-command-", 8) // ~192 chars
	m.cfg.Blocks[1].Tokens[2].Value = long                // myserver → HostName

	// Static view: the value is truncated with a trailing ellipsis.
	m, _ = m.update(k("down")) // select "myserver"
	m, _ = m.update(k("enter"))
	for _, line := range strings.Split(m.view(), "\n") {
		if w := lipgloss.Width(line); w > m.width {
			t.Fatalf("static view line overflows: width %d > %d\n%q", w, m.width, line)
		}
	}
	if !strings.Contains(m.view(), "…") {
		t.Fatal("static view should truncate the long value with an ellipsis")
	}

	// Edit mode: the input window is fixed; typing and cursor movement scroll
	// the value instead of widening the row.
	m, _ = m.update(k("e"))
	if !m.editing {
		t.Fatal("expected edit mode")
	}
	if m.editInput.Width <= 0 {
		t.Fatal("editInput.Width must be set on edit start for horizontal scrolling")
	}
	m, _ = m.update(k("x")) // type at the end
	for _, line := range strings.Split(m.view(), "\n") {
		if w := lipgloss.Width(line); w > m.width {
			t.Fatalf("edit view line overflows: width %d > %d\n%q", w, m.width, line)
		}
	}
	m, _ = m.update(k("esc"))

	// Add-param form: a long value typed into the inputs scrolls too.
	m, _ = m.update(k("a"))
	m, _ = m.update(k("ProxyCommand"))
	m, _ = m.update(k("tab"))
	m, _ = m.update(k(long))
	if m.addParamInputs[1].Width <= 0 {
		t.Fatal("add-param input width must be set for horizontal scrolling")
	}
	for _, line := range strings.Split(m.view(), "\n") {
		if w := lipgloss.Width(line); w > m.width {
			t.Fatalf("add-param view line overflows: width %d > %d\n%q", w, m.width, line)
		}
	}
	m, _ = m.update(k("esc"))

	// Hosts pane: renaming to / adding an overlong pattern scrolls inside the
	// pane and never pushes the divider; a long static name is truncated.
	m, _ = m.update(k("esc")) // back to left pane
	m, _ = m.update(k("r"))
	if m.renameInput.Width <= 0 {
		t.Fatal("rename input width must be set for horizontal scrolling")
	}
	m, _ = m.update(k(long))
	hostsPaneOverflow(t, m)
	m, _ = m.update(k("enter")) // commit rename → long static name
	hostsPaneOverflow(t, m)

	m, _ = m.update(k("a"))
	m, _ = m.update(k(long))
	hostsPaneOverflow(t, m)
}

// hostsPaneOverflow asserts no view line spills past the Hosts pane into the
// divider column.
func hostsPaneOverflow(t *testing.T, m configModel) {
	t.Helper()
	leftW, _ := m.paneWidths()
	for _, line := range strings.Split(m.view(), "\n") {
		if w := lipgloss.Width(line); w > m.width {
			t.Fatalf("view line overflows frame: width %d > %d\n%q", w, m.width, line)
		}
		// Every joined line must still carry the divider at column leftW+1.
		plain := []rune(stripANSI(line))
		if strings.ContainsRune(string(plain), '│') && len(plain) > leftW &&
			!strings.HasPrefix(strings.TrimLeft(string(plain[leftW:]), " "), "│") {
			t.Fatalf("divider shifted from column %d:\n%q", leftW+1, string(plain))
		}
	}
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

// stripANSI removes SGR escape sequences so columns can be counted.
func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

// ── §11 known_hosts viewer ──────────────────────────────────────────────────

// writeKnownHostsFile writes a known_hosts file with n plain ed25519 entries
// (hosts host1.example … hostN.example) into a fresh temp SSH dir and returns
// that dir.
func writeKnownHostsFile(t *testing.T, n int) string {
	t.Helper()
	sshDir := t.TempDir()
	var b strings.Builder
	for i := 1; i <= n; i++ {
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("ssh.NewPublicKey: %v", err)
		}
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
		fmt.Fprintf(&b, "host%d.example %s\n", i, line)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return sshDir
}

// khEntries builds n in-memory known_hosts entries for view/nav tests.
func khEntries(n int) []knownhosts.Entry {
	out := make([]knownhosts.Entry, n)
	for i := range out {
		out[i] = knownhosts.Entry{
			Hosts:       []string{fmt.Sprintf("host%d.example", i+1)},
			KeyType:     "ssh-ed25519",
			Fingerprint: "SHA256:abc",
			LineNum:     i + 1,
		}
	}
	return out
}

func TestKnownHosts_NavigatePopulatesFromFile(t *testing.T) {
	sshDir := writeKnownHostsFile(t, 3)
	m := Model{active: ScreenKeys, sshDir: sshDir}
	m, _ = sendRoot(t, m, "tab") // Audit
	m, _ = sendRoot(t, m, "tab") // Config
	m, _ = sendRoot(t, m, "tab") // Generate
	m, _ = sendRoot(t, m, "tab") // Known Hosts
	if m.active != ScreenKnownHosts {
		t.Fatalf("active = %v, want ScreenKnownHosts", m.active)
	}
	if len(m.knownHosts.entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(m.knownHosts.entries))
	}
}

func TestKnownHosts_ForgetTwoStepConfirm(t *testing.T) {
	m := knownHostsModel{entries: khEntries(3), path: "irrelevant"}

	// First d arms the confirmation and issues no command.
	m, cmd := m.update(k("d"))
	if !m.confirmForget {
		t.Fatal("first d should arm confirmForget")
	}
	if cmd != nil {
		t.Fatal("first d should not issue a command")
	}

	// esc cancels the confirmation without navigating away.
	m, cmd = m.update(k("esc"))
	if m.confirmForget {
		t.Fatal("esc should clear confirmForget")
	}
	if cmd != nil {
		t.Fatal("esc that only cancels confirm should not navigate")
	}

	// d, d issues the forget command.
	m, _ = m.update(k("d"))
	m, cmd = m.update(k("d"))
	if m.confirmForget {
		t.Fatal("second d should clear confirmForget")
	}
	if cmd == nil {
		t.Fatal("second d should issue the forget command")
	}
}

func TestKnownHosts_ForgetRemovesEntryAndKeepsSize(t *testing.T) {
	sshDir := writeKnownHostsFile(t, 3)
	m := Model{active: ScreenKeys, sshDir: sshDir, width: 100, height: 30}
	m = m.propagateSize()
	m, _ = sendRoot(t, m, "tab")
	m, _ = sendRoot(t, m, "tab")
	m, _ = sendRoot(t, m, "tab")
	m, _ = sendRoot(t, m, "tab")
	if m.active != ScreenKnownHosts {
		t.Fatalf("active = %v, want ScreenKnownHosts", m.active)
	}
	m.knownHosts.cursor = 1 // target host2.example
	wantH := m.knownHosts.height

	// d, d → forget command, then apply its message through the root model.
	var cmd tea.Cmd
	m.knownHosts, _ = m.knownHosts.update(k("d"))
	m.knownHosts, cmd = m.knownHosts.update(k("d"))
	msg := runCmd(cmd)
	if _, ok := msg.(khForgotMsg); !ok {
		t.Fatalf("expected khForgotMsg, got %T", msg)
	}
	next, _ := m.Update(msg)
	m = next.(Model)

	if len(m.knownHosts.entries) != 2 {
		t.Fatalf("entries after forget = %d, want 2", len(m.knownHosts.entries))
	}
	for _, e := range m.knownHosts.entries {
		if e.Hosts[0] == "host2.example" {
			t.Fatal("host2.example should have been forgotten")
		}
	}
	if m.knownHosts.height != wantH || m.knownHosts.width == 0 {
		t.Fatalf("size not retained after forget: w=%d h=%d (want h=%d)",
			m.knownHosts.width, m.knownHosts.height, wantH)
	}
}

func TestKnownHosts_EmptyScreenNoCrash(t *testing.T) {
	m := knownHostsModel{width: 80, height: 20}
	// d on an empty list is a no-op and must not panic.
	m, cmd := m.update(k("d"))
	if cmd != nil || m.confirmForget {
		t.Fatal("d on empty list should do nothing")
	}
	if !strings.Contains(m.view(), "no known_hosts entries") {
		t.Fatalf("empty view missing placeholder:\n%s", m.view())
	}
}
