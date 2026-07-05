# keyward full demo — setup → keys/detail/metadata → audit → config editing → generate → known hosts → backup
Output demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1720
Set Height 900
Set Padding 24
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

# --- hidden: sandbox HOME + truecolor so the gradient renders smoothly ---
Hide
Type `export HOME="/tmp/dev"; export COLORTERM=truecolor; export PS1="$ "; eval "$(ssh-agent -s)" >/dev/null; cd "$HOME"; clear`
Enter
Sleep 500ms
Show

Type "./keyward"
Enter
Sleep 1200ms

# ── first run: create the encrypted vault ────────────────────────────────
Type "demo-vault-42"
Enter
Type "demo-vault-42"
Sleep 300ms
Enter
Sleep 1600ms

# ── keys list → open the CRITICAL rsa key ────────────────────────────────
Down
Down
Sleep 400ms
Enter
Sleep 1800ms

# ── edit metadata: toggle tags, write a note ─────────────────────────────
Type "e"
Sleep 700ms
Right
Right
Space
Sleep 350ms
Right
Space
Sleep 350ms
Down
Type "legacy deploy key, rotate soon"
Sleep 500ms
Ctrl+S
Sleep 1100ms

# ── load this key into the ssh-agent (passphrase-less → loads at once) ────
Type "A"
Sleep 1600ms
Escape
Sleep 700ms

# ── audit: walk through findings ─────────────────────────────────────────
Tab
Sleep 1400ms
Down
Sleep 650ms
Down
Sleep 650ms
Down
Sleep 900ms

# ── config: switch hosts, browse params ──────────────────────────────────
Tab
Sleep 900ms
Down
Sleep 350ms
Down
Sleep 550ms
Enter
Sleep 550ms
Down
Sleep 300ms
Down
Sleep 450ms
Escape
Sleep 350ms

# add a new host with params, edit one, save
Type "a"
Sleep 400ms
Type "bastion"
Sleep 250ms
Enter
Sleep 600ms
Enter
Sleep 450ms
Type "a"
Sleep 350ms
Type "HostName"
Enter
Type "10.0.0.1"
Enter
Sleep 500ms
Type "a"
Sleep 250ms
Type "User"
Enter
Type "ops"
Enter
Sleep 500ms
Up
Sleep 300ms
Type "e"
Sleep 400ms
Ctrl+U
Type "10.0.0.5"
Sleep 250ms
Enter
Sleep 550ms
Type "s"
Sleep 1300ms

# ── generate a new protected ed25519 key ─────────────────────────────────
Tab
Sleep 900ms
Down
Type "ci_ed25519"
Down
Down
Type "ci@deploy"
Down
Type "s3cret-pass"
Down
Type "s3cret-pass"
Down
Sleep 350ms
Enter
Sleep 2200ms

# ── known hosts: browse entries, forget one ──────────────────────────────
# generate returns to the Keys screen; tab across to Known Hosts (now between
# Generate and Backup in the tab bar).
Tab
Sleep 250ms
Tab
Sleep 250ms
Tab
Sleep 250ms
Tab
Sleep 1000ms
Down
Sleep 500ms
Down
Sleep 700ms
Type "d"
Sleep 950ms
Type "d"
Sleep 1300ms

# ── encrypted backup of ~/.ssh ───────────────────────────────────────────
Tab
Sleep 700ms
Type "b"
Sleep 2200ms
Sleep 1400ms
