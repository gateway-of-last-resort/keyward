# keyward full demo: setup, search, metadata, agent, rotation, audit, config,
# generate, known hosts, backup and restore
#
# Precondition:
#   cd assets && ./demo-setup.sh && go build -o /tmp/dev/keyward ../cmd/keyward
#   HOME=/tmp/dev vhs demo.tape
Output demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1720
Set Height 900
Set Padding 24
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
Set TypingSpeed 65ms

# --- hidden: sandbox HOME + truecolor so the gradient renders smoothly ---
Hide
Type `export HOME="/tmp/dev"; export COLORTERM=truecolor; export PS1="$ "; eval "$(ssh-agent -s)" >/dev/null; cd "$HOME"; clear`
Enter
Sleep 1000ms
Show

Type "./keyward"
Enter
Sleep 2400ms

# ── first run: create the encrypted vault ────────────────────────────────
Type "demo-vault-42"
Enter
Type "demo-vault-42"
Sleep 600ms
Enter
Wait+Screen@10s /SSH Keys/
Sleep 3200ms

# ── search the key list, open the CRITICAL rsa key ───────────────────────
Type "/"
Sleep 600ms
Type "prod"
Sleep 1200ms
Enter
Sleep 800ms
Enter
Sleep 3200ms

# ── edit metadata: toggle tags, write a note ─────────────────────────────
Type "e"
Sleep 1400ms
Right
Right
Space
Sleep 700ms
Right
Space
Sleep 700ms
Down
Type "legacy deploy key, rotate soon"
Sleep 1000ms
Ctrl+S
Sleep 2200ms

# ── load it into the ssh-agent: the result shows above the hints ─────────
Type "A"
Wait+Screen@10s /added to ssh-agent/
Sleep 3200ms

# ── rotate it: a new 4096-bit RSA key with a passphrase ──────────────────
Type "r"
Sleep 1400ms
Enter
Sleep 600ms
Type "rotated-pass"
Enter
Type "rotated-pass"
Sleep 800ms
Enter
Wait+Screen@30s /key rotated/
Sleep 3200ms
Escape
Sleep 1200ms

# ── audit: the grade went up after the rotation ──────────────────────────
Tab
Sleep 3000ms
Down
Sleep 1200ms
Down
Sleep 1800ms

# ── config: browse, ask to delete a host (cancel), add one, save ─────────
Tab
Sleep 1800ms
Down
Sleep 700ms
Down
Sleep 1000ms
Enter
Sleep 1000ms
Down
Sleep 800ms
Escape
Sleep 800ms
Type "d"
Sleep 3200ms
Escape
Sleep 1000ms

Type "a"
Sleep 800ms
Type "bastion"
Sleep 500ms
Enter
Sleep 1200ms
Enter
Sleep 900ms
Type "a"
Sleep 700ms
Type "HostName"
Enter
Type "10.0.0.1"
Enter
Sleep 1000ms
Type "a"
Sleep 500ms
Type "User"
Enter
Type "ops"
Enter
Sleep 1000ms
Type "s"
Wait+Screen@10s /saved/
Sleep 3200ms

# ── generate a new protected ed25519 key ─────────────────────────────────
Tab
Sleep 1800ms
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
Sleep 700ms
Enter
Wait+Screen@10s /generated/
Sleep 3200ms

# ── known hosts: forget one, confirmed at the bottom ─────────────────────
# generate returns to the Keys screen; Known Hosts is four tabs away.
Tab
Sleep 500ms
Tab
Sleep 500ms
Tab
Sleep 500ms
Tab
Sleep 2000ms
Down
Sleep 1000ms
Down
Sleep 1200ms
Type "d"
Sleep 3000ms
Type "d"
Wait+Screen@10s /forgot/
Sleep 3200ms

# ── backup, then restore the selected backup ─────────────────────────────
Tab
Sleep 1400ms
Type "b"
Wait+Screen@15s /backup saved/
Sleep 3200ms
Type "r"
Sleep 3600ms
Type "y"
Wait+Screen@15s /restored from/
Sleep 3200ms
