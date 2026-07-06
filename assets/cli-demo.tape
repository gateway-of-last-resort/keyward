# keyward CLI demo — headless subcommands: list · audit · agent · backup
#
# Precondition (run before recording, same sandbox as demo.tape):
#   cd assets && ./demo-setup.sh && go build -o /tmp/dev/keyward ../cmd/keyward
#   HOME=/tmp/dev vhs cli-demo.tape
#
# Needs: vhs + ttyd + ffmpeg + jq.
Output cli-demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1600
Set Height 1000
Set Padding 24
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

# --- hidden: sandbox HOME, truecolor, agent, PATH, and a vault so `backup` works ---
Hide
Type `export HOME="/tmp/dev"; export COLORTERM=truecolor; export PS1="$ "; export PATH="$HOME:$PATH"; cd "$HOME"; eval "$(ssh-agent -s)" >/dev/null`
Enter
# Initialise the encrypted vault via a quick TUI run so `backup` has a master.key.
Type "keyward"
Enter
Sleep 1200ms
Type "demo-vault-42"
Enter
Type "demo-vault-42"
Enter
Sleep 1600ms
Ctrl+C
Sleep 500ms
Type `export KEYWARD_PASSWORD="demo-vault-42"; clear`
Enter
Show

# ── list discovered keys ─────────────────────────────────────────────────
Type "keyward list"
Enter
Sleep 2600ms

# ── security audit (text report, grade C) ────────────────────────────────
Type "keyward audit"
Enter
Sleep 3200ms

# ── machine-readable audit for scripts ───────────────────────────────────
Type "keyward audit --json | jq '{grade, points}'"
Enter
Sleep 2600ms

# ── gate a pipeline: non-zero exit when a finding meets the threshold ─────
Type `keyward audit --fail-on=warning; echo "exit=$?"`
Enter
Sleep 2600ms

# ── load a key into the ssh-agent (passphrase from an env var) ────────────
Type "export KP='correct horse'"
Enter
Type "keyward agent add ~/.ssh/id_ed25519 --passphrase-env KP"
Enter
Sleep 1800ms
Type "keyward agent list"
Enter
Sleep 2600ms

# ── write an encrypted backup of ~/.ssh (password from $KEYWARD_PASSWORD) ──
Type "keyward backup --out backup.tar.age"
Enter
Sleep 2400ms
Type "ls -lh backup.tar.age"
Enter
Sleep 2200ms
