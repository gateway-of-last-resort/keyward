#!/usr/bin/env bash
#
# demo-setup.sh — build (or reset) the throwaway sandbox used to record the
# Keyward demo in demo.tape. Everything lives under a fake $HOME so the
# recording never touches your real ~/.ssh or ~/.keyward.
#
# Usage:
#   ./demo-setup.sh          # create the sandbox at /tmp/dev
#   ./demo-setup.sh --reset  # wipe vault + generated key, restore config only
#
# Re-record after running this:
#   cd assets && vhs demo.tape        # writes demo.gif
#
# The sandbox keys are deliberately anonymized (dev@laptop / dev@github /
# deploy@server) and the RSA key is intentionally passphrase-less + 2048-bit so
# the audit screen lands on grade C — that "not everything is OK" state is what
# the demo walks through.
set -euo pipefail

SB=/tmp/dev
SSH="$SB/.ssh"

write_config() {
	cat > "$SSH/config" <<'EOF'
# Personal & work SSH hosts

Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/github_ed25519

Host prod
    HostName 203.0.113.10
    User deploy
    IdentityFile ~/.ssh/prod_rsa
    ForwardAgent yes

Host staging
    HostName 198.51.100.5
    User deploy
    Port 2222
    StrictHostKeyChecking no
EOF
	chmod 600 "$SSH/config"
}

# --reset: drop recording artifacts (vault, generated key, backups) and restore
# the pristine config, but keep the seed keys so you can re-record immediately.
if [[ "${1:-}" == "--reset" ]]; then
	rm -rf "$SB/.keyward"
	rm -f "$SSH/ci_ed25519" "$SSH/ci_ed25519.pub"
	rm -f "$SSH/config.bak" "$SSH"/*.pre-restore 2>/dev/null || true
	write_config
	echo "sandbox reset OK ($SB)"
	exit 0
fi

# Fresh build.
rm -rf "$SB"
mkdir -p "$SSH"
chmod 700 "$SB" "$SSH"

# Two protected ed25519 keys + one bare 2048-bit RSA key (→ audit grade C).
ssh-keygen -t ed25519 -C "dev@laptop"  -N "correct horse" -f "$SSH/id_ed25519"     >/dev/null
ssh-keygen -t ed25519 -C "dev@github"  -N "battery staple" -f "$SSH/github_ed25519" >/dev/null
ssh-keygen -t rsa -b 2048 -C "deploy@server" -N "" -f "$SSH/prod_rsa"               >/dev/null
chmod 600 "$SSH"/id_ed25519 "$SSH"/github_ed25519 "$SSH"/prod_rsa

write_config
echo "sandbox built OK ($SB) — record with: cd assets && HOME=$SB vhs demo.tape"
