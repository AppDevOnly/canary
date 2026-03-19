#!/usr/bin/env bash
# Canary installer — Linux/Mac
# Usage: curl -sSL https://raw.githubusercontent.com/AppDevOnly/canary/main/install.sh | bash

set -euo pipefail

SKILL_URL="https://raw.githubusercontent.com/AppDevOnly/canary/main/canary.md"
COMMANDS_DIR="$HOME/.claude/commands"
DEST="$COMMANDS_DIR/canary.md"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✅  $*${NC}"; }
warn() { echo -e "  ${YELLOW}⚠️   $*${NC}"; }
err()  { echo -e "  ${RED}❌  $*${NC}"; }
info() { echo -e "  ${CYAN}$*${NC}"; }

echo ""
info "Canary installer"
info "────────────────────────────────────"
echo ""

# ── Check for Claude Code ──────────────────────────────────────────────────────
if ! command -v claude &>/dev/null; then
    err "Claude Code not found."
    echo "     Install it first: https://github.com/anthropics/claude-code"
    echo ""
    exit 1
fi

# ── Install canary.md skill ────────────────────────────────────────────────────
info "[1/3] Installing canary skill..."
mkdir -p "$COMMANDS_DIR"
if command -v curl &>/dev/null; then
    curl -sSL "$SKILL_URL" -o "$DEST"
elif command -v wget &>/dev/null; then
    wget -qO "$DEST" "$SKILL_URL"
else
    err "Neither curl nor wget found. Download $SKILL_URL manually to $DEST"
    exit 1
fi
ok "Installed to $DEST"

# ── Check static analysis tools ───────────────────────────────────────────────
info "[2/3] Checking static analysis tools (Medium/Full)..."

check_tool() {
    local cmd="$1" label="$2" install_hint="$3"
    if command -v "$cmd" &>/dev/null; then
        ok "$label — $(${cmd} --version 2>/dev/null | head -1 || echo 'found')"
    else
        warn "$label — not installed. Install: $install_hint"
    fi
}

check_tool gh        "gh"        "brew install gh  (then: gh auth login)"
check_tool semgrep   "semgrep"   "pip install semgrep"
check_tool bandit    "bandit"    "pip install bandit"
check_tool gitleaks  "gitleaks"  "brew install gitleaks"
check_tool pip-audit "pip-audit" "pip install pip-audit"

# trufflehog needs special handling — must be v3.x from binary, not pip
if command -v trufflehog &>/dev/null; then
    ver=$(trufflehog --version 2>/dev/null | head -1 || echo "")
    if echo "$ver" | grep -qE '^3\.'; then
        ok "trufflehog — $ver"
    else
        warn "trufflehog — found but appears to be v2.x ($ver). Canary needs v3.x."
        echo "       Install: brew install trufflehog  OR  binary from https://github.com/trufflesecurity/trufflehog/releases"
        echo "       Do NOT use pip — it installs legacy v2.x"
    fi
else
    warn "trufflehog — not installed."
    echo "       Install: brew install trufflehog  OR  binary from https://github.com/trufflesecurity/trufflehog/releases"
    echo "       Do NOT use pip — it installs legacy v2.x"
fi

# ── Check sandbox (Medium/Full) ────────────────────────────────────────────────
info "[3/3] Checking sandbox for Medium/Full mode..."

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    ok "Docker — available (used for Medium/Full sandbox on Linux/Mac)"
else
    warn "Docker — not running or not installed."
    echo "       Medium and Full mode require Docker for sandbox isolation on Linux/Mac."
    echo "       Install: https://docs.docker.com/get-docker/"
    echo "       Quick mode works without Docker."
fi

echo ""
echo -e "  ${GREEN}Done. Restart Claude Code if it is already running.${NC}"
echo ""
info "Quick start:"
echo "    /canary https://github.com/someuser/somerepo   (Quick — works now)"
echo "    /canary https://github.com/someuser/somerepo   (Medium/Full — requires Docker)"
echo ""
echo "  Note: Full mode (dynamic sandbox with process/network monitoring) is"
echo "  currently Windows-only. Medium static analysis works on Linux/Mac via Docker."
echo ""
