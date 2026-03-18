#!/usr/bin/env bash
# Canary installer — copies the /canary Claude skill to ~/.claude/commands/
# Usage: curl -sSL https://raw.githubusercontent.com/AppDevOnly/canary/main/install.sh | bash

set -euo pipefail

SKILL_URL="https://raw.githubusercontent.com/AppDevOnly/canary/main/canary.md"
COMMANDS_DIR="$HOME/.claude/commands"
DEST="$COMMANDS_DIR/canary.md"

echo ""
echo "  🐦 Canary installer"
echo "  ───────────────────"
echo ""

# Check for Claude Code
if ! command -v claude &>/dev/null; then
    echo "  ❌  Claude Code not found."
    echo "      Install it first: https://github.com/anthropics/claude-code"
    echo ""
    exit 1
fi

# Create commands dir if needed
mkdir -p "$COMMANDS_DIR"

# Download skill
echo "  Downloading canary.md..."
if command -v curl &>/dev/null; then
    curl -sSL "$SKILL_URL" -o "$DEST"
elif command -v wget &>/dev/null; then
    wget -qO "$DEST" "$SKILL_URL"
else
    echo "  ❌  Neither curl nor wget found. Download $SKILL_URL manually to $DEST"
    exit 1
fi

echo "  ✅  Installed to $DEST"
echo ""
echo "  Usage in Claude Code:"
echo "    /canary https://github.com/someuser/somerepo"
echo "    /canary ~/projects/my-app"
echo "    /canary pip:requests"
echo "    /canary npm:lodash"
echo ""
echo "  Restart Claude Code if it's already running, then try /canary."
echo ""
