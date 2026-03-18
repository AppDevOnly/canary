#!/usr/bin/env bash
# check-deps.sh — verify which analysis tools are available for Canary
# Run this to see what static analysis capabilities you have installed.

echo ""
echo "  Canary dependency check"
echo "  ─────────────────────────"
echo ""

check() {
    local name="$1"
    local cmd="$2"
    local install_hint="$3"
    if command -v "$cmd" &>/dev/null; then
        echo "  ✅  $name ($cmd)"
    else
        echo "  ⬜  $name — not found"
        echo "      Install: $install_hint"
    fi
}

echo "  Static analysis tools:"
check "pip-audit"    "pip-audit"   "pip install pip-audit"
check "Bandit"       "bandit"      "pip install bandit"
check "Semgrep"      "semgrep"     "pip install semgrep"
check "Trufflehog"   "trufflehog"  "brew install trufflehog  OR  https://github.com/trufflesecurity/trufflehog"
check "npm audit"    "npm"         "https://nodejs.org"
check "jq"           "jq"          "brew install jq  OR  apt install jq"

echo ""
echo "  Sandbox / isolation:"
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OS" == "Windows_NT" ]]; then
    # Windows — check for Windows Sandbox feature
    if powershell.exe -Command "Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM" 2>/dev/null | grep -q "Enabled"; then
        echo "  ✅  Windows Sandbox (enabled)"
    else
        echo "  ⬜  Windows Sandbox — not enabled"
        echo "      Enable: Settings → Apps → Optional features → Windows Sandbox"
    fi
else
    check "Docker" "docker" "https://docs.docker.com/get-docker/"
fi

echo ""
echo "  Network monitoring (Windows only):"
echo "  ⬜  tshark — see https://www.wireshark.org"
echo "  ⬜  Sysinternals Procmon — see https://learn.microsoft.com/en-us/sysinternals"
echo ""
