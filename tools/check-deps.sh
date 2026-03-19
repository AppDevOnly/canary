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

check_path() {
    local name="$1"
    local path="$2"
    local install_hint="$3"
    if [ -f "$path" ]; then
        echo "  ✅  $name"
    else
        echo "  ⬜  $name — not found at $path"
        echo "      Install: $install_hint"
    fi
}

echo "  Quick / Medium tools:"
check "gh (GitHub CLI)"  "gh"          "winget install GitHub.cli  OR  brew install gh"
check "pip-audit"        "pip-audit"   "pip install pip-audit"
check "npm"              "npm"         "https://nodejs.org"
check "Semgrep"          "semgrep"     "pip install semgrep"
check "Bandit"           "bandit"      "pip install bandit"
check "Trufflehog"       "trufflehog"  "winget install trufflesecurity.trufflehog  OR  brew install trufflehog"
check "Gitleaks"         "gitleaks"    "winget install gitleaks  OR  brew install gitleaks"

echo ""
echo "  Full mode tools (sandbox):"

if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OS" == "Windows_NT" ]]; then
    # Windows Sandbox
    if powershell.exe -Command "Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM" 2>/dev/null | grep -q "Enabled"; then
        echo "  ✅  Windows Sandbox (enabled)"
    else
        echo "  ⬜  Windows Sandbox — not enabled"
        echo "      Enable: Settings → System → Optional Features → Windows Sandbox  OR:"
        echo "      Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM"
    fi

    # Sysinternals
    check_path "Sysinternals Procmon64"  "/c/temp/security-tools/Sysinternals/Procmon64.exe" \
        "Download from https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite, extract to C:\\temp\\security-tools\\Sysinternals\\"
    check_path "Sysinternals Autoruns64" "/c/temp/security-tools/Sysinternals/autorunsc64.exe" \
        "Same package as Procmon — extract Sysinternals Suite to C:\\temp\\security-tools\\Sysinternals\\"

    # tshark
    check "tshark" "tshark" "winget install WiresharkFoundation.Wireshark  (tshark is included)"
else
    check "Docker" "docker" "https://docs.docker.com/get-docker/"
    check "tshark"  "tshark"  "brew install wireshark  OR  apt install tshark"
fi

echo ""
echo "  Canary sandbox scripts:"
if [ -d "/c/sandbox/scripts" ]; then
    echo "  ✅  C:\\sandbox\\scripts\\ (sandbox infrastructure deployed)"
else
    echo "  ⬜  C:\\sandbox\\scripts\\ — not found"
    echo "      Run the canary installer: irm https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 | iex"
fi
echo ""
