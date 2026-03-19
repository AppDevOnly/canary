# Canary installer for PowerShell (Windows)
# Usage: irm https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 | iex

$BaseUrl     = "https://raw.githubusercontent.com/AppDevOnly/canary/main"
$CommandsDir = "$env:USERPROFILE\.claude\commands"
$SandboxDir  = "C:\sandbox"
$ScriptsDir  = "$SandboxDir\scripts"
$OutputDir   = "$SandboxDir\output"

Write-Host ""
Write-Host "  Canary installer" -ForegroundColor Cyan
Write-Host "  ─────────────────────────────────────" -ForegroundColor Cyan
Write-Host ""

# ── Check for Claude Code ────────────────────────────────────────────────────────
if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
    Write-Host "  ERROR: Claude Code not found." -ForegroundColor Red
    Write-Host "         Install it first: https://github.com/anthropics/claude-code" -ForegroundColor Red
    Write-Host ""
    exit 1
}

# ── Install canary.md skill ──────────────────────────────────────────────────────
Write-Host "  [1/3] Installing canary skill..." -ForegroundColor Cyan
if (-not (Test-Path $CommandsDir)) {
    New-Item -ItemType Directory -Path $CommandsDir -Force | Out-Null
}
try {
    Invoke-WebRequest -Uri "$BaseUrl/canary.md" -OutFile "$CommandsDir\canary.md" -UseBasicParsing
    Write-Host "        Installed to $CommandsDir\canary.md" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Failed to download canary.md — $_" -ForegroundColor Red
    exit 1
}

# ── Deploy sandbox infrastructure ───────────────────────────────────────────────
Write-Host "  [2/3] Setting up sandbox infrastructure..." -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path $ScriptsDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutputDir  | Out-Null

$sandboxFiles = @(
    "sandbox/run-watchdog.ps1",
    "sandbox/bootstrap.cmd",
    "sandbox/sandbox-template.wsb",
    "sandbox/analyze-pid-chain.ps1",
    "sandbox/setup-template.ps1"
)

$allOk = $true
foreach ($file in $sandboxFiles) {
    $dest = "$ScriptsDir\$(Split-Path $file -Leaf)"
    try {
        Invoke-WebRequest -Uri "$BaseUrl/$file" -OutFile $dest -UseBasicParsing
        Write-Host "        $dest" -ForegroundColor Green
    } catch {
        Write-Host "        FAILED: $file — $_" -ForegroundColor Red
        $allOk = $false
    }
}

if (-not $allOk) {
    Write-Host "  WARNING: Some sandbox files failed to download. Full mode may not work." -ForegroundColor Yellow
}

# ── Check Full mode prerequisites ────────────────────────────────────────────────
Write-Host "  [3/3] Checking Full mode prerequisites..." -ForegroundColor Cyan

# Windows Sandbox
$sbFeature = Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -ErrorAction SilentlyContinue
if ($sbFeature -and $sbFeature.State -eq 'Enabled') {
    Write-Host "        Windows Sandbox: enabled" -ForegroundColor Green
} else {
    Write-Host "        Windows Sandbox: NOT enabled" -ForegroundColor Yellow
    Write-Host "        To enable: Settings > System > Optional Features > Windows Sandbox" -ForegroundColor Yellow
    Write-Host "        (Full mode requires Windows Sandbox or Docker)" -ForegroundColor Yellow
}

# Sysinternals (Procmon)
$procmon = "C:\temp\security-tools\Sysinternals\Procmon64.exe"
if (Test-Path $procmon) {
    Write-Host "        Sysinternals: found at C:\temp\security-tools\Sysinternals\" -ForegroundColor Green
} else {
    Write-Host "        Sysinternals: not found" -ForegroundColor Yellow
    Write-Host "        Download from https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite" -ForegroundColor Yellow
    Write-Host "        Extract to C:\temp\security-tools\Sysinternals\" -ForegroundColor Yellow
    Write-Host "        (Required for process monitoring in Full mode)" -ForegroundColor Yellow
}

# ── Done ─────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Done. Restart Claude Code if it is already running." -ForegroundColor Green
Write-Host ""
Write-Host "  Quick start:" -ForegroundColor Cyan
Write-Host "    /canary https://github.com/someuser/somerepo   (Quick/Medium — works now)"
Write-Host "    /canary https://github.com/someuser/somerepo   (Full — requires Windows Sandbox + Sysinternals)"
Write-Host ""
