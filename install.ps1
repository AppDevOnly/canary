# Canary installer for PowerShell (Windows)
# Usage: irm https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 | iex

$SkillUrl    = "https://raw.githubusercontent.com/AppDevOnly/canary/main/canary.md"
$CommandsDir = "$env:USERPROFILE\.claude\commands"
$Dest        = "$CommandsDir\canary.md"

Write-Host ""
Write-Host "  Canary installer" -ForegroundColor Cyan
Write-Host "  ─────────────────────────" -ForegroundColor Cyan
Write-Host ""

# Check for Claude Code
if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
    Write-Host "  ERROR: Claude Code not found." -ForegroundColor Red
    Write-Host "         Install it first: https://github.com/anthropics/claude-code" -ForegroundColor Red
    Write-Host ""
    exit 1
}

# Create commands dir if needed
if (-not (Test-Path $CommandsDir)) {
    New-Item -ItemType Directory -Path $CommandsDir -Force | Out-Null
}

# Download skill
Write-Host "  Downloading canary.md..."
try {
    Invoke-WebRequest -Uri $SkillUrl -OutFile $Dest -UseBasicParsing
} catch {
    Write-Host "  ERROR: Download failed — $_" -ForegroundColor Red
    exit 1
}

Write-Host "  Installed to $Dest" -ForegroundColor Green
Write-Host ""
Write-Host "  Usage in Claude Code:" -ForegroundColor Cyan
Write-Host "    /canary https://github.com/someuser/somerepo"
Write-Host "    /canary C:\projects\my-app"
Write-Host "    /canary pip:requests"
Write-Host "    /canary npm:lodash"
Write-Host ""
Write-Host "  Restart Claude Code if it is already running, then try /canary." -ForegroundColor Cyan
Write-Host ""
