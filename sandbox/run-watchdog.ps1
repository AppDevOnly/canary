# run-watchdog.ps1
# Self-healing sandbox launcher with real-time log streaming.
# Replaces start-monitors.ps1 as the single entry point for a test run.
# - Takes Autoruns baseline before sandbox launch
# - Starts Procmon + tshark on host (Wi-Fi interface detected dynamically)
# - Launches sandbox
# - Streams setup.log and pipeline.log to stream.log in real time
# - Detects stalls and mapped-folder failures, kills and restarts
# - Takes Autoruns after-snapshot at teardown for persistence diff
# - Up to $MaxRetries attempts before giving up

param(
    [int]$MaxRetries        = 2,
    [int]$SetupTimeoutSec   = 60,    # Max wait for setup.log to appear after sandbox launch
    [int]$StallTimeoutSec   = 90,    # Max silence before declaring a stall mid-run
    [string]$WsbFile        = 'C:\sandbox\sandbox.wsb',  # Path to the .wsb config for this run
    [switch]$SkipClean,              # Preserve previous pcap/procmon files
    [switch]$Interactive             # Keep streaming after pipeline completes (for interactive sessions)
)

$ErrorActionPreference = 'Continue'
$OutputDir    = 'C:\sandbox\output'
$StreamLog    = "$OutputDir\stream.log"
$ProcmonExe   = 'C:\temp\security-tools\Sysinternals\Procmon64.exe'
$AutorunsExe  = 'C:\temp\security-tools\Sysinternals\autorunsc64.exe'
$TsharkExe    = 'C:\Program Files\Wireshark\tshark.exe'

# ── Helpers ────────────────────────────────────────────────────────────────────

function Log {
    param([string]$msg, [string]$src = 'watchdog', [string]$color = 'Cyan')
    $line = "[$(Get-Date -Format 'HH:mm:ss')] [$src] $msg"
    Write-Host $line -ForegroundColor $color
    $line | Out-File $StreamLog -Append -Encoding UTF8
}

function Stop-Sandbox {
    Log 'Stopping sandbox processes...' 'watchdog' 'Yellow'

    Get-Process -Name 'WindowsSandboxServer','WindowsSandboxRemoteSession','WindowsSandboxClient' `
        -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 3
    $stubborn = Get-Process -Name 'WindowsSandboxServer','WindowsSandboxRemoteSession','WindowsSandboxClient' `
        -ErrorAction SilentlyContinue
    if ($stubborn) {
        Log 'Processes still alive after Stop-Process — force-killing via taskkill...' 'watchdog' 'Yellow'
        $stubborn | ForEach-Object { taskkill /F /PID $_.Id 2>$null }
        Start-Sleep -Seconds 3
    }

    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Process vmmemWindowsSandbox -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Seconds 2
    }
    if (Get-Process vmmemWindowsSandbox -ErrorAction SilentlyContinue) {
        Log 'WARNING: vmmemWindowsSandbox still present after timeout — proceeding anyway.' 'watchdog' 'Yellow'
    }

    Log 'Sandbox stopped.' 'watchdog' 'Yellow'
}

function Stop-Monitors {
    Log 'Stopping monitors (tshark, Procmon)...' 'watchdog' 'Yellow'
    Get-Process tshark, Procmon64 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

function Get-TsharkWifiInterface {
    # Detect Wi-Fi interface number dynamically — do not hardcode
    $ifaces = & $TsharkExe -D 2>&1
    # Try common Wi-Fi adapter name patterns
    $wifi = $ifaces | Select-String -Pattern 'Wi-Fi|WiFi|Wireless|wlan|802\.11' | Select-Object -First 1
    if ($wifi) {
        $ifNum = ($wifi.ToString() -split '\.')[0].Trim()
        Log "Detected Wi-Fi interface: $ifNum ($($wifi.ToString().Trim()))" 'watchdog' 'Green'
        return $ifNum
    }
    # Fallback: list all interfaces so the user can see what's available
    Log 'WARNING: Could not auto-detect Wi-Fi interface. Available interfaces:' 'watchdog' 'Yellow'
    $ifaces | ForEach-Object { Log "  $_" 'watchdog' 'Yellow' }
    Log 'Skipping Wi-Fi capture. vSwitch capture will still run.' 'watchdog' 'Yellow'
    return $null
}

function Start-Monitors {
    param([string]$ts)

    # Procmon (host-side, timestamped)
    $pml = "$OutputDir\procmon-host-$ts.pml"
    Start-Process $ProcmonExe -ArgumentList "/accepteula /quiet /minimized /backingfile $pml" -WindowStyle Minimized
    Log "Procmon -> $pml" 'watchdog' 'Green'
    Start-Sleep -Seconds 2

    # tshark Wi-Fi — detect interface dynamically
    $wifiIf = Get-TsharkWifiInterface
    if ($wifiIf) {
        Start-Process $TsharkExe `
            -ArgumentList "-i $wifiIf -w $OutputDir\capture-wifi-$ts.pcapng -b duration:300 -b files:3" `
            -WindowStyle Hidden -RedirectStandardError "$OutputDir\tshark-err.log"
        Start-Process $TsharkExe `
            -ArgumentList "-i $wifiIf -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e tcp.dstport -Y `"dns or tcp.flags.syn==1`" -E separator=| -l" `
            -WindowStyle Hidden `
            -RedirectStandardOutput "$OutputDir\network.log" `
            -RedirectStandardError  "$OutputDir\network-err.log"
        Log 'tshark Wi-Fi started.' 'watchdog' 'Green'
    }
}

function Start-Sandbox-And-VSwitch {
    param([string]$ts)

    $existing = Get-Process -Name 'WindowsSandboxRemoteSession','WindowsSandboxClient','WindowsSandboxServer' -ErrorAction SilentlyContinue
    if ($existing) {
        Log 'ERROR: Existing sandbox instance detected. Stopping it first.' 'watchdog' 'Red'
        Stop-Sandbox
    }

    Log 'Launching sandbox...' 'watchdog' 'Green'
    Start-Process $WsbFile

    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        if (Get-Process -Name 'WindowsSandboxRemoteSession','WindowsSandboxClient' -ErrorAction SilentlyContinue) { break }
        Start-Sleep -Seconds 2
    }

    Log 'Waiting for sandbox NIC...' 'watchdog'
    $deadline = (Get-Date).AddSeconds(60)
    $nicUp = $false
    while ((Get-Date) -lt $deadline) {
        $nic = Get-NetAdapter -Name 'vEthernet (Default Switch)' -ErrorAction SilentlyContinue
        if ($nic -and $nic.Status -eq 'Up') { $nicUp = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $nicUp) { Log 'WARNING: vEthernet (Default Switch) not Up after 60s' 'watchdog' 'Yellow' }
    Start-Sleep -Seconds 3

    # tshark vSwitch — detect interface number dynamically
    $ifaces = & $TsharkExe -D 2>&1
    $vs = $ifaces | Select-String 'Default Switch'
    if ($vs) {
        $ifNum = ($vs.ToString() -split '\.')[0].Trim()
        Start-Process $TsharkExe `
            -ArgumentList "-i $ifNum -w $OutputDir\capture-vswitch-$ts.pcapng -b duration:300 -b files:3" `
            -WindowStyle Hidden -RedirectStandardError "$OutputDir\tshark-vswitch-err.log"
        Start-Process $TsharkExe `
            -ArgumentList "-i $ifNum -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e tcp.dstport -Y `"dns or tcp.flags.syn==1`" -E separator=| -l" `
            -WindowStyle Hidden `
            -RedirectStandardOutput "$OutputDir\network-vswitch.log" `
            -RedirectStandardError  "$OutputDir\network-vswitch-err.log"
        Log "vSwitch tshark started on interface $ifNum." 'watchdog' 'Green'
    } else {
        Log 'WARNING: Default Switch interface not found in tshark -D. vSwitch capture skipped.' 'watchdog' 'Yellow'
    }
}

function Take-AutorunsSnapshot {
    param([string]$OutFile)
    if (Test-Path $AutorunsExe) {
        Log "Taking Autoruns snapshot -> $OutFile" 'watchdog' 'Cyan'
        & $AutorunsExe /accepteula '-a' '*' -c -h -s -nobanner -o $OutFile '*'
        Log 'Autoruns snapshot complete.' 'watchdog' 'Green'
    } else {
        Log "WARNING: autorunsc64.exe not found at $AutorunsExe — persistence detection skipped." 'watchdog' 'Yellow'
    }
}

# ── Single-instance guard ───────────────────────────────────────────────────────

$PidFile = "$OutputDir\watchdog.pid"

if (Test-Path $PidFile) {
    $oldPid = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($oldPid) {
        $oldProc = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
        if ($oldProc) {
            Write-Host "[watchdog] WARNING: Another watchdog instance (PID $oldPid) is running. Killing it first." -ForegroundColor Yellow
            Stop-Process -Id $oldPid -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

$PID | Out-File $PidFile -Encoding UTF8 -Force

$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

# ── Clean output dir ────────────────────────────────────────────────────────────

if (-not $SkipClean) {
    Write-Host 'Clearing previous run logs...' -ForegroundColor Cyan
    'setup.log','pipeline.log','pipeline-realtime.log','done.sentinel','network.log','network-vswitch.log',
    'network-err.log','network-vswitch-err.log','tshark-err.log','tshark-vswitch-err.log','stream.log' |
        ForEach-Object { Remove-Item "$OutputDir\$_" -ErrorAction SilentlyContinue }
    Get-ChildItem $OutputDir -Filter 'capture*.pcapng' | Remove-Item -ErrorAction SilentlyContinue
}

"=== Watchdog started at $(Get-Date) ===" | Out-File $StreamLog -Encoding UTF8

# ── Autoruns baseline ───────────────────────────────────────────────────────────

Take-AutorunsSnapshot -OutFile "$OutputDir\autoruns-before.csv"

# ── Main retry loop ─────────────────────────────────────────────────────────────

$success = $false

for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
    Log "=== Attempt $attempt of $MaxRetries ===" 'watchdog' 'Magenta'

    if ($attempt -gt 1) {
        Log "The sandbox stopped responding — restarting automatically. Attempt $attempt of $MaxRetries. Everything collected so far is preserved." 'watchdog' 'Yellow'
    }

    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'

    if ($attempt -gt 1) {
        'setup.log','pipeline.log','done.sentinel' | ForEach-Object { Remove-Item "$OutputDir\$_" -ErrorAction SilentlyContinue }
    }

    Stop-Monitors
    if ($attempt -gt 1) { Stop-Sandbox; Start-Sleep -Seconds 5 }

    Start-Monitors -ts $ts
    Start-Sandbox-And-VSwitch -ts $ts

    # ── Phase 1: wait for setup.log ─────────────────────────────────────────────
    Log "Waiting up to ${SetupTimeoutSec}s for sandbox to initialize..." 'watchdog'
    $deadline = (Get-Date).AddSeconds($SetupTimeoutSec)
    $setupFound = $false
    while ((Get-Date) -lt $deadline) {
        if (Test-Path "$OutputDir\setup.log") { $setupFound = $true; break }
        if (-not (Get-Process -Name 'WindowsSandboxServer' -ErrorAction SilentlyContinue)) {
            Log 'Sandbox exited before setup.log appeared (mapped-folder failure?).' 'watchdog' 'Red'
            break
        }
        Start-Sleep -Seconds 3
    }

    if (-not $setupFound) {
        Log "Sandbox did not initialize within ${SetupTimeoutSec}s. Restarting..." 'watchdog' 'Red'
        continue
    }

    Log 'Sandbox initialized — streaming output...' 'watchdog' 'Green'

    # ── Phase 2: stream logs until done or stall ────────────────────────────────
    $setupPos              = 0
    $pipelinePos           = 0
    $pipelineRunCount      = 0
    $lastUpdate            = Get-Date

    while ($true) {
        $sbAlive = [bool](Get-Process -Name 'WindowsSandboxServer','WindowsSandboxRemoteSession' -ErrorAction SilentlyContinue)

        if (Test-Path "$OutputDir\setup.log") {
            $lines = Get-Content "$OutputDir\setup.log" -ErrorAction SilentlyContinue
            if ($lines -and $lines.Count -gt $setupPos) {
                $lines[$setupPos..($lines.Count - 1)] | ForEach-Object { Log $_ 'setup' 'White' }
                $setupPos   = $lines.Count
                $lastUpdate = Get-Date
            }
        }

        $pipelineFile = if (Test-Path "$OutputDir\pipeline-realtime.log") {
            "$OutputDir\pipeline-realtime.log"
        } else {
            "$OutputDir\pipeline.log"
        }
        if (Test-Path $pipelineFile) {
            $lines = Get-Content $pipelineFile -ErrorAction SilentlyContinue
            if ($lines -and $lines.Count -gt $pipelinePos) {
                $lines[$pipelinePos..($lines.Count - 1)] | ForEach-Object { Log $_ 'pipeline' 'White' }
                $pipelinePos = $lines.Count
                $lastUpdate  = Get-Date
            }
        }

        if (Test-Path "$OutputDir\done.sentinel") {
            $pipelineRunCount++
            if ($Interactive) {
                Log "=== Pipeline run #$pipelineRunCount complete (sentinel). Interactive mode: continuing to stream until sandbox closes. ===" 'watchdog' 'Green'
                Remove-Item "$OutputDir\done.sentinel" -Force -ErrorAction SilentlyContinue
                $lastUpdate = Get-Date
            } else {
                Log "=== Pipeline complete — run successful. ===" 'watchdog' 'Green'
                $success = $true
                break
            }
        }

        if (-not $sbAlive -and $pipelinePos -gt 0) {
            Log '=== Sandbox exited — session complete. ===' 'watchdog' 'Green'
            $success = $true
            break
        }

        $silenceSec = ((Get-Date) - $lastUpdate).TotalSeconds
        if ($silenceSec -gt $StallTimeoutSec -and $pipelinePos -eq 0) {
            Log "STALL: no log activity for $([int]$silenceSec)s and pipeline never started. Restarting..." 'watchdog' 'Red'
            break
        }

        Start-Sleep -Seconds 2
    }

    if ($success) { break }
}

# ── Teardown ────────────────────────────────────────────────────────────────────

Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
Stop-Monitors

# ── Autoruns after-snapshot ─────────────────────────────────────────────────────

Take-AutorunsSnapshot -OutFile "$OutputDir\autoruns-after.csv"

# ── Procmon cleanup — keep only the 3 most recent .pml files ───────────────────

$allPml = Get-ChildItem $OutputDir -Filter '*.pml' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending
if ($allPml.Count -gt 3) {
    $toDelete = $allPml | Select-Object -Skip 3
    $toDelete | ForEach-Object {
        Log "Cleaning up old procmon file: $($_.Name) ($([math]::Round($_.Length/1GB,1)) GB)" 'watchdog' 'Cyan'
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    }
}

if ($success) {
    Log '=== All done. Review stream.log, network logs, and pcap files. ===' 'watchdog' 'Green'
} else {
    Log "=== Watchdog exhausted $MaxRetries attempts without success. ===" 'watchdog' 'Red'
    Log 'Check stream.log for details. The static analysis report is still valid.' 'watchdog' 'Red'
}

Write-Host ''
Write-Host 'Output: C:\sandbox\output\' -ForegroundColor Cyan
Read-Host 'Press Enter to close'
