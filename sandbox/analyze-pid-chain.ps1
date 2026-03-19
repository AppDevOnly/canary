# analyze-pid-chain.ps1
#
# Exports a Procmon .pml capture to CSV, then reconstructs the full process
# ancestry chain for every network connection made during the run.
#
# Why this matters: a destination IP/domain in the network log tells you WHERE
# something connected. The PID chain tells you WHO — and whether it was the
# expected process or something spawned several layers deep that you didn't
# anticipate. Process injection, unexpected child processes, and living-off-the-land
# attacks all become visible here even if the destination looked benign.
#
# Usage:
#   .\analyze-pid-chain.ps1 -PmlFile C:\sandbox\output\procmon-internal-<ts>.pml
#   .\analyze-pid-chain.ps1 -PmlFile C:\sandbox\output\procmon-host-<ts>.pml

param(
    [Parameter(Mandatory)][string]$PmlFile,
    [string]$ProcmonExe = 'C:\temp\security-tools\Sysinternals\Procmon64.exe',
    [string]$ReportFile  = ''   # Optional: write findings to this path in addition to console
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $PmlFile))  { Write-Error "PML file not found: $PmlFile"; exit 1 }
if (-not (Test-Path $ProcmonExe)) { Write-Error "Procmon not found: $ProcmonExe"; exit 1 }

$OutputDir = Split-Path $PmlFile
$BaseName  = [System.IO.Path]::GetFileNameWithoutExtension($PmlFile)
$CsvFile   = Join-Path $OutputDir "$BaseName.csv"
if (-not $ReportFile) { $ReportFile = Join-Path $OutputDir "$BaseName-pid-chain-report.txt" }

# ── 1. Export PML → CSV ────────────────────────────────────────────────────────

Write-Host "Exporting $PmlFile -> $CsvFile ..." -ForegroundColor Cyan
Write-Host "(This can take a minute for large captures)" -ForegroundColor Gray

# Procmon closes itself after export when /quiet is used
$proc = Start-Process $ProcmonExe -ArgumentList "/openlog `"$PmlFile`" /saveas `"$CsvFile`" /quiet" -PassThru -Wait
if (-not (Test-Path $CsvFile)) {
    Write-Error "CSV export failed — check that Procmon can open the file and the output path is writable"
    exit 1
}
Write-Host "Exported. Parsing..." -ForegroundColor Cyan

# ── 2. Parse CSV ───────────────────────────────────────────────────────────────

$events = Import-Csv $CsvFile
Write-Host "Loaded $($events.Count) events." -ForegroundColor Gray

# ── 3. Build PID → ancestry map from Process Start / Create events ────────────
# Procmon CSV columns of interest:
#   "Process Name", "PID", "Parent PID", "Command Line", "Operation", "Path", "Detail"
# Column names vary slightly by Procmon version — handle both.

$pidInfo = @{}   # PID (int) → @{ Name; ParentPid; CmdLine }

$events | Where-Object {
    $_.Operation -in @('Process Start','Process Create') -or
    ($_.Operation -eq 'Load Image' -and $_.'Process Name' -ne '')
} | ForEach-Object {
    $p = [int]$_.PID
    if (-not $pidInfo.ContainsKey($p)) {
        $parentCol = if ($_.PSObject.Properties.Name -contains 'Parent PID') { [int]$_.'Parent PID' } else { 0 }
        $cmdCol    = if ($_.PSObject.Properties.Name -contains 'Command Line') { $_.'Command Line' } else { '' }
        $pidInfo[$p] = @{
            Name      = $_.'Process Name'
            ParentPid = $parentCol
            CmdLine   = $cmdCol
        }
    }
}

# Also seed from ALL events so we at least have Name for any PID that appears
$events | ForEach-Object {
    $p = [int]$_.PID
    if (-not $pidInfo.ContainsKey($p)) {
        $pidInfo[$p] = @{ Name = $_.'Process Name'; ParentPid = 0; CmdLine = '' }
    }
}

# ── 4. Walk ancestry chain ────────────────────────────────────────────────────

function Get-Ancestors {
    param([int]$Pid, [int]$MaxDepth = 12)
    $chain = [System.Collections.Generic.List[string]]::new()
    $visited = [System.Collections.Generic.HashSet[int]]::new()
    $cur = $Pid
    while ($cur -ne 0 -and -not $visited.Contains($cur) -and $chain.Count -lt $MaxDepth) {
        $null = $visited.Add($cur)
        if ($pidInfo.ContainsKey($cur)) {
            $info = $pidInfo[$cur]
            $label = "$($info.Name) (PID $cur)"
            if ($info.CmdLine -and $info.CmdLine -ne $info.Name) {
                # Truncate very long command lines
                $cmd = if ($info.CmdLine.Length -gt 120) { $info.CmdLine.Substring(0,117) + '...' } else { $info.CmdLine }
                $label += " [`"$cmd`"]"
            }
            $chain.Insert(0, $label)
            $cur = $info.ParentPid
        } else {
            $chain.Insert(0, "UNKNOWN (PID $cur)")
            break
        }
    }
    return $chain
}

# ── 5. Find all network events ────────────────────────────────────────────────

$netEvents = $events | Where-Object {
    $_.Operation -match 'TCP|UDP|Network Connect|Network Reconnect|Network Send|Network Receive' -or
    ($_.Operation -match 'TCP' -and $_.'Path' -match '\d+\.\d+')
}

Write-Host "Found $($netEvents.Count) network events across $($netEvents | Select-Object -ExpandProperty PID -Unique | Measure-Object | Select-Object -ExpandProperty Count) distinct PIDs." -ForegroundColor Cyan

# ── 6. Group by PID + remote endpoint, build report ──────────────────────────

$output = [System.Text.StringBuilder]::new()
$null = $output.AppendLine("=== PID Chain Analysis: $BaseName ===")
$null = $output.AppendLine("Generated: $(Get-Date)")
$null = $output.AppendLine("Source: $PmlFile")
$null = $output.AppendLine("")

# Flag suspicious parent-child patterns
$suspiciousParents = @('word.exe','excel.exe','outlook.exe','winword.exe','powerpnt.exe',
                       'acrobat.exe','acrord32.exe','notepad.exe','mspaint.exe','explorer.exe',
                       'svchost.exe','lsass.exe','services.exe','winlogon.exe')
$suspiciousChildren = @('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe',
                        'mshta.exe','rundll32.exe','regsvr32.exe','certutil.exe','bitsadmin.exe',
                        'net.exe','net1.exe','whoami.exe','ipconfig.exe','nslookup.exe')

$grouped = $netEvents | Group-Object {
    $p = [int]$_.PID
    $name = if ($pidInfo.ContainsKey($p)) { $pidInfo[$p].Name } else { 'UNKNOWN' }
    "$name|$p|$($_.Path -replace ':\d+$','')"   # group by process+dest, strip port
}

$findings = @()

foreach ($g in ($grouped | Sort-Object { ($_ | Select-Object -ExpandProperty Group)[0].'Process Name' })) {
    $sample = $g.Group[0]
    $pid    = [int]$sample.PID
    $dest   = $sample.Path
    $ops    = ($g.Group | Select-Object -ExpandProperty Operation | Sort-Object -Unique) -join ', '
    $count  = $g.Count
    $chain  = Get-Ancestors -Pid $pid

    # Detect suspicious patterns
    $flags = @()
    $chainNames = $chain -replace ' \(PID \d+\).*','' | ForEach-Object { $_.ToLower() }
    foreach ($i in 1..($chainNames.Count-1)) {
        $parent = $chainNames[$i-1]
        $child  = $chainNames[$i]
        if ($suspiciousParents -contains $parent -and $suspiciousChildren -contains $child) {
            $flags += "⚠ SUSPICIOUS: $parent spawned $child"
        }
    }
    # Flag if network-connecting process itself is in suspicious list
    $connProc = ($chainNames | Select-Object -Last 1)
    if ($suspiciousChildren -contains $connProc -and $chainNames.Count -gt 1) {
        $flags += "⚠ REVIEW: $connProc is making network connections"
    }

    $block = [System.Text.StringBuilder]::new()
    $null = $block.AppendLine("Destination : $dest")
    $null = $block.AppendLine("Operations  : $ops ($count events)")
    $null = $block.AppendLine("Chain       : $($chain -join ' -> ')")
    if ($flags) {
        foreach ($f in $flags) { $null = $block.AppendLine("FLAG        : $f") }
    }
    $null = $block.AppendLine("")

    $null = $output.Append($block.ToString())
    $findings += [PSCustomObject]@{
        Destination = $dest
        ProcessChain = $chain -join ' -> '
        EventCount  = $count
        Flags       = $flags -join '; '
        Block       = $block.ToString()
    }
}

# ── 7. Summary ────────────────────────────────────────────────────────────────

$flagged = $findings | Where-Object { $_.Flags }
$null = $output.AppendLine("=== Summary ===")
$null = $output.AppendLine("Total network events   : $($netEvents.Count)")
$null = $output.AppendLine("Unique destination+proc: $($findings.Count)")
$null = $output.AppendLine("Flagged for review     : $($flagged.Count)")
if ($flagged) {
    $null = $output.AppendLine("")
    $null = $output.AppendLine("--- Flagged items ---")
    foreach ($f in $flagged) {
        $null = $output.AppendLine("  $($f.Destination)  |  $($f.Flags)")
        $null = $output.AppendLine("  $($f.ProcessChain)")
        $null = $output.AppendLine("")
    }
}

# ── 8. Output ─────────────────────────────────────────────────────────────────

$report = $output.ToString()
$report | Out-File $ReportFile -Encoding UTF8

# Print to console with color
foreach ($line in $report -split "`n") {
    if ($line -match '^FLAG|^⚠')        { Write-Host $line -ForegroundColor Red }
    elseif ($line -match '^Destination') { Write-Host $line -ForegroundColor Yellow }
    elseif ($line -match '^Chain')       { Write-Host $line -ForegroundColor Cyan }
    elseif ($line -match '^===')         { Write-Host $line -ForegroundColor Green }
    else                                 { Write-Host $line }
}

Write-Host ""
Write-Host "Report saved to: $ReportFile" -ForegroundColor Green
