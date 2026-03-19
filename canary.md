---
description: Evaluate code for security issues, dependency vulnerabilities, bugs, and quality problems before installing
version: 2.5
---

# /canary
# canary-version: 2.5

Evaluate code before you trust it. Canary reads source code, checks for security issues, scans for known vulnerabilities, and can run the code in an isolated sandbox — then gives you a plain-English verdict.

## Usage
```
/canary <target>
/canary update
```
Where `<target>` is a GitHub URL, local path, `pip:<package>`, or `npm:<package>`.

**`/canary update`** — checks your installed version against the repo and reinstalls if behind.

---

## Self-update

If the user types `update` (or `/canary update`) with no target:

1. Read the local skill file version from the `# canary-version:` line
2. Fetch the remote version:
```bash
gh api repos/AppDevOnly/canary/contents/canary.md --jq '.content' | base64 -d | grep "canary-version"
```
3. Compare. If behind (or if the user just wants a clean reinstall), run:
```powershell
irm https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 | iex
```
4. Tell the user what was updated and remind them to restart Claude Code to pick up the new skill file.

If already up to date, say so and stop — don't reinstall unnecessarily.

---

## Tool availability

**Always use `gh api <endpoint> --jq '<filter>'` for GitHub API calls and JSON parsing.** Do not use standalone `jq`, `python3`, or `python` for JSON parsing — they are not reliably available on Windows. If you need to parse JSON outside of a `gh api` call, use `grep` or string matching instead.

### Tools by scan level

Quick needs almost nothing. Medium needs the static analysis toolkit. Full needs everything.

```
Tool                  Quick        Medium            Full
────────────────────  ───────────  ────────────────  ──────────────────
gh + gh auth login    GitHub only  GitHub only       required
pip / Python          —            for pip installs  required
winget (Windows)      —            for some installs required
semgrep               —            required          required
bandit                —            Python projects   Python projects
trufflehog            —            required          required
gitleaks              —            required          required
pip-audit             —            Python projects   Python projects
npm / npm audit       —            Node projects     Node projects
Admin rights          —            —                 required
Windows Sandbox       —            —                 required
Sysinternals Suite    —            —                 required
tshark / Wireshark    —            —                 required
Canary sandbox scripts—            —                 required
Docker                —            —                 fallback (Linux/Mac)
```

### Install commands

```
gh:           winget install GitHub.cli            (Windows)
              brew install gh                       (Mac/Linux)
semgrep:      pip install semgrep
bandit:       pip install bandit
trufflehog:   winget install trufflesecurity.trufflehog  (Windows)
              brew install trufflehog               (Mac)
gitleaks:     winget install gitleaks              (Windows)
              brew install gitleaks                 (Mac)
pip-audit:    pip install pip-audit
npm:          Install Node.js from https://nodejs.org
tshark:       winget install WiresharkFoundation.Wireshark
Sysinternals: Download suite from https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite
              Extract to C:\temp\security-tools\Sysinternals\
Windows Sandbox: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
              (requires reboot)
Docker:       winget install Docker.DockerDesktop
```

### Tool install behavior

No tool is ever skipped silently. When a tool is missing, tell the user exactly what it is, what it's needed for, and offer to install it. If the user declines, note it as a limitation in the report. Never proceed assuming a tool is there when you haven't checked.

---

## Phase 0 — Resume check

Before doing anything else, check for an existing partial scan of this target.

Derive a target slug from the target string:
- `https://github.com/foo/bar` → `github-foo-bar`
- `/path/to/project` → last folder name, e.g. `local-project`
- `pip:requests` → `pip-requests`
- `npm:lodash` → `npm-lodash`

Check for a state file:
```powershell
$stateFile = "$HOME\canary-reports\$targetSlug-state.json"
Test-Path $stateFile
```

If a state file exists, read it and tell the user:
> "I found a partial [level] scan of [target] from [date]. Here's what's already complete: [list phases done]. Want to resume from where we left off, or start fresh?"

- **Resume** — load existing findings from state file, skip completed phases, continue from next incomplete phase
- **Fresh** — delete state file, start over from Phase 1

If no state file exists, proceed normally.

---

## Phase 1 — Identify the target

Parse `<target>`:
- **GitHub URL** → fetch repo contents via GitHub API (no clone needed for static analysis)
- **Local path** → read files directly
- **`pip:<name>`** → fetch from PyPI: source tarball or wheel, read metadata + scripts
- **`npm:<name>`** → fetch from npmjs: read package.json, scripts, index

If no target is provided, ask the user what they'd like to evaluate and explain the supported formats.

**Tell the user:**

> "Canary v2.5
>
> Everything I do during this evaluation is [Claude] — I'm fetching and reading code on your behalf using the GitHub API and other tools. I won't run anything from this software on your machine unless you choose Full mode, in which case those actions will be clearly labeled [software under test] and I'll confirm with you before running anything."

Then ask:

> "How thorough should I be?
>
> - **Quick** — I'll read the most important files (entry points, install scripts, anything that runs at startup) and look for red flags using my own analysis. No external tools needed. Takes about a minute.
> - **Medium** — I'll read the full codebase, run specialized scanning tools (semgrep, bandit, trufflehog, gitleaks), check all dependencies for known security vulnerabilities, and assess code quality. Takes a few minutes.
> - **Full** — Everything in Medium, plus I'll run it in an isolated sandbox and watch what it actually does (network connections, files touched, whether it tries to persist). Requires Windows Sandbox, Wireshark, and Sysinternals. If any of these aren't installed, I'll walk you through it."

**After the user chooses a tier, run dependency checks before doing anything else:**

### Dependency check — Quick

If the target is a GitHub URL:
```bash
gh --version 2>/dev/null && echo "OK" || echo "MISSING"
gh auth status 2>/dev/null && echo "OK" || echo "NOT LOGGED IN"
```

If `gh` is missing: offer to install via `winget install GitHub.cli` (Windows) or `brew install gh` (Mac/Linux). Verify before continuing.
If `gh auth` fails: guide through `gh auth login`. Wait for completion.
If target is a local path, pip package, or npm package: no tool check needed for Quick.

### Dependency check — Medium

Run all Quick checks first, then:

Check pip/Python (needed to install pip-based tools):
```bash
pip --version 2>/dev/null || pip3 --version 2>/dev/null || python -m pip --version 2>/dev/null
```

Check winget (Windows, needed for winget-based installs):
```powershell
winget --version 2>$null
```

Check all static analysis tools:
```bash
semgrep --version 2>/dev/null && echo "semgrep: OK" || echo "semgrep: MISSING"
bandit --version 2>/dev/null && echo "bandit: OK" || echo "bandit: MISSING"
trufflehog --version 2>/dev/null && echo "trufflehog: OK" || echo "trufflehog: MISSING"
gitleaks version 2>/dev/null && echo "gitleaks: OK" || echo "gitleaks: MISSING"
pip-audit --version 2>/dev/null && echo "pip-audit: OK" || echo "pip-audit: MISSING"
npm --version 2>/dev/null && echo "npm: OK" || echo "npm: MISSING"
```

Show a clean summary to the user before asking to install anything:

> "Here's what I found on your machine:
> ✅ semgrep
> ✅ bandit
> ⬜ trufflehog — not installed
> ⬜ gitleaks — not installed
> ✅ pip-audit
> ✅ npm
>
> I need to install trufflehog and gitleaks before I can start. Want me to do that now? It'll take about a minute each and I'll confirm each one works before moving on."

Install missing tools one at a time. Confirm each works before moving to the next.

If pip/Python is not available and a pip-based tool is missing:
> "I need Python/pip installed to set up [tool]. Is Python installed on your machine? If it is, try opening a new terminal and running `pip --version`. If Python isn't installed yet, I can walk you through installing it first."

If winget is not available and a winget-based tool is missing:
> "winget isn't available on this machine. I can walk you through installing [tool] manually — want me to do that?"

If the user declines any tool: note it as a limitation. Never skip silently — always record what was skipped and why.

### Dependency check — Full

Run all Medium checks first, then:

Check admin rights (required for Procmon, tshark, SAC registry):
```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```
If not admin:
> "Full mode needs administrator rights to run Procmon, tshark, and modify system settings. Please restart Claude Code as Administrator (right-click → Run as administrator) and try again."
Stop here — do not proceed without admin rights.

Check Windows Sandbox:
```powershell
(Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -ErrorAction SilentlyContinue).State
```
If not Enabled:
> "Windows Sandbox isn't enabled on this machine. I can enable it for you — it requires a reboot after. Want me to do that now?"
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
```
After reboot, re-run the installer and continue.

Check Sysinternals:
```powershell
Test-Path 'C:\temp\security-tools\Sysinternals\Procmon64.exe'
Test-Path 'C:\temp\security-tools\Sysinternals\autorunsc64.exe'
```
If missing:
> "Sysinternals isn't installed at the expected path. Download the Sysinternals Suite from https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite and extract it to `C:\temp\security-tools\Sysinternals\`. Let me know when that's done and I'll continue."

Check tshark:
```bash
tshark --version 2>/dev/null && echo "OK" || echo "MISSING"
```
If missing: offer `winget install WiresharkFoundation.Wireshark`. Verify after.

Check sandbox scripts:
```powershell
Test-Path 'C:\sandbox\scripts\run-watchdog.ps1'
```
If missing:
> "The canary sandbox infrastructure isn't installed yet. Running the installer now..."
```powershell
irm https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 | iex
```

**Do not present the consent block until all required tools are confirmed present or the user has explicitly declined specific ones.**

**After all checks pass, present the consent block tailored to the chosen tier:**

> "Here's everything I'll do during this [Quick / Medium / Full] evaluation — I'll ask once and then run without interruptions.
>
> **[Claude] — all of this is me, not the software being evaluated:**
> - Fetch repo metadata and file tree from GitHub API
> - Read source files directly from GitHub (no download to your machine)
> - Search for secrets, hardcoded credentials, and suspicious patterns in the code
> *(Medium + Full only)* Run `semgrep`, `bandit`, `trufflehog`, and `gitleaks` on your machine for deeper static analysis
> *(Medium + Full only)* Run `pip-audit` and/or `npm audit` to check dependencies for known CVEs
> - Write a report to `~/canary-reports/`
> - Save scan progress after each step so you can resume if anything interrupts
>
> *(Full only)* **[software under test] — this is the code running on your machine:**
> - Download the target release binary to a temporary folder
> - Launch Windows Sandbox (or Docker) and run the software inside it
> - Observe what network connections it makes, what files it creates, whether it tries to persist
> - Sandbox is destroyed after evaluation — nothing persists to your main system
>
> Ready to proceed?"

Wait for a yes before starting. Do not ask for permission again during the evaluation unless a genuinely unexpected action comes up.

**After consent, initialize scan state:**

Write a state file to track progress:
```json
{
  "target": "<url or path>",
  "target_slug": "<slug>",
  "date": "<YYYY-MM-DD>",
  "level": "<Quick|Medium|Full>",
  "phases_complete": [],
  "findings_count": 0,
  "sac_original_state": null
}
```

Write to `~/canary-reports/<target-slug>-state.json`. Update this file after each phase completes by adding the phase name to `phases_complete`. This is how resume works after a restart.

---

## Phase 2 — Static security analysis

### 2a. Code inspection

**Progress:** Tell the user "Reading source files..." before starting. When done: "Source review complete — [N findings / no issues found]."

**Quick and above:** Read these files first (in order of risk):
1. Entry points: `__main__.py`, `main.py`, `index.js`, `cli.py`, `app.py`
2. Install/setup scripts: `setup.py`, `pyproject.toml`, `package.json`, `Makefile`, `*.sh`, `*.ps1`
3. Any file with network calls, subprocess calls, or `eval()`/`exec()`

**Medium and above:** Read the full codebase, prioritizing files with network I/O, file I/O, subprocess calls, authentication, and data handling.

Flag these patterns (rate each CRITICAL / HIGH / MEDIUM / LOW / INFO):

- `eval()` / `exec()` on external input — **CRITICAL** (e.g. `eval(response.text)`)
- Subprocess with shell=True on external input — **CRITICAL**
- Writes to startup/autorun locations — **CRITICAL** (Registry Run keys, `~/.bashrc`, cron)
- Outbound connections to unexpected domains — **HIGH**
- `postinstall` / `prepare` scripts in package.json — **HIGH** (runs at install time, before review)
- Base64-encoded strings — **HIGH** (common obfuscation technique)
- Hardcoded IP addresses (non-localhost) — **HIGH**
- `os.system()` / `subprocess` calls — **MEDIUM** (may be legitimate; check args)
- `install_requires` with no version pins — **MEDIUM** (unpinned deps allow supply chain attacks)
- `__import__` / dynamic imports — **MEDIUM** (can obfuscate what's loaded)

Save state after 2a completes.

### 2b. Semgrep static analysis

**Medium and above only.**

**Progress:** "Running semgrep static analysis — this may take 30-60 seconds..." Every 30 seconds if still running: "Semgrep still running... [elapsed]s elapsed." When done: "Semgrep complete — [N findings / no findings]."

If semgrep is available, run against the local clone or downloaded source:
```bash
semgrep --config=auto --json 2>/dev/null | grep -i "severity\|message\|path\|line"
```

Focus on HIGH and CRITICAL findings. Skip INFO-level noise. If semgrep isn't available (user declined install), note it in the report and rely on manual code inspection.

Save state after 2b completes.

### 2c. Bandit (Python projects only)

**Medium and above only.**

**Progress:** "Running bandit Python security scan..." When done: "Bandit complete — [N findings / no findings]."

If the project is Python and bandit is available:
```bash
bandit -r . -f json 2>/dev/null | grep -i "issue_severity\|issue_text\|filename\|line_number"
```

Flag HIGH and MEDIUM severity findings. Cross-reference with manual code inspection — bandit has false positives.

Save state after 2c completes.

### 2d. Secrets scan

**Medium and above only.**

**Progress:** "Scanning git history for secrets..." When done: "Secrets scan complete — [N secrets found / no secrets found]."

If trufflehog is available, scan git history for secrets (catches things committed then deleted):
```bash
trufflehog git file://. --json 2>/dev/null | head -100
```

If gitleaks is available, run a fast secrets scan:
```bash
gitleaks detect --source . --report-format json 2>/dev/null | head -100
```

If neither is available, manually search for patterns:
- Long random strings adjacent to words: key, token, secret, password, api, auth
- AWS key patterns: `AKIA[0-9A-Z]{16}`
- Private key headers: `-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`
- Common service patterns: `sk-[a-zA-Z0-9]{32,}`, `ghp_[a-zA-Z0-9]{36}`

Report any matches with file + line number. Rate HIGH if found in committed source. Do NOT print the full value — show first 8 chars + `...`

Save state after 2d completes.

### 2e. Dependency audit

**Medium and above only.**

**Progress:** "Checking dependencies for known CVEs..." When done: "Dependency audit complete — [N vulnerabilities found / no CVEs found]."

**Python projects** — check `requirements.txt`, `pyproject.toml`, `setup.py`:
```bash
pip-audit -r requirements.txt --format json 2>/dev/null || echo "pip-audit not available"
```

**Node projects** — check `package.json`:
```bash
npm audit --json 2>/dev/null || echo "npm audit not available"
```

If audit tools aren't available, manually check top-level dependencies and flag any that are:
- More than 2 major versions behind latest
- Known to have had critical CVEs (e.g. `log4j`, `lodash < 4.17.21`, `requests < 2.20.0`)

Save state after 2e completes.

### 2f. License compliance

**Medium and above only.**

**Progress:** "Checking license compliance..." When done: "License check complete."

Summarize licenses used by direct dependencies. Flag:
- GPL/AGPL in commercial contexts — MEDIUM (may require source disclosure)
- Unknown/unlicensed packages — HIGH (legal risk)
- License mismatches (project claims MIT but depends on GPL)

Save state after 2f completes.

---

## Phase 3 — Code quality assessment

**Medium and above only.**

**Progress:** "Analyzing code quality..." When done: "Code quality assessment complete — [N findings]."

Rate each finding CRITICAL / HIGH / MEDIUM / LOW / INFO.

**Anti-patterns to flag:**
- Imports inside try/except blocks (obscures dependencies, hides silent failures)
- Bare `except:` without exception type (swallows all errors silently)
- Mutable default arguments (`def foo(x=[])`)
- `TODO`/`FIXME`/`HACK` comments in critical paths
- No test files present (`test_*.py`, `*.test.js`, `spec/`)
- Functions longer than 100 lines (complexity risk)
- Hardcoded file paths (portability issues)
- `print()` / `console.log()` used for error handling instead of logging

**Undocumented requirements check:**
- API keys referenced in code but not mentioned in README
- External services called but not documented
- System tools assumed present (Docker, pdflatex, ffmpeg, etc.) without install instructions
- Environment variables read without defaults or documentation

Save state after Phase 3 completes.

---

## Phase 4 — Dynamic sandbox (full mode only)

*Skip this phase if the user chose Quick or Medium, or if no sandbox is available.*

**Important:** Before running anything from the target, warn the user if static analysis already found serious issues (CRITICAL findings). Give them the option to stop here rather than run potentially hostile code even in a sandbox.

If Windows Sandbox is available:

**Autoruns baseline — run before launching the sandbox:**

```powershell
$autorunsExe = 'C:\temp\security-tools\Sysinternals\autorunsc64.exe'
if (Test-Path $autorunsExe) {
    Write-Host "Taking Autoruns baseline snapshot..."
    & $autorunsExe /accepteula '-a' '*' -c -h -s -nobanner -o 'C:\sandbox\output\autoruns-before.csv' '*'
    Write-Host "Autoruns baseline saved."
}
```

After the sandbox run, take a second snapshot and diff:

```powershell
Write-Host "Taking Autoruns after-snapshot..."
& $autorunsExe /accepteula '-a' '*' -c -h -s -nobanner -o 'C:\sandbox\output\autoruns-after.csv' '*'

# Show new entries (persistence attempts)
$before = Import-Csv 'C:\sandbox\output\autoruns-before.csv'
$after  = Import-Csv 'C:\sandbox\output\autoruns-after.csv'
Compare-Object $before $after -Property 'Image Path','Entry' |
    Where-Object { $_.SideIndicator -eq '=>' }
```

Flag any new entries as HIGH — they represent persistence the software attempted to install outside the sandbox.

**Pre-flight: check Smart App Control (SAC) state before launching.**

```powershell
$sacState = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
```

- `0` = Off — proceed normally
- `1` = Evaluation mode — will block unsigned binaries
- `2` = On — will block unsigned binaries
- `$null` = key not present — SAC not active, proceed normally

If SAC is 1 or 2, present this consent prompt before doing anything else:

> "To run this software in the sandbox, I need to temporarily disable Smart App Control on your machine.
>
> **What that means in plain English:** Smart App Control is a Windows security feature that blocks unsigned software from running. Disabling it means Windows will be slightly more permissive for a few minutes while the scan runs. This affects your whole machine, not just the sandbox.
>
> **Why it's still safe:** The software itself runs inside an isolated sandbox — it can't touch your files, your browser, or anything on your main system. I'm only disabling SAC so Windows will allow it to launch inside that container. Once the scan finishes, I'll re-enable it and show you exactly how to verify it's back on.
>
> **Your options:**
> - **Yes, proceed** — I'll disable SAC, run the scan, and re-enable it when done
> - **No, skip sandbox** — I'll write the report based on static analysis only and clearly note that runtime behavior wasn't observed
>
> What would you like to do?"

Wait for explicit confirmation before touching SAC. If the user says no, skip to Phase 5 and note in the Sandbox Results section: "User declined to disable Smart App Control. Runtime analysis was not performed. Results are based on static analysis only."

If the user says yes, disable SAC and **spawn a new PowerShell process** to pick up the change — the registry update only takes effect in a new session:

```powershell
# Disable SAC
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' `
    -Name VerifiedAndReputablePolicyState -Value 0 -Type DWord -Force

# Verify it took
$check = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy').VerifiedAndReputablePolicyState
Write-Host "SAC state now: $check (0 = Off)"
```

Record `$sacState` in the state file so it can be restored even if the session is interrupted. All sandbox launch commands must be run in a **new** PowerShell process (via `Start-Process powershell`) so the policy change is in effect.

After the sandbox run completes (success or failure), **always re-enable SAC** if it was active before:

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' `
    -Name VerifiedAndReputablePolicyState -Value $sacState -Type DWord -Force
Write-Host "Smart App Control restored to original state ($sacState)."
```

Then tell the user:

> "Smart App Control has been re-enabled. To verify: open Windows Security > App & browser control > Smart App Control. Or run: `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy').VerifiedAndReputablePolicyState` — it should return $sacState."

Before launching, warn the user:

> "I'm about to start the sandbox. Here's what to expect:
> - A Windows Sandbox window will open — this is normal. Don't close it.
> - Additional windows may appear as the software launches inside the sandbox.
> - **You don't need to interact with any of those windows.** Just keep an eye on this Claude window — I'll report everything I observe here as it happens.
> - When the evaluation is done, the sandbox will close automatically and I'll write the report.
> - **If anything looks wrong or gets stuck, just tell me in plain English** — describe what you're seeing and I'll figure out what to do. You don't need to know any commands."

**Before launching: verify sandbox infrastructure is installed.**

Check that `C:\sandbox\scripts\run-watchdog.ps1` exists. If it doesn't, tell the user:
> "The sandbox infrastructure isn't installed yet. Run the canary installer first:
> `irm https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 | iex`"

**Generate the target's .wsb config from the template:**

```powershell
# Read template
$template = Get-Content 'C:\sandbox\scripts\sandbox-template.wsb' -Raw

# Add Sysinternals mapped folder if present on host
$sysinternals = 'C:\temp\security-tools\Sysinternals'
if (Test-Path $sysinternals) {
    $block = @"
    <MappedFolder>
      <HostFolder>$sysinternals</HostFolder>
      <SandboxFolder>C:\tools\Sysinternals</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
"@
    $template = $template -replace '<!-- SYSINTERNALS_BLOCK -->', $block
} else {
    $template = $template -replace '<!-- SYSINTERNALS_BLOCK -->', ''
}

# Write target-specific .wsb
$wsbPath = "C:\sandbox\$targetName.wsb"
$template | Out-File $wsbPath -Encoding UTF8 -Force
```

**Generate `setup.ps1` for this target from the template:**

Read `C:\sandbox\scripts\setup-template.ps1`, fill in the placeholders, and write to `C:\sandbox\scripts\setup.ps1`:

- `{{TARGET_NAME}}` — friendly name (e.g. `shadPS4`)
- `{{TARGET_URL}}` — direct download URL for the release binary or zip. Find via GitHub releases API: `gh api repos/<owner>/<repo>/releases/latest --jq '.assets[] | select(.name | test("win.*64|x64.*win"; "i")) | .browser_download_url'`
- `{{BINARY_NAME}}` — exact filename of the exe (check release asset name or README)
- `{{EXTRACT_DIR}}` — extraction path inside sandbox (e.g. `C:\shadps4_local`)
- `{{LAUNCH_ARGS}}` — command line args if needed, empty string if none

```powershell
$template = Get-Content 'C:\sandbox\scripts\setup-template.ps1' -Raw
$template = $template -replace '{{TARGET_NAME}}',  $targetName
$template = $template -replace '{{TARGET_URL}}',   $targetUrl
$template = $template -replace '{{BINARY_NAME}}',  $binaryName
$template = $template -replace '{{EXTRACT_DIR}}',  $extractDir
$template = $template -replace '{{LAUNCH_ARGS}}',  $launchArgs
$template | Out-File 'C:\sandbox\scripts\setup.ps1' -Encoding UTF8 -Force
Write-Host "setup.ps1 generated for $targetName"
```

Then ask the user before launching:

> "Will you be interacting with the sandbox directly (clicking, typing commands), or should I run everything automatically and you just watch this window?"

- **Automated** (default) — stall timeout **90 seconds**. If the binary hasn't produced any log output in 90 seconds, the watchdog restarts automatically.
- **Interactive** — stall timeout **600 seconds** (10 minutes). Gives you time to interact with the software without the watchdog killing it.

```powershell
# Automated (default) — new process so SAC policy change is in effect
Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File C:\sandbox\scripts\run-watchdog.ps1 -WsbFile `"$wsbPath`" -StallTimeoutSec 90 -MaxRetries 2" -WindowStyle Normal

# Interactive
Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File C:\sandbox\scripts\run-watchdog.ps1 -WsbFile `"$wsbPath`" -StallTimeoutSec 600 -MaxRetries 2" -WindowStyle Normal
```

**While monitoring `C:\sandbox\output\stream.log`, give the user a heartbeat every 30 seconds:**
> "Still running — [elapsed]s. You'll see output here as it comes in. Nothing to do — just keep an eye on this window."

**When stream.log shows a retry attempt:**
Tell the user immediately:
> "The sandbox stopped responding — restarting automatically. Attempt [N] of 2. Everything we've found so far is saved."

**After the sandbox run, read `stream.log` and `setup.log` to determine outcome:**

- If `setup.log` contains `"RESULT: Binary could not be launched"` — **do not retry**. Record as a sandbox finding: "Binary blocked — likely SAC/WDAC policy or missing dependency. Dynamic analysis not possible on this system without further configuration." Proceed to write the report.
- If the sandbox exited before `setup.log` appeared (mapped-folder failure) — retry **once only**, then report the failure.
- If the binary launched successfully — run post-run analysis before writing the report.

**Post-run analysis (binary launched successfully):**

Unique DNS names queried by the sandbox:
```powershell
Get-Content C:\sandbox\output\network-vswitch.log |
    ForEach-Object { ($_ -split '\|')[3] } |
    Where-Object { $_ -and $_ -notmatch '^\d' -and $_ -notmatch 'arpa' } |
    Sort-Object -Unique
```

External IPs connected to:
```powershell
Get-Content C:\sandbox\output\network-vswitch.log |
    ForEach-Object {
        $p = $_ -split '\|'
        if ($p[1] -match '^172\.27\.' -and $p[4] -in @('443','80')) { $p[2] }
    } | Sort-Object -Unique
```

Separate Windows OS baseline traffic (WindowsUpdate, OCSP, licensing) from target-initiated connections. Flag any connections the target made to unexpected domains as HIGH.

**PID chain analysis** — the network log shows *where* connections went; the PID chain shows *who made them*. This catches process injection, LOL-bins, and unexpected child process spawning.

If `analyze-pid-chain.ps1` is available at `C:\sandbox\scripts\`:
```powershell
powershell -ExecutionPolicy Bypass -File C:\sandbox\scripts\analyze-pid-chain.ps1 `
    -PmlFile C:\sandbox\output\procmon-internal-<timestamp>.pml
```

If not available, manually review the Procmon log for:
- Any network connection that doesn't trace back to the target process
- Chains involving `cmd.exe → powershell.exe → curl/certutil` (exfil via LOL-bins)
- The target spawning processes you didn't expect (shell, scripting engine, system utilities)
- Any chain involving `lsass.exe`, `winlogon.exe`, or `svchost.exe` as an ancestor of user-space network activity

Flag unexpected chains as HIGH. Include the full ancestry in the report: `targetapp.exe (PID 1234) → cmd.exe (PID 5678) → certutil.exe (PID 9012) → [connection to external-ip]`

Take the Autoruns diff after the sandbox closes and flag any new persistence entries as HIGH.

Save state after Phase 4 completes (record `sac_original_state` in state file).

If Docker is available (cross-platform fallback):
```bash
docker run --rm --network=none -v "$(pwd):/target:ro" python:3.11-slim bash -c "
    cd /target && pip install . 2>&1 | tail -20
    echo 'Install complete'
"
```

Note: Docker provides filesystem isolation but limited network/process monitoring compared to Windows Sandbox.

---

## Phase 5 — Write the report

**Progress:** "Writing report..."

Write the report to `~/canary-reports/<target-name>-<date>-canary-report.md`

Format for plain-text readability — no markdown tables, no `---` dividers, no heavy bold syntax. The report must look clean when viewed as raw text in an editor, not just when rendered.

```
# Canary Security Report: <target>

Date: <date>
Target: <url or path>
Evaluation: <Quick / Medium / Full> — Static Analysis
Tool: Canary v2.5


## Verdict: ✅ Safe / ⚠️ Caution / ❌ Unsafe

One or two plain-English sentences summarizing the verdict and the key reason for it.


## Executive Summary

One paragraph describing what the target is and what was found at a high level.
Written for a non-technical reader.

  Critical   0
  High       0
  Medium     0
  Low        0
  Info       0

Recommendation: One sentence. What should the user do?


## Findings


### 1. <Short title>
  Severity:  CRITICAL / HIGH / MEDIUM / LOW / INFO
  Category:  Security / Secrets / Dependencies / Quality / Bug
  File:      path/to/file.py:42

Two or three sentences explaining what this is and why it matters in plain English.

Fix:
  - Specific actionable step
  - Second step if needed

(Repeat for each finding. If no findings: "No issues found.")


## Security Analysis

Based on static code review only. Full mode required to observe actual runtime behavior.

Network activity    One line summary of what the code is written to contact.
Credentials         One line summary.
Persistence         One line summary.
Process behavior    One line summary.


## Dependency Audit

One paragraph. Note if audit tools weren't available. If nothing found, say so.
If this was a Quick evaluation, write: "Not evaluated — run a Medium or Full evaluation to check dependencies."


## Code Quality

One paragraph. Anti-patterns, complexity, test coverage, undocumented requirements.
Keep it brief. If nothing notable, say so.
If this was a Quick evaluation, write: "Not evaluated — run a Medium or Full evaluation for code quality analysis."


## Sandbox Results

Only include this section for Full evaluations. Describe what the code actually did when run:
network connections observed, files created or modified, processes spawned, anything unexpected.
If this was a Quick or Medium evaluation, write: "Not evaluated — run a Full evaluation to observe runtime behavior."

If SAC was disabled for this scan, always include:
"Smart App Control was active on this machine (state: [0/1/2]) before this evaluation.
It was temporarily disabled to allow the unsigned binary to run in the sandbox, then
re-enabled immediately after. This is a normal step for evaluating unsigned software.
To verify SAC is back on: Windows Security > App & browser control > Smart App Control."

If the user declined to disable SAC, write:
"Runtime analysis was not performed — Smart App Control was active and the user chose
not to disable it. Results above are based on static analysis only. To get runtime
behavior data, re-run as Full and allow SAC to be temporarily disabled."


## Bugs Found

Describe each bug with file:line, what it does, and the fix. If none, say so.
If this was a Quick evaluation, write: "Not evaluated — run a Medium or Full evaluation for bug analysis."


## Recommendation

Plain-English verdict: safe to use or not, and exactly what to do.

Before you use it:
  1. First required action
  2. Second required action

Optional:
  - Nice-to-have improvement
```

After writing the report, delete the state file — the scan is complete:
```powershell
Remove-Item "$HOME\canary-reports\$targetSlug-state.json" -ErrorAction SilentlyContinue
```

Then ask the user: "Want me to save a note so future sessions know this evaluation is done?"

---

## Troubleshooting

At any point during the evaluation, the user can describe a problem in plain English and canary should respond helpfully. Examples:
- "something popped up asking me to allow a network connection" → advise what to do
- "the sandbox window closed early" → diagnose and offer to re-run
- "it's been sitting here for 5 minutes" → check what's stuck and recover
- "I see an error that says X" → interpret and fix
- "I restarted my PC / closed Claude" → check for state file and offer to resume

Never require the user to run commands themselves to diagnose an issue. If something is wrong, canary figures it out and handles it.

---

## Output rules

- **Verdict at the top** — ✅ / ⚠️ / ❌ — users need to see this immediately
- **Plain English** — explain what each finding means and why it matters, as if the user has no security background
- **Actionable** — every finding includes a suggested fix or workaround
- **Honest about limits** — note if a check wasn't possible (e.g. tool not installed, private repo, tool declined)
- **Rate every finding:** CRITICAL / HIGH / MEDIUM / LOW / INFO
- **No unsolicited comparisons** — don't compare to other reports unless the user asks
- **No silent failures** — every tool check and phase transition reported explicitly
- **Consistent feedback** — user should never see a blank screen; always know what's happening

---

## Edge cases

**No target provided:** Ask what they'd like to evaluate and show supported formats. Don't error.

**Resuming a paused evaluation:** Check for state file first (Phase 0). If found, offer to resume. If the state file has `sac_original_state` set to a non-zero value, re-enable SAC immediately before doing anything else — it may have been left disabled by the interrupted scan.

**Private repo / access failure:** Tell the user clearly: "I wasn't able to access this repo — it may be private or the URL may be incorrect. If it's private, make sure you're logged in with `gh auth login`."

**Monorepo / multi-package repo:** List the packages/apps found and ask which one(s) to evaluate, or offer to evaluate all of them.

**Target looks hostile during static analysis:** If CRITICAL findings appear before Phase 4, warn the user: "I've already found serious issues in the static analysis. Do you still want me to run this in a sandbox, or is the static report enough?" Don't proceed to sandbox automatically.

**Tool install fails:** If a tool fails to install after attempting, tell the user exactly what went wrong, note it as a limitation, and continue without it. Never silently skip.

---

## Security rules (always enforce)

- Read source before running anything
- Never execute code from the target during static analysis
- Never transmit target source code to external services (exception: package metadata to PyPI/npmjs for version checking)
- Label all permission requests as `[Claude]` or `[software under test]`
- If a secret is found, do NOT print the full value — show first 8 chars + `...`
- Never screenshot the VM terminal — stream logs in real time via `stream.log`; screenshots miss timing and can't be automated
- Only one sandbox instance at a time — check `Get-Process WindowsSandboxServer` before launch; the watchdog's PID guard handles this automatically but confirm on first run
- Never put config files in the output folder — the output folder is read-write for the sandbox, so a malicious target could modify its own config. Keep config in a separate read-only mapped folder
- Procmon filenames are timestamped — avoids overwrite prompts on retry; setup.ps1 must use `$ts = Get-Date -Format 'yyyyMMdd-HHmmss'` in the Procmon filename
- On any interrupted Full scan: check state file for `sac_original_state` and restore SAC before doing anything else
