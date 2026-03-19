---
description: Evaluate code for security issues, dependency vulnerabilities, bugs, and quality problems before installing
version: 2.7
---

# /canary
# canary-version: 2.7

Evaluate code before you trust it. Canary reads source code, checks for security issues, scans for known vulnerabilities, and can run the code in an isolated sandbox â€” then gives you a plain-English verdict.

## Usage
```
/canary <target>
/canary update
```
Where `<target>` is a GitHub URL, local path, `pip:<package>`, or `npm:<package>`.

**`/canary update`** â€” checks your installed version against the repo and reinstalls if behind.

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

If already up to date, say so and stop â€” don't reinstall unnecessarily.

---

## Tool availability

**Always use `gh api <endpoint> --jq '<filter>'` for GitHub API calls and JSON parsing.** Do not use standalone `jq`, `python3`, or `python` for JSON parsing â€” they are not reliably available on Windows. If you need to parse JSON outside of a `gh api` call, use `grep` or string matching instead.

### Tools by scan level

Quick needs almost nothing. Medium needs the static analysis toolkit. Full needs everything.

```
Tool                  Quick        Medium            Full
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
gh + gh auth login    GitHub only  GitHub only       required
pip / Python          â€”            inside sandbox    required
winget (Windows)      â€”            â€”                 required
semgrep               â€”            inside sandbox    inside sandbox
bandit                â€”            Python (sandbox)  Python (sandbox)
trufflehog            â€”            inside sandbox    inside sandbox
gitleaks              â€”            inside sandbox    inside sandbox
pip-audit             â€”            Python (sandbox)  Python (sandbox)
npm / npm audit       â€”            Node (sandbox)    Node (sandbox)
Admin rights          â€”            â€”                 required
Windows Sandbox       â€”            required          required
Sysinternals Suite    â€”            â€”                 required
tshark / Wireshark    â€”            â€”                 required
Canary sandbox scriptsâ€”            required          required
```

**Architecture note:** No scan tier ever clones or writes target code to the host machine.
- **Quick** â€” GitHub API only. Nothing touches your disk.
- **Medium** â€” Static analysis tools run inside Windows Sandbox. Only Claude's interpreted summary leaves the sandbox; raw tool output stays inside.
- **Full** â€” Same as Medium, plus the target binary runs inside the sandbox.

### Install commands

```
gh:           winget install GitHub.cli            (Windows)
              brew install gh                       (Mac/Linux)
semgrep:      pip install semgrep
bandit:       pip install bandit
trufflehog:   Download the v3 release binary from https://github.com/trufflesecurity/trufflehog/releases
              (do NOT use winget â€” the ID is wrong and falls back to pip which installs legacy v2.2.1)
              (do NOT use pip â€” pip installs v2.x; canary requires v3.x CLI syntax)
              Verify: trufflehog --version should show 3.x
              Mac/Linux: brew install trufflehog
gitleaks:     winget install gitleaks              (Windows)
              brew install gitleaks                 (Mac)
pip-audit:    pip install pip-audit
npm:          Install Node.js from https://nodejs.org
tshark:       winget install WiresharkFoundation.Wireshark
Sysinternals: Download suite from https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite
              Extract to C:\temp\security-tools\Sysinternals\
Windows Sandbox: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
              (requires reboot)
```

### Tool install behavior

No tool is ever skipped silently. When a tool is missing, tell the user exactly what it is, what it's needed for, and offer to install it. If the user declines, note it as a limitation in the report. Never proceed assuming a tool is there when you haven't checked.

---

## Phase 0 â€” Resume check

Before doing anything else, check for an existing partial scan of this target.

Derive a target slug from the target string:
- `https://github.com/foo/bar` â†’ `github-foo-bar`
- `/path/to/project` â†’ last folder name, e.g. `local-project`
- `pip:requests` â†’ `pip-requests`
- `npm:lodash` â†’ `npm-lodash`

**Sanitize the slug immediately after deriving it** â€” strip every character that is not `[a-zA-Z0-9_-]`. This must happen before the slug is used in any file path, state file name, or folder name. A repo named `../../Windows/System32/evil` must produce a slug like `Windows-System32-evil`, not a path traversal.

```powershell
$targetSlug = $targetSlug -replace '[^a-zA-Z0-9_-]', '-'
$targetName  = $targetName  -replace '[^a-zA-Z0-9_-]', '-'
```

Check for a state file:
```powershell
$stateFile = "$HOME\canary-reports\$targetSlug-state.json"
Test-Path $stateFile
```

If a state file exists, read it and tell the user:
> "I found a partial [level] scan of [target] from [date]. Here's what's already complete: [list phases done]. Want to resume from where we left off, or start fresh?"

- **Resume** â€” load existing findings from state file, skip completed phases, continue from next incomplete phase
- **Fresh** â€” delete state file, start over from Phase 1

If no state file exists, proceed normally.

---

## Phase 1 â€” Identify the target

Parse `<target>`:
- **GitHub URL** â†’ fetch repo contents via GitHub API (no clone needed for static analysis)
- **Local path** â†’ read files directly
- **`pip:<name>`** â†’ fetch from PyPI: source tarball or wheel, read metadata + scripts
- **`npm:<name>`** â†’ fetch from npmjs: read package.json, scripts, index

If no target is provided, ask the user what they'd like to evaluate and explain the supported formats.

**Offensive repo check:** Before presenting tier options, check the repo name and description for offensive security indicators: keywords such as `0day`, `exploit`, `poc`, `payload`, `shellcode`, `RAT`, `C2`, `backdoor`, `EXP`, `CVE` in the repo name, or descriptions mentioning "exploit collection", "proof of concept", or "offensive". If found:

> "Heads up â€” this repo appears to be offensive security tooling (exploit code, POCs, C2 framework, etc.). Canary can still evaluate it, but be aware:
> - Cloning or running any code from this repo may trigger your AV/EDR or violate corporate policy.
> - Static analysis tools may reproduce malicious signatures in their output.
> - Canary will only read files via the GitHub API â€” nothing will be cloned to your machine.
>
> Do you want to proceed with a Quick (API-only) evaluation?"

If the user wants to proceed: default them to Quick regardless of what they choose, and note the override in the report. Do not offer Medium or Full for repos flagged as offensive tooling.

**Tell the user:**

> "Canary v2.7 â€” use at your own risk. Canary reduces risk but does not guarantee safety. Use your own judgment before installing any software.
>
> Everything I do during this evaluation is [Claude] â€” I'm fetching and reading code on your behalf. Nothing from this repo will be cloned or saved to your machine. If you choose Full mode, the software runs inside an isolated sandbox and those actions will be labeled [software under test]."

Then ask:

> "How thorough should I be?
>
> - **Quick** â€” I'll read the most important files via the GitHub API (entry points, install scripts, anything that runs at startup) and look for red flags using my own analysis. Nothing is cloned to your machine. No external tools needed. Takes about a minute.
> - **Medium** â€” I'll do a full static analysis using semgrep, bandit, trufflehog, and gitleaks â€” all running inside Windows Sandbox so nothing from the target touches your machine. Requires Windows Sandbox (built into Windows 10/11 Pro). Takes a few minutes.
> - **Full** â€” Everything in Medium, plus I'll run the software inside the sandbox and watch what it actually does (network connections, files touched, whether it tries to persist). Requires Windows Sandbox, Wireshark, and Sysinternals. If any of these aren't installed, I'll walk you through it."

**After the user chooses a tier, run dependency checks before doing anything else:**

### Dependency check â€” Quick

If the target is a GitHub URL:
```bash
gh --version 2>/dev/null && echo "OK" || echo "MISSING"
gh auth status 2>/dev/null && echo "OK" || echo "NOT LOGGED IN"
```

If `gh` is missing: offer to install via `winget install GitHub.cli` (Windows) or `brew install gh` (Mac/Linux). Verify before continuing.
If `gh auth` fails: guide through `gh auth login`. Wait for completion.
If target is a local path, pip package, or npm package: no tool check needed for Quick.

### Dependency check â€” Medium

Run all Quick checks first, then:

**Check Windows Sandbox (required for Medium):**
```powershell
(Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -ErrorAction SilentlyContinue).State
```

If not Enabled:
> "Medium scan requires Windows Sandbox â€” static analysis tools run inside it so no target code or raw tool output ever touches your machine. Windows Sandbox isn't enabled yet.
>
> Options:
> - **Enable it now** â€” I'll run the command; requires a reboot, then come back and start the scan again.
> - **Switch to Quick** â€” I'll do an API-only evaluation. No sandbox needed, but no static analysis tools.
>
> What would you prefer?"

If user chooses Enable:
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
```
Then stop and tell the user to reboot and restart the scan.

If user chooses Quick: restart at Phase 1 with Quick tier. Do not proceed with Medium without Windows Sandbox.

**Check canary sandbox scripts (required for Medium):**
```powershell
Test-Path 'C:\sandbox\scripts\run-watchdog.ps1'
```
If missing:
> "The canary sandbox infrastructure isn't installed. Running the installer..."
```powershell
irm https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 | iex
```

**Check static analysis tools** (these will run inside the sandbox, but we verify they're installed on the host so they can be copied in):

Check trufflehog version specifically â€” must be v3.x:
```bash
trufflehog --version 2>/dev/null
```
If missing or showing v2.x:
> "trufflehog needs to be v3.x. Download the release binary from https://github.com/trufflesecurity/trufflehog/releases (do NOT use winget or pip â€” they install the wrong version). Let me know when it's installed."

Check other tools:
```bash
semgrep --version 2>/dev/null && echo "semgrep: OK" || echo "semgrep: MISSING"
bandit --version 2>/dev/null && echo "bandit: OK" || echo "bandit: MISSING"
gitleaks version 2>/dev/null && echo "gitleaks: OK" || echo "gitleaks: MISSING"
pip-audit --version 2>/dev/null && echo "pip-audit: OK" || echo "pip-audit: MISSING"
npm --version 2>/dev/null && echo "npm: OK" || echo "npm: MISSING"
```

**After installing any tool, verify it's callable** â€” don't trust that install succeeded just because the installer returned 0:
```bash
# Example for semgrep
semgrep --version 2>/dev/null && echo "CALLABLE" || echo "NOT ON PATH"
```
If a tool installs but isn't callable: warn the user that pip --user installs on Windows often aren't on PATH. Suggest adding the Python Scripts folder to PATH or using the full path as fallback.

**Check pip version** â€” old pip can fail silently:
```bash
pip --version 2>/dev/null
```
If pip is available but older than 21.x: suggest `python -m pip install --upgrade pip` before installing other tools.

Show a clean summary to the user before asking to install anything:

> "Here's what I found on your machine:
> âœ… Windows Sandbox â€” enabled
> âœ… semgrep
> âœ… bandit
> â¬œ trufflehog â€” not installed (need v3.x from GitHub releases)
> â¬œ gitleaks â€” not installed
> âœ… pip-audit
> âœ… npm
>
> I need to install trufflehog and gitleaks before I can start. Want me to do that now?"

Install missing tools one at a time. Confirm each is callable before moving to the next.

**After all tools are confirmed callable, discover and record their binary paths:**
```powershell
$trufflehogPath = (Get-Command trufflehog -ErrorAction SilentlyContinue).Source
$gitleaksPath   = (Get-Command gitleaks   -ErrorAction SilentlyContinue).Source
```

Save both paths to the state file under `trufflehog_path` and `gitleaks_path`. These will be used when generating the sandbox `.wsb` config to create the correct `MappedFolder` blocks. If either path is null (tool not found after install), record it as a limitation and plan to install fresh inside the sandbox instead.

If pip/Python is not available and a pip-based tool is missing:
> "I need Python/pip installed to set up [tool]. Is Python installed on your machine? If it is, try opening a new terminal and running `pip --version`. If Python isn't installed yet, I can walk you through installing it first."

If the user declines any tool: note it as a limitation. Never skip silently â€” always record what was skipped and why.

### Dependency check â€” Full

Run all Medium checks first, then:

Check admin rights (required for Procmon, tshark, SAC registry):
```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```
If not admin:
> "Full mode needs administrator rights to run Procmon, tshark, and modify system settings. Please restart Claude Code as Administrator (right-click â†’ Run as administrator) and try again."
Stop here â€” do not proceed without admin rights.

Check Windows Sandbox:
```powershell
(Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -ErrorAction SilentlyContinue).State
```
If not Enabled:
> "Windows Sandbox isn't enabled on this machine. I can enable it for you â€” it requires a reboot after. Want me to do that now?"
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

> "Here's everything I'll do during this [Quick / Medium / Full] evaluation â€” I'll ask once and then run without interruptions.
>
> **[Claude] â€” all of this is me, not the software being evaluated:**
> - Fetch repo metadata and file tree from GitHub API
> - Read source files directly from GitHub (no download to your machine)
> - Search for secrets, hardcoded credentials, and suspicious patterns in the code
> *(Medium + Full only)* Launch Windows Sandbox and run `semgrep`, `bandit`, `trufflehog`, and `gitleaks` inside it â€” nothing from the target is ever written to your machine; only my interpreted summary leaves the sandbox
> *(Medium + Full only)* Run `pip-audit` and/or `npm audit` inside the sandbox to check dependencies for known CVEs
> - Write a report to `~/canary-reports/`
> - Delete all target files (clone, downloads, sandbox output) after the report is written
> - Save scan progress after each step so you can resume if anything interrupts
>
> *(Full only)* **[software under test] â€” this is the code running inside the sandbox:**
> - Clone the target repo and download the release binary inside the sandbox
> - Run the software inside Windows Sandbox â€” it cannot touch your files, browser, or main system
> - Observe what network connections it makes, what files it creates, whether it tries to persist
> - Sandbox is destroyed after evaluation â€” nothing persists to your main system
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

## Phase 2 â€” Static security analysis

### 2a. Code inspection

**Progress:** Tell the user "Reading source files..." before starting. When done: "Source review complete â€” [N findings / no issues found]."

**Quick and above:** Read these files first (in order of risk):
1. Entry points: `__main__.py`, `main.py`, `index.js`, `cli.py`, `app.py`
2. Install/setup scripts: `setup.py`, `pyproject.toml`, `package.json`, `Makefile`, `*.sh`, `*.ps1`
3. Any file with network calls, subprocess calls, or `eval()`/`exec()`

**Medium and above:** Read the full codebase, prioritizing files with network I/O, file I/O, subprocess calls, authentication, and data handling.

Flag these patterns (rate each CRITICAL / HIGH / MEDIUM / LOW / INFO):

- `eval()` / `exec()` on external input â€” **CRITICAL** (e.g. `eval(response.text)`)
- Subprocess with shell=True on external input â€” **CRITICAL**
- Writes to startup/autorun locations â€” **CRITICAL** (Registry Run keys, `~/.bashrc`, cron)
- Outbound connections to unexpected domains â€” **HIGH**
- `postinstall` / `prepare` scripts in package.json â€” **HIGH** (runs at install time, before review)
- Base64-encoded strings â€” **HIGH** (common obfuscation technique)
- Hardcoded IP addresses (non-localhost) â€” **HIGH**
- `os.system()` / `subprocess` calls â€” **MEDIUM** (may be legitimate; check args)
- `install_requires` with no version pins â€” **MEDIUM** (unpinned deps allow supply chain attacks)
- `__import__` / dynamic imports â€” **MEDIUM** (can obfuscate what's loaded)

Save state after 2a completes.

### 2bâ€“2d. Sandbox static analysis (Medium and Full)

**Medium and above only. All static analysis tools run inside Windows Sandbox â€” nothing from the target is written to the host machine.**

**Architecture:** Generate a Medium-mode sandbox config that:
1. Maps trufflehog and gitleaks binaries from host into sandbox (read-only) using paths discovered in the dep check
2. Maps `C:\sandbox\tool-output\` host folder into sandbox as `C:\sandbox\tool-output\` (read-write) â€” this is where tool results land
3. Clones the target repo inside the sandbox (no clone on host)
4. Installs Python-based tools (semgrep, bandit, pip-audit) fresh inside the sandbox via pip
5. Runs all static analysis tools inside the sandbox
6. Claude reads only the summarized output from the mapped tool-output folder â€” raw JSON is never reproduced in Claude's context

**10-minute hard timeout:** The Medium sandbox launch must complete within 10 minutes. If no `RESULT:` line appears in `setup-static.log` within 600 seconds of launch, kill the sandbox process, log `TIMEOUT: static analysis did not complete within 10 minutes`, and proceed to the report with whatever partial output exists.

**Before launching the Medium sandbox, create the output directory if it doesn't exist:**
```powershell
New-Item -ItemType Directory -Force -Path 'C:\sandbox\tool-output' | Out-Null
```

**Generate `.wsb` config for static analysis (Medium):**

Build a target-specific .wsb that maps:
- `C:\sandbox\scripts\` â†’ `C:\sandbox\scripts\` (read-only â€” bootstrap and setup scripts)
- `C:\sandbox\tool-output\` â†’ `C:\sandbox\tool-output\` (read-write â€” tool results)
- The directory containing the trufflehog binary (from `$trufflehogPath` in state) â†’ `C:\tools\trufflehog\` (read-only)
- The directory containing the gitleaks binary (from `$gitleaksPath` in state) â†’ `C:\tools\gitleaks\` (read-only)

No Sysinternals mapping needed for Medium (no process monitoring).
No target binary download needed (tools run against cloned source).

**Generate `C:\sandbox\scripts\setup-static.ps1`** with the following behavior inside the sandbox:

```powershell
# Inside sandbox â€” runs as part of bootstrap
Set-ExecutionPolicy Bypass -Scope Process -Force
New-Item -ItemType Directory -Force -Path 'C:\sandbox\tool-output' | Out-Null
Start-Transcript 'C:\sandbox\tool-output\setup-static.log'

# 1. Install Python analysis tools fresh inside sandbox
Write-Host "Installing Python tools..."
pip install --quiet semgrep bandit pip-audit 2>'C:\sandbox\tool-output\pip-install-stderr.txt'
Write-Host "Pip install stderr: $(Get-Content 'C:\sandbox\tool-output\pip-install-stderr.txt' -Raw)"

# 2. Clone the target repo (hooks disabled â€” prevents hook execution during clone)
$targetUrl = '{{TARGET_CLONE_URL}}'
$cloneDir  = 'C:\target'
git clone --depth 1 --config core.hooksPath=NUL $targetUrl $cloneDir 2>&1
if (-not (Test-Path $cloneDir)) {
    Write-Host "RESULT: Clone failed"
    Stop-Transcript; exit 1
}
Write-Host "Clone complete â€” $((Get-ChildItem $cloneDir -Recurse -File).Count) files"

# 3. Run semgrep
Write-Host "Running semgrep..."
semgrep --config=auto --json $cloneDir 2>'C:\sandbox\tool-output\semgrep-stderr.txt' |
    Out-File 'C:\sandbox\tool-output\semgrep.json' -Encoding UTF8
if ($LASTEXITCODE -ne 0) {
    Write-Host "TOOL ERROR semgrep exit=$LASTEXITCODE stderr=$(Get-Content 'C:\sandbox\tool-output\semgrep-stderr.txt' -Raw)"
} else { Write-Host "semgrep complete" }

# 4. Run bandit (Python projects only)
$pyFiles = Get-ChildItem $cloneDir -Recurse -Filter '*.py' -ErrorAction SilentlyContinue
if ($pyFiles.Count -gt 0) {
    Write-Host "Running bandit ($($pyFiles.Count) Python files)..."
    bandit -r $cloneDir -f json 2>'C:\sandbox\tool-output\bandit-stderr.txt' |
        Out-File 'C:\sandbox\tool-output\bandit.json' -Encoding UTF8
    if ($LASTEXITCODE -gt 1) {  # bandit exits 1 on findings (normal), >1 on error
        Write-Host "TOOL ERROR bandit exit=$LASTEXITCODE stderr=$(Get-Content 'C:\sandbox\tool-output\bandit-stderr.txt' -Raw)"
    } else { Write-Host "bandit complete" }
} else { Write-Host "SKIP bandit â€” no Python files found" }

# 5. Run trufflehog (mapped binary from host)
$trufflehogExe = 'C:\tools\trufflehog\{{TRUFFLEHOG_BIN}}'
if (Test-Path $trufflehogExe) {
    Write-Host "Running trufflehog..."
    & $trufflehogExe filesystem $cloneDir --json 2>'C:\sandbox\tool-output\trufflehog-stderr.txt' |
        Out-File 'C:\sandbox\tool-output\trufflehog.json' -Encoding UTF8
    if ($LASTEXITCODE -ne 0) {
        Write-Host "TOOL ERROR trufflehog exit=$LASTEXITCODE stderr=$(Get-Content 'C:\sandbox\tool-output\trufflehog-stderr.txt' -Raw)"
    } else { Write-Host "trufflehog complete" }
} else { Write-Host "SKIP trufflehog â€” binary not found at $trufflehogExe" }

# Note: using 'filesystem' mode (not 'git') because --depth 1 clone has no history to scan.
# trufflehog filesystem scans current files. Limitation noted in report.

# 6. Run gitleaks (mapped binary from host)
$gitleaksExe = 'C:\tools\gitleaks\{{GITLEAKS_BIN}}'
if (Test-Path $gitleaksExe) {
    Write-Host "Running gitleaks..."
    & $gitleaksExe detect --source $cloneDir --report-format json `
        --report-path 'C:\sandbox\tool-output\gitleaks.json' `
        2>'C:\sandbox\tool-output\gitleaks-stderr.txt'
    if ($LASTEXITCODE -gt 1) {  # gitleaks exits 1 on findings (normal), >1 on error
        Write-Host "TOOL ERROR gitleaks exit=$LASTEXITCODE stderr=$(Get-Content 'C:\sandbox\tool-output\gitleaks-stderr.txt' -Raw)"
    } else { Write-Host "gitleaks complete" }
} else { Write-Host "SKIP gitleaks â€” binary not found at $gitleaksExe" }

# 7. Run pip-audit (Python) and npm audit (Node)
if (Test-Path "$cloneDir\requirements*.txt") {
    Write-Host "Running pip-audit..."
    pip-audit -r "$cloneDir\requirements.txt" --format json `
        2>'C:\sandbox\tool-output\pip-audit-stderr.txt' |
        Out-File 'C:\sandbox\tool-output\pip-audit.json' -Encoding UTF8
}
if (Test-Path "$cloneDir\package.json") {
    Write-Host "Running npm audit..."
    Push-Location $cloneDir
    npm audit --package-lock-only --json 2>'C:\sandbox\tool-output\npm-audit-stderr.txt' |
        Out-File 'C:\sandbox\tool-output\npm-audit.json' -Encoding UTF8
    Pop-Location
}

Write-Host "RESULT: Static analysis complete"
Stop-Transcript
```

When generating this script, substitute:
- `{{TARGET_CLONE_URL}}` â€” the target's GitHub URL (e.g. `https://github.com/foo/bar`)
- `{{TRUFFLEHOG_BIN}}` â€” filename of the trufflehog binary (basename of `$trufflehogPath`)
- `{{GITLEAKS_BIN}}` â€” filename of the gitleaks binary (basename of `$gitleaksPath`)

**Critical rules for all tool output:**
- Never print raw JSON blobs into Claude's conversation â€” always parse and summarize
- Always capture stderr from every tool run; surface errors in a "Tool Errors" section in the report
- If a tool crashes (non-zero exit + no output file), log it as a tool error â€” do NOT silently skip
- If semgrep crashes with a Unicode error: log the offending file path, skip it, continue full-scope scan â€” do NOT narrow the scan directory
- If a tool output file is empty or missing after the sandbox run, note it as a tool error

**After sandbox completes, read results from `C:\sandbox\tool-output\`:**

**2b â€” Semgrep findings:**

**Progress:** "Reading semgrep results..." When done: "Semgrep complete â€” [N findings / no findings / tool error: X]."

Parse `C:\sandbox\tool-output\semgrep.json`. Focus on HIGH and CRITICAL findings. Skip INFO-level noise.

**2c â€” Bandit findings (Python only):**

**Progress:** "Reading bandit results..." When done: "Bandit complete â€” [N findings / no findings]."

Parse `C:\sandbox\tool-output\bandit.json`. Flag HIGH and MEDIUM severity. Cross-reference with manual code inspection â€” bandit has false positives.

**2d â€” Secrets scan:**

**Progress:** "Reading secrets scan results..." When done: "Secrets scan complete â€” [N secrets found / no secrets found]."

Parse `C:\sandbox\tool-output\trufflehog.json` and `C:\sandbox\tool-output\gitleaks.json`.

Report any matches with file + line number. Rate HIGH if found in committed source. Do NOT print the full value â€” show first 8 chars + `...`

If static tools weren't available (user running Quick or tools missing), manually search via GitHub API for patterns:
- Long random strings adjacent to words: key, token, secret, password, api, auth
- AWS key patterns: `AKIA[0-9A-Z]{16}`
- Private key headers: `-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`

**After reading all tool outputs, delete sandbox output files from the host:**
```powershell
Remove-Item 'C:\sandbox\tool-output\*.json' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.txt' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.log' -ErrorAction SilentlyContinue
```

Save state after static analysis phases complete.

### 2e. Dependency audit

**Medium and above only.**

**Progress:** "Checking dependencies for known CVEs..." When done: "Dependency audit complete."

pip-audit and npm audit ran inside the sandbox as part of Phase 2b-2d. Read results from `C:\sandbox\tool-output\pip-audit.json` and `C:\sandbox\tool-output\npm-audit.json`.

Do NOT run pip-audit or npm audit on the host — no dependency manifests exist locally (the clone is inside the sandbox).

Parse results and report CVEs by severity. If a tool output file is missing or empty, note it as a tool error rather than "no CVEs found."

If the target has no Python or Node manifest files: "No Python/Node dependency manifests found — dependency audit skipped."

If audit tools were unavailable and no output file exists, manually check dependencies visible in Phase 2a GitHub API reads and flag any known to have had critical CVEs (e.g. `log4j`, `lodash < 4.17.21`, `requests < 2.20.0`).

Save state after 2e completes.

### 2f. License compliance

**Medium and above only.**

**Progress:** "Checking license compliance..." When done: "License check complete."

Summarize licenses used by direct dependencies. Flag:
- GPL/AGPL in commercial contexts â€” MEDIUM (may require source disclosure)
- Unknown/unlicensed packages â€” HIGH (legal risk)
- License mismatches (project claims MIT but depends on GPL)

Save state after 2f completes.

---

## Phase 3 â€” Code quality assessment

**Medium and above only.**

**Execution model:** This phase uses source files already fetched via the GitHub API in Phase 2a. No additional tool execution, sandbox launch, or network calls are needed. All analysis is performed by Claude on the already-fetched code.

**Progress:** "Analyzing code quality..." When done: "Code quality assessment complete â€” [N findings]."

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

## Phase 4 â€” Dynamic sandbox (full mode only)

*Skip this phase if the user chose Quick or Medium, or if no sandbox is available.*

**Important:** Before running anything from the target, warn the user if static analysis already found serious issues (CRITICAL findings). Give them the option to stop here rather than run potentially hostile code even in a sandbox.

If Windows Sandbox is available:

**Autoruns baseline and tshark capture — run before launching the sandbox:**

C:\sandbox\autoruns\ is a host-only directory — never mapped into the sandbox. This prevents a malicious binary from overwriting the baseline to hide persistence.



Store the tshark PID in a variable — needed to stop it cleanly after the sandbox closes.

After the sandbox run, take a second snapshot and diff:

```powershell
Write-Host "Taking Autoruns after-snapshot..."
& $autorunsExe /accepteula '-a' '*' -c -h -s -nobanner -o 'C:\sandbox\autoruns\autoruns-after.csv' '*'

# Show new entries (persistence attempts)
$before = Import-Csv 'C:\sandbox\autoruns\autoruns-before.csv'
$after  = Import-Csv 'C:\sandbox\autoruns\autoruns-after.csv'
Compare-Object $before $after -Property 'Image Path','Entry' |
    Where-Object { $_.SideIndicator -eq '=>' }
```

Flag any new entries as HIGH â€” they represent persistence the software attempted to install outside the sandbox.

**Pre-flight: check Smart App Control (SAC) state before launching.**

```powershell
$sacState = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
```

- `0` = Off â€” proceed normally
- `1` = Evaluation mode â€” will block unsigned binaries
- `2` = On â€” will block unsigned binaries
- `$null` = key not present â€” SAC not active, proceed normally

If SAC is 1 or 2, present this consent prompt before doing anything else:

> "To run this software in the sandbox, I need to temporarily disable Smart App Control on your machine.
>
> **What that means in plain English:** Smart App Control is a Windows security feature that blocks unsigned software from running. Disabling it means Windows will be slightly more permissive for a few minutes while the scan runs. This affects your whole machine, not just the sandbox.
>
> **Why it's still safe:** The software itself runs inside an isolated sandbox â€” it can't touch your files, your browser, or anything on your main system. I'm only disabling SAC so Windows will allow it to launch inside that container. Once the scan finishes, I'll re-enable it and show you exactly how to verify it's back on.
>
> **Your options:**
> - **Yes, proceed** â€” I'll disable SAC, run the scan, and re-enable it when done
> - **No, skip sandbox** â€” I'll write the report based on static analysis only and clearly note that runtime behavior wasn't observed
>
> What would you like to do?"

Wait for explicit confirmation before touching SAC. If the user says no, skip to Phase 5 and note in the Sandbox Results section: "User declined to disable Smart App Control. Runtime analysis was not performed. Results are based on static analysis only."

If the user says yes, disable SAC and **spawn a new PowerShell process** to pick up the change â€” the registry update only takes effect in a new session:

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

> "Smart App Control has been re-enabled. To verify: open Windows Security > App & browser control > Smart App Control. Or run: `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy').VerifiedAndReputablePolicyState` â€” it should return $sacState."

Before launching, warn the user:

> "I'm about to start the sandbox. Here's what to expect:
> - A Windows Sandbox window will open â€” this is normal. Don't close it.
> - Additional windows may appear as the software launches inside the sandbox.
> - **You don't need to interact with any of those windows.** Just keep an eye on this Claude window â€” I'll report everything I observe here as it happens.
> - When the evaluation is done, the sandbox will close automatically and I'll write the report.
> - **If anything looks wrong or gets stuck, just tell me in plain English** â€” describe what you're seeing and I'll figure out what to do. You don't need to know any commands."

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

- `{{TARGET_NAME}}` â€” friendly name (e.g. `shadPS4`)
- `{{TARGET_URL}}` â€” direct download URL for the release binary or zip. Find via GitHub releases API: `gh api repos/<owner>/<repo>/releases/latest --jq '.assets[] | select(.name | test("win.*64|x64.*win"; "i")) | .browser_download_url'`
- `{{BINARY_NAME}}` â€” exact filename of the exe (check release asset name or README)
- `{{EXTRACT_DIR}}` â€” extraction path inside sandbox (e.g. `C:\shadps4_local`)
- `{{LAUNCH_ARGS}}` â€” command line args if needed, empty string if none

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

- **Automated** (default) â€” stall timeout **90 seconds**. If the binary hasn't produced any log output in 90 seconds, the watchdog restarts automatically.
- **Interactive** â€” stall timeout **600 seconds** (10 minutes). Gives you time to interact with the software without the watchdog killing it.

```powershell
# Automated (default) â€” new process so SAC policy change is in effect
Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File C:\sandbox\scripts\run-watchdog.ps1 -WsbFile `"$wsbPath`" -StallTimeoutSec 90 -MaxRetries 2" -WindowStyle Normal

# Interactive
Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File C:\sandbox\scripts\run-watchdog.ps1 -WsbFile `"$wsbPath`" -StallTimeoutSec 600 -MaxRetries 2" -WindowStyle Normal
```

**While monitoring `C:\sandbox\tool-output\stream.log`, give the user a heartbeat every 30 seconds:**
> "Still running â€” [elapsed]s. You'll see output here as it comes in. Nothing to do â€” just keep an eye on this window."

**When stream.log shows a retry attempt:**
Tell the user immediately:
> "The sandbox stopped responding â€” restarting automatically. Attempt [N] of 2. Everything we've found so far is saved."

**Stop tshark after the sandbox closes:**



**After the sandbox run, read `stream.log` and `setup.log` to determine outcome:**

- If `setup.log` contains `"RESULT: Binary could not be launched"` â€” **do not retry**. Record as a sandbox finding: "Binary blocked â€” likely SAC/WDAC policy or missing dependency. Dynamic analysis not possible on this system without further configuration." Proceed to write the report.
- If the sandbox exited before `setup.log` appeared (mapped-folder failure) â€” retry **once only**, then report the failure.
- If the binary launched successfully â€” run post-run analysis before writing the report.

**Post-run analysis (binary launched successfully):**

Unique DNS names queried by the sandbox:
```powershell
Get-Content C:\sandbox\tool-output\network-vswitch.log |
    ForEach-Object { ($_ -split '\|')[3] } |
    Where-Object { $_ -and $_ -notmatch '^\d' -and $_ -notmatch 'arpa' } |
    Sort-Object -Unique
```

External IPs connected to:
```powershell
Get-Content C:\sandbox\tool-output\network-vswitch.log |
    ForEach-Object {
        $p = $_ -split '\|'
        if ($p[1] -match '^172\.27\.' -and $p[4] -in @('443','80')) { $p[2] }
    } | Sort-Object -Unique
```

Separate Windows OS baseline traffic (WindowsUpdate, OCSP, licensing) from target-initiated connections. Flag any connections the target made to unexpected domains as HIGH.

**PID chain analysis** â€” the network log shows *where* connections went; the PID chain shows *who made them*. This catches process injection, LOL-bins, and unexpected child process spawning.

If `analyze-pid-chain.ps1` is available at `C:\sandbox\scripts\`:
```powershell
powershell -ExecutionPolicy Bypass -File C:\sandbox\scripts\analyze-pid-chain.ps1 `
    -PmlFile C:\sandbox\tool-output\procmon-internal-<timestamp>.pml
```

If not available, manually review the Procmon log for:
- Any network connection that doesn't trace back to the target process
- Chains involving `cmd.exe â†’ powershell.exe â†’ curl/certutil` (exfil via LOL-bins)
- The target spawning processes you didn't expect (shell, scripting engine, system utilities)
- Any chain involving `lsass.exe`, `winlogon.exe`, or `svchost.exe` as an ancestor of user-space network activity

Flag unexpected chains as HIGH. Include the full ancestry in the report: `targetapp.exe (PID 1234) â†’ cmd.exe (PID 5678) â†’ certutil.exe (PID 9012) â†’ [connection to external-ip]`

Take the Autoruns diff after the sandbox closes and flag any new persistence entries as HIGH.

Save state after Phase 4 completes (record `sac_original_state` in state file).

---

## Phase 5 â€” Cleanup and write the report

**Cleanup before writing the report** â€” delete all target files from the host regardless of scan outcome:

```powershell
# Remove any local clone (should not exist for Medium/Full, but clean up just in case)
$clonePath = "$HOME\canary-scans\$targetSlug"
if (Test-Path $clonePath) {
    Remove-Item $clonePath -Recurse -Force
    Write-Host "Cleanup: deleted clone at $clonePath"
} else {
    Write-Host "Cleanup: no clone found on host (expected for sandbox scans)"
}

# Remove any downloaded archives or temp files
Remove-Item "$HOME\canary-scans\$targetSlug*" -Recurse -Force -ErrorAction SilentlyContinue

# Remove sandbox output files (already deleted after reading in Phase 2, but verify)
Remove-Item 'C:\sandbox\tool-output\*.json' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.txt' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.log' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.pml' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.csv' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.pcap*' -ErrorAction SilentlyContinue

# Remove autoruns snapshots (host-only folder — never in sandbox)
Remove-Item 'C:\sandbox\autoruns\*.csv' -ErrorAction SilentlyContinue

# Remove generated .wsb and setup files for this target
Remove-Item "C:\sandbox\$targetName.wsb" -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\scripts\setup.ps1' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\scripts\setup-static.ps1' -ErrorAction SilentlyContinue
```

Note the cleanup result in the report. If deletion failed for any file, log the path and reason â€” do not silently skip.

**Progress:** "Writing report..."

Write the report to `~/canary-reports/<target-name>-<date>-canary-report.md`

Format for plain-text readability â€” no markdown tables, no `---` dividers, no heavy bold syntax. The report must look clean when viewed as raw text in an editor, not just when rendered.


**Verdict selection (internal — do not write this block into the report):**
- Safe: no significant findings; normal use path is low risk
- Caution: notable findings the user should review; risks are manageable with care
- Unsafe (hidden threat): malicious behavior found — C2, credential theft, auto-execution
- Unsafe (dangerous by design): normal use path exposes serious risk without a hidden backdoor — exploit collections, C2 tools, repos where AV triggers on clone. Make the distinction explicit in the report.

```
# Canary Security Report: <target>

Date: <date>
Target: <url or path>
Evaluation: <Quick / Medium / Full> â€” Static Analysis
Tool: Canary v2.7


## Verdict: âœ… Safe / âš ï¸ Caution / âŒ Unsafe


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
If this was a Quick evaluation, write: "Not evaluated â€” run a Medium or Full evaluation to check dependencies."


## Code Quality

One paragraph. Anti-patterns, complexity, test coverage, undocumented requirements.
Keep it brief. If nothing notable, say so.
If this was a Quick evaluation, write: "Not evaluated â€” run a Medium or Full evaluation for code quality analysis."


## Sandbox Results

Only include this section for Full evaluations. Describe what the code actually did when run:
network connections observed, files created or modified, processes spawned, anything unexpected.
If this was a Quick or Medium evaluation, write: "Not evaluated â€” run a Full evaluation to observe runtime behavior."

If SAC was disabled for this scan, always include:
"Smart App Control was active on this machine (state: [0/1/2]) before this evaluation.
It was temporarily disabled to allow the unsigned binary to run in the sandbox, then
re-enabled immediately after. This is a normal step for evaluating unsigned software.
To verify SAC is back on: Windows Security > App & browser control > Smart App Control."

If the user declined to disable SAC, write:
"Runtime analysis was not performed â€” Smart App Control was active and the user chose
not to disable it. Results above are based on static analysis only. To get runtime
behavior data, re-run as Full and allow SAC to be temporarily disabled."


## Bugs Found

Describe each bug with file:line, what it does, and the fix. If none, say so.
If this was a Quick evaluation, write: "Not evaluated â€” run a Medium or Full evaluation for bug analysis."


## Recommendation

Plain-English verdict: safe to use or not, and exactly what to do.

Before you use it:
  1. First required action
  2. Second required action

Optional:
  - Nice-to-have improvement

If the repo has unverified binaries, high-severity findings, or any sandbox-worthy behavior (even if verdict is âš ï¸ Caution), include:
  - "To observe what this software actually does at runtime, run `/canary <target> full` â€” this runs it inside Windows Sandbox with network and process monitoring."


## Cleanup

  Clone deleted from host:    [yes / no clone existed]
  Sandbox output deleted:     [yes / n/a]
  Temp files removed:         [yes / none found]


## Token Usage

Before writing this section, sum all `usage` fields from this session's JSONL file:

```powershell
$sessionFile = Get-ChildItem "$env:USERPROFILE\.claude\projects\" -Recurse -Filter '*.jsonl' |
    Where-Object { $_.Name -notmatch '^agent-' } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1 -ExpandProperty FullName

$input = 0; $output = 0; $cacheRead = 0; $cacheCreate = 0
Get-Content $sessionFile | ForEach-Object {
    try {
        $j = $_ | ConvertFrom-Json -ErrorAction Stop
        if ($j.message.usage) {
            $u = $j.message.usage
            $input      += if ($u.input_tokens) { $u.input_tokens } else { 0 }
            $output     += if ($u.output_tokens) { $u.output_tokens } else { 0 }
            $cacheRead   += if ($u.cache_read_input_tokens) { $u.cache_read_input_tokens } else { 0 }
            $cacheCreate += if ($u.cache_creation_input_tokens) { $u.cache_creation_input_tokens } else { 0 }
        }
    } catch {}
}
# Sonnet 4.5 pricing: $3/M input, $15/M output, $0.30/M cache read, $3.75/M cache write
$cost = ($input / 1e6 * 3) + ($output / 1e6 * 15) + ($cacheRead / 1e6 * 0.30) + ($cacheCreate / 1e6 * 3.75)
Write-Host "input=$input output=$output cache_read=$cacheRead cache_create=$cacheCreate cost=$([math]::Round($cost,4))"
```

Write the section using the values above:

```
## Token Usage

  Input tokens:         <N>
  Output tokens:        <N>
  Cache read tokens:    <N>   (<X>% of input served from cache)
  Cache write tokens:   <N>
  Estimated cost:       ~$<N>  (Sonnet 4.6 pricing)


---
Canary v2.7 â€” use at your own risk. This tool reduces risk but does not guarantee safety.
No security evaluation is a substitute for your own judgment. Review findings before
installing any software. Report issues at https://github.com/AppDevOnly/canary
```

Cache read % = cache_read / (input + cache_read) * 100, rounded to nearest integer.
```

After writing the report, delete the state file â€” the scan is complete:
```powershell
Remove-Item "$HOME\canary-reports\$targetSlug-state.json" -ErrorAction SilentlyContinue
```

Then ask the user: "Want me to save a note so future sessions know this evaluation is done?"

---

## Troubleshooting

At any point during the evaluation, the user can describe a problem in plain English and canary should respond helpfully. Examples:
- "something popped up asking me to allow a network connection" â†’ advise what to do
- "the sandbox window closed early" â†’ diagnose and offer to re-run
- "it's been sitting here for 5 minutes" â†’ check what's stuck and recover
- "I see an error that says X" â†’ interpret and fix
- "I restarted my PC / closed Claude" â†’ check for state file and offer to resume

Never require the user to run commands themselves to diagnose an issue. If something is wrong, canary figures it out and handles it.

---

## Output rules

- **Verdict at the top** â€” âœ… / âš ï¸ / âŒ â€” users need to see this immediately
- **Plain English** â€” explain what each finding means and why it matters, as if the user has no security background
- **Actionable** â€” every finding includes a suggested fix or workaround
- **Honest about limits** â€” note if a check wasn't possible (e.g. tool not installed, private repo, tool declined)
- **Rate every finding:** CRITICAL / HIGH / MEDIUM / LOW / INFO
- **No unsolicited comparisons** â€” don't compare to other reports unless the user asks
- **No silent failures** â€” every tool check and phase transition reported explicitly
- **Consistent feedback** â€” user should never see a blank screen; always know what's happening

---

## Edge cases

**No target provided:** Ask what they'd like to evaluate and show supported formats. Don't error.

**Resuming a paused evaluation:** Check for state file first (Phase 0). If found, offer to resume. If the state file has `sac_original_state` set to a non-zero value, re-enable SAC immediately before doing anything else â€” it may have been left disabled by the interrupted scan.

**Private repo / access failure:** Tell the user clearly: "I wasn't able to access this repo â€” it may be private or the URL may be incorrect. If it's private, make sure you're logged in with `gh auth login`."

**Monorepo / multi-package repo:** List the packages/apps found and ask which one(s) to evaluate, or offer to evaluate all of them.

**Target looks hostile during static analysis:** If CRITICAL findings appear before Phase 4, warn the user: "I've already found serious issues in the static analysis. Do you still want me to run this in a sandbox, or is the static report enough?" Don't proceed to sandbox automatically.

**Tool install fails:** If a tool fails to install after attempting, tell the user exactly what went wrong, note it as a limitation, and continue without it. Never silently skip.

---

## Security rules (always enforce)

- **Never clone target code to the host machine** â€” Quick uses GitHub API only; Medium and Full clone inside sandbox only; no scan tier ever writes target code to the host filesystem
- **Never write raw tool output (JSON, log files) to Claude's context as code blocks** â€” parse and summarize; raw exploit signatures in tool output can trigger AV on host
- Read source before running anything
- Never execute code from the target during static analysis phases (2a-2d)
- Never transmit target source code to external services (exception: package metadata to PyPI/npmjs for version checking)
- Label all permission requests as `[Claude]` or `[software under test]`
- If a secret is found, do NOT print the full value â€” show first 8 chars + `...`
- Always capture stderr from every tool run â€” never swallow errors silently; surface in a "Tool Errors" section in the report
- Auto-cleanup is mandatory â€” delete all target files, sandbox outputs, and temp files after every scan regardless of how it ends (normal exit, error, or user interrupt)
- Never screenshot the VM terminal â€” stream logs in real time via `stream.log`; screenshots miss timing and can't be automated
- Only one sandbox instance at a time â€” check `Get-Process WindowsSandboxServer` before launch; the watchdog's PID guard handles this automatically but confirm on first run
- Never put config files in the output folder â€” the output folder is read-write for the sandbox, so a malicious target could modify its own config. Keep config in a separate read-only mapped folder
- **Folder isolation**: C:\sandbox\tool-output\ is the only sandbox-writable folder (for tool results). C:\sandbox\autoruns\ is host-only and never mapped into the sandbox — a malicious binary cannot overwrite the persistence baseline.
- **Path sanitization**: targetSlug and targetName must be stripped to [a-zA-Z0-9_-] before use in any file path or folder name — prevents path traversal from a repo named something like ../../Windows/System32/evil.
- Procmon filenames are timestamped â€” avoids overwrite prompts on retry; setup.ps1 must use `$ts = Get-Date -Format 'yyyyMMdd-HHmmss'` in the Procmon filename
- On any interrupted Full scan: check state file for `sac_original_state` and restore SAC before doing anything else
- On any interrupted Medium or Full scan: run the cleanup block from Phase 5 before exiting â€” never leave target files on the host
