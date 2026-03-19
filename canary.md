---
description: Evaluate code for security issues, dependency vulnerabilities, bugs, and quality problems before installing
version: 2.8
---

# /canary
# canary-version: 2.8

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
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
gh + gh auth login    GitHub only  GitHub only       required
pip / Python          —            inside sandbox    required
winget (Windows)      —            —                 required
semgrep               —            inside sandbox    inside sandbox
bandit                —            Python (sandbox)  Python (sandbox)
trufflehog            —            inside sandbox    inside sandbox
gitleaks              —            inside sandbox    inside sandbox
pip-audit             —            Python (sandbox)  Python (sandbox)
npm / npm audit       —            Node (sandbox)    Node (sandbox)
Admin rights          —            —                 required
Windows Sandbox       —            required          required
Sysinternals Suite    —            —                 required
tshark / Wireshark    —            —                 required
Canary sandbox scripts—            required          required
```

**Architecture note:** No scan tier ever clones or writes target code to the host machine.
- **Quick** — GitHub API only. Nothing touches your disk.
- **Medium** — Static analysis tools run inside Windows Sandbox. Only Claude's interpreted summary leaves the sandbox; raw tool output stays inside.
- **Full** — Same as Medium, plus the target binary runs inside the sandbox.

### Install commands

```
gh:           winget install GitHub.cli            (Windows)
              brew install gh                       (Mac/Linux)
semgrep:      pip install semgrep
bandit:       pip install bandit
trufflehog:   Download the v3 release binary from https://github.com/trufflesecurity/trufflehog/releases
              (do NOT use winget — the ID is wrong and falls back to pip which installs legacy v2.2.1)
              (do NOT use pip — pip installs v2.x; canary requires v3.x CLI syntax)
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

## Phase 0 — Resume check

Before doing anything else, check for an existing partial scan of this target.

Derive a target slug from the target string:
- `https://github.com/foo/bar` â†’ `github-foo-bar`
- `/path/to/project` â†’ last folder name, e.g. `local-project`
- `pip:requests` â†’ `pip-requests`
- `npm:lodash` â†’ `npm-lodash`

**Sanitize the slug immediately after deriving it** — strip every character that is not `[a-zA-Z0-9_-]`. This must happen before the slug is used in any file path, state file name, or folder name. A repo named `../../Windows/System32/evil` must produce a slug like `Windows-System32-evil`, not a path traversal.

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

- **Resume** — load existing findings from state file, skip completed phases, continue from next incomplete phase. **First check `cleanup_complete` in the state file** — if it is `false` and Phase 4 is in `phases_complete`, run the Phase 5 cleanup block before anything else (a previous scan may have left target files on the host).
- **Fresh** — delete state file, start over from Phase 1

If no state file exists, proceed normally.

---

## Phase 1 — Identify the target

Parse `<target>`:
- **GitHub URL** â†’ fetch repo contents via GitHub API (no clone needed for static analysis)
- **Local path** â†’ read files directly
- **`pip:<name>`** â†’ fetch from PyPI: source tarball or wheel, read metadata + scripts
- **`npm:<name>`** â†’ fetch from npmjs: read package.json, scripts, index

If no target is provided, ask the user what they'd like to evaluate and explain the supported formats.

**Offensive repo check:** Before presenting tier options, check the repo name and description for offensive security indicators: keywords such as `0day`, `exploit`, `poc`, `payload`, `shellcode`, `RAT`, `C2`, `backdoor`, `EXP`, `CVE` in the repo name, or descriptions mentioning "exploit collection", "proof of concept", or "offensive". If found:

> "Heads up — this repo appears to be offensive security tooling (exploit code, POCs, C2 framework, etc.). Canary can still evaluate it, but be aware:
> - Cloning or running any code from this repo may trigger your AV/EDR or violate corporate policy.
> - Static analysis tools may reproduce malicious signatures in their output.
> - Canary will only read files via the GitHub API — nothing will be cloned to your machine.
>
> Do you want to proceed with a Quick (API-only) evaluation?"

If the user wants to proceed: default them to Quick regardless of what they choose, and note the override in the report. Do not offer Medium or Full for repos flagged as offensive tooling.

**VirusTotal binary pre-scan (all tiers, GitHub targets only):**

Before presenting the tier menu, fetch the repo file tree and check for pre-compiled binaries:
```bash
gh api repos/{owner}/{repo}/git/trees/HEAD?recursive=1 \
  --jq '[.tree[] | select(.path | test("\\.(exe|dll|msi|pkg|dmg|deb|rpm|bin|so|dylib)$"; "i")) | {path: .path, sha: .sha}]'
```

If binaries are found and `VT_API_KEY` is set, scan up to 10 of them via VirusTotal URL scan. Rate limit: pause 15 seconds between submissions (free tier = 4 req/min).

For each binary, submit its raw GitHub URL:
```powershell
$rawUrl = "https://raw.githubusercontent.com/{owner}/{repo}/HEAD/$binaryPath"
$encoded = [uri]::EscapeDataString($rawUrl)
$submit = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/urls" -Method POST `
    -Headers @{"x-apikey" = $env:VT_API_KEY} `
    -Body "url=$encoded" -ContentType "application/x-www-form-urlencoded"
$analysisId = $submit.data.id
Start-Sleep -Seconds 20
$result = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/analyses/$analysisId" `
    -Headers @{"x-apikey" = $env:VT_API_KEY}
$stats = $result.data.attributes.stats
# stats.malicious, stats.suspicious, stats.undetected, stats.harmless
```

Report findings immediately — do not wait until Phase 5:
- `malicious > 0` → **CRITICAL** — flag the specific binary, count of engines detecting it, and stop to warn user before continuing
- `suspicious > 0` → **HIGH** — flag with count; note it may be a false positive (common for security tools and packers)
- `malicious = 0, suspicious = 0` → note as "VirusTotal: clean (N engines)"
- If more than 10 binaries exist: scan the 10 largest by file size, note count of unscanned in report

If `VT_API_KEY` is not set and binaries are found:
> "This repo contains [N] pre-compiled binaries (.exe, .dll, etc.) that I can't verify. VirusTotal integration isn't configured — I'd strongly recommend setting `VT_API_KEY` to check these against 70+ AV engines before using them. Continuing without binary hash checks."

If no binaries found: skip this step silently.

**VirusTotal binary hash check (all tiers, local path targets only):**

For local path targets, scan binaries on disk using SHA256 hash lookups — no upload, no URL needed. VT returns results instantly if the hash is known (most public software is indexed).

```powershell
$binaryExtensions = @('*.exe','*.dll','*.msi','*.bin','*.so','*.dylib','*.pkg','*.deb','*.rpm')
$binaries = $binaryExtensions | ForEach-Object {
    Get-ChildItem -Path $targetPath -Recurse -Filter $_ -ErrorAction SilentlyContinue
} | Sort-Object Length -Descending | Select-Object -First 10

foreach ($bin in $binaries) {
    $hash = (Get-FileHash -Algorithm SHA256 -Path $bin.FullName).Hash.ToLower()
    Write-Host "Checking $($bin.Name) ($hash)..."
    $result = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hash" `
        -Headers @{"x-apikey" = $env:VT_API_KEY} -ErrorAction SilentlyContinue
    if ($result.data.attributes.last_analysis_stats) {
        $stats = $result.data.attributes.last_analysis_stats
        # stats.malicious, stats.suspicious, stats.undetected, stats.harmless
    } else {
        Write-Host "$($bin.Name): not in VirusTotal database (never submitted — locally built or very new)"
    }
    Start-Sleep -Seconds 15  # free tier: 4 req/min
}
```

Report findings immediately using the same thresholds as the GitHub binary pre-scan:
- `malicious > 0` → **CRITICAL** — stop and warn before continuing
- `suspicious > 0` → **HIGH** — flag with count
- `malicious = 0, suspicious = 0` → "VirusTotal: clean (N engines)"
- Hash not found in VT → note as "Not in VT database" — flag as INFO if the binary claims to be a known public tool (mismatch is suspicious); expected for locally compiled code

If more than 10 binaries exist: scan the 10 largest, note count of unscanned in report.

If `VT_API_KEY` is not set and binaries are found:
> "This path contains [N] binaries (.exe, .dll, etc.) that I can't verify without VirusTotal. Set `VT_API_KEY` to check them against 70+ AV engines. Continuing without binary hash checks."

**VirusTotal package scan (all tiers, pip/npm targets only):**

For pip and npm targets, fetch the package download URL from the registry and submit to VT. The registry APIs are public — no auth needed.

**pip:**
```bash
# Get latest wheel or sdist download URL from PyPI
curl -s https://pypi.org/pypi/<package>/json | \
  grep -o '"url":"https://files.pythonhosted.org/[^"]*\.whl"' | head -1
# Fallback to sdist if no wheel:
curl -s https://pypi.org/pypi/<package>/json | \
  grep -o '"url":"https://files.pythonhosted.org/[^"]*\.tar\.gz"' | head -1
```

**npm:**
```bash
# Get tarball URL from npmjs registry
curl -s https://registry.npmjs.org/<package>/latest | grep -o '"tarball":"[^"]*"'
```

Once the URL is found, submit it to VT exactly as in the GitHub URL scan:
```powershell
$encoded = [uri]::EscapeDataString($packageUrl)
$submit = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/urls" -Method POST `
    -Headers @{"x-apikey" = $env:VT_API_KEY} `
    -Body "url=$encoded" -ContentType "application/x-www-form-urlencoded"
$analysisId = $submit.data.id
Start-Sleep -Seconds 20
$result = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/analyses/$analysisId" `
    -Headers @{"x-apikey" = $env:VT_API_KEY}
$stats = $result.data.attributes.stats
```

Same reporting thresholds: `malicious > 0` → CRITICAL (stop and warn), `suspicious > 0` → HIGH, clean → note engine count.

If the registry API call fails or returns no download URL: note it as a limitation and continue.

If `VT_API_KEY` is not set: skip silently — no binary warning needed here since the user is evaluating a named package, not dropping a mystery binary on their machine.

**Tell the user:**

> "Canary v2.8 — use at your own risk. Canary reduces risk but does not guarantee safety. Use your own judgment before installing any software.
>
> Everything I do during this evaluation is [Claude] — I'm fetching and reading code on your behalf. Nothing from this repo will be cloned or saved to your machine. If you choose Full mode, the software runs inside an isolated sandbox and those actions will be labeled [software under test]."

Then ask:

> "How thorough should I be?
>
> - **Quick** — I'll read the most important files via the GitHub API (entry points, install scripts, anything that runs at startup) and look for red flags using my own analysis. Nothing is cloned to your machine. No external tools needed. Takes about a minute.
> - **Medium** — I'll do a full static analysis using semgrep, bandit, trufflehog, and gitleaks — all running inside Windows Sandbox so nothing from the target touches your machine. Requires Windows Sandbox (built into Windows 10/11 Pro). Takes a few minutes.
> - **Full** — Everything in Medium, plus I'll run the software inside the sandbox and watch what it actually does (network connections, files touched, whether it tries to persist). Requires Windows Sandbox, Wireshark, and Sysinternals. If any of these aren't installed, I'll walk you through it."

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

**VirusTotal API key (optional but strongly recommended):**
```powershell
$env:VT_API_KEY
```
If not set:
> "VirusTotal integration isn't configured — I won't be able to check pre-compiled binaries against 70+ AV engines. This is especially important for repos that ship .exe or .dll files.
>
> To enable it: sign up free at https://www.virustotal.com, go to your profile → API Key, copy it, then set it with:
> `$env:VT_API_KEY = 'your-key-here'`
> Or add it to your PowerShell profile for persistence.
>
> Free tier gives 500 lookups/day — plenty for normal canary use. Continue without it?"

If user declines or skips: note "VirusTotal: not configured — binary hash checks skipped" in the report. Continue the scan.

### Dependency check — Medium

Run all Quick checks first, then:

**Check Windows Sandbox (required for Medium):**
```powershell
(Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -ErrorAction SilentlyContinue).State
```

If not Enabled:
> "Medium scan requires Windows Sandbox — static analysis tools run inside it so no target code or raw tool output ever touches your machine. Windows Sandbox isn't enabled yet.
>
> Options:
> - **Enable it now** — I'll run the command; requires a reboot, then come back and start the scan again.
> - **Switch to Quick** — I'll do an API-only evaluation. No sandbox needed, but no static analysis tools.
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

**Check runtime prerequisites first** — Python and Node must exist before pip/npm tool installs can work:
```bash
python --version 2>/dev/null || python3 --version 2>/dev/null && echo "Python: OK" || echo "Python: MISSING"
node --version 2>/dev/null && echo "Node: OK" || echo "Node: MISSING"
```
If Python is missing:
> "Python is required to install semgrep, bandit, and pip-audit. Install it from https://www.python.org/downloads/ (Windows) or `brew install python` (Mac). Let me know when it's done."
Stop here — do not attempt pip installs without Python.

If Node/npm is missing and the target has a `package.json`: note it as a limitation — npm audit will be skipped. Don't block the scan; note it in the report.

**Check pip version** — old pip can fail silently:
```bash
pip --version 2>/dev/null
```
If pip is available but older than 21.x: suggest `python -m pip install --upgrade pip` before installing other tools.

**Check static analysis tools** (these will run inside the sandbox, but we verify they're installed on the host so they can be mapped in):

Check trufflehog version specifically — must be v3.x:
```bash
trufflehog --version 2>/dev/null
```

- If **missing**: guide the user through the binary install:
  > "trufflehog needs to be installed from the GitHub releases page — do NOT use winget or pip, they both install the wrong version.
  >
  > 1. Go to https://github.com/trufflesecurity/trufflehog/releases/latest
  > 2. Download `trufflehog_X.X.X_windows_amd64.tar.gz`
  > 3. Extract it — you'll get `trufflehog.exe`
  > 4. Move it somewhere on your PATH, e.g. `C:\tools\trufflehog\trufflehog.exe`
  > 5. Add `C:\tools\trufflehog` to your PATH if it isn't already, or run it by full path
  >
  > Let me know when it's done and I'll verify the version."

  After user confirms: run `trufflehog --version` again and confirm it shows `3.x`.

- If **showing v2.x** (legacy pip install):
  > "You have trufflehog v2.x installed — that's the old pip version with a different CLI. Canary needs v3.x. Uninstall the old one with `pip uninstall trufflehog`, then follow the binary install steps above."

**semgrep:**
```bash
semgrep --version 2>/dev/null
```
- If missing: `pip install semgrep`, then verify: `semgrep --version 2>/dev/null && echo "OK" || echo "NOT ON PATH"`
- If not callable after install: pip --user installs on Windows often miss PATH. Ask the user to open a new terminal and try again. If still missing, find the Scripts folder: `python -m site --user-site` (Scripts is one level up from site-packages). Add it to PATH or note as a limitation.
- Known behavior: first run downloads rules and may take 30–60s — tell the user this is normal.

**bandit:**
```bash
bandit --version 2>/dev/null
```
- If missing: `pip install bandit`, then verify callable.
- If not callable after install: same PATH fix as semgrep.

**gitleaks:**
```bash
gitleaks version 2>/dev/null
```
- If missing on **Windows**: `winget install gitleaks`. If winget fails or isn't available, download the binary from https://github.com/gitleaks/gitleaks/releases/latest (`gitleaks_X.X.X_windows_x64.zip`), extract `gitleaks.exe`, place in a folder on PATH (e.g. `C:\tools\gitleaks\`).
- If missing on **Mac/Linux**: `brew install gitleaks`
- Verify after install: `gitleaks version` should show a version number.

**pip-audit:**
```bash
pip-audit --version 2>/dev/null
```
- If missing: `pip install pip-audit`, then verify callable.
- If not callable after install: same PATH fix as semgrep.

**npm:**
Already checked in the runtime prereq step above. If missing and the target has a `package.json`, note it as a scan limitation — npm audit will be skipped. Don't block the scan.

Show a clean summary to the user before asking to install anything:

> "Here's what I found on your machine:
> âœ… Windows Sandbox — enabled
> âœ… semgrep
> âœ… bandit
> â¬œ trufflehog — not installed (need v3.x from GitHub releases)
> â¬œ gitleaks — not installed
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

If the user declines any tool: note it as a limitation. Never skip silently — always record what was skipped and why.

### Dependency check — Full

Run all Medium checks first, then:

Check admin rights (required for Procmon, tshark, SAC registry):
```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```
If not admin:
> "Full mode needs administrator rights to run Procmon, tshark, and modify system settings. Please restart Claude Code as Administrator (right-click â†’ Run as administrator) and try again."
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
> "Sysinternals isn't installed at the expected path. Here's how to set it up:
> 1. Go to https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite
> 2. Download `SysinternalsSuite.zip`
> 3. Create the folder `C:\temp\security-tools\Sysinternals\` if it doesn't exist
> 4. Extract everything from the zip into that folder
> 5. You should now have `Procmon64.exe` and `autorunsc64.exe` in there
>
> Let me know when that's done and I'll continue."

After user confirms: verify both files exist before proceeding.

**tshark:**
```bash
tshark --version 2>/dev/null
```
- If missing on **Windows**: `winget install WiresharkFoundation.Wireshark`. This installs the full Wireshark suite which includes tshark. Requires a reboot or new terminal for PATH to update.
- If missing on **Mac**: `brew install wireshark` (includes tshark).
- Verify after install: `tshark --version` should show a version number. If not found after install, open a new terminal — Wireshark's installer updates PATH but the change isn't visible in the current session.
- Known issue on Windows: tshark requires Npcap (packet capture driver). The Wireshark installer includes it — accept the Npcap install prompt during setup.

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
> *(Medium + Full only)* Launch Windows Sandbox and run `semgrep`, `bandit`, `trufflehog`, and `gitleaks` inside it — nothing from the target is ever written to your machine; only my interpreted summary leaves the sandbox
> *(Medium + Full only)* Run `pip-audit` and/or `npm audit` inside the sandbox to check dependencies for known CVEs
> - Write a report to `~/canary-reports/`
> - Delete all target files (clone, downloads, sandbox output) after the report is written
> - Save scan progress after each step so you can resume if anything interrupts
>
> *(Full only)* **[software under test] — this is the code running inside the sandbox:**
> - Clone the target repo and download the release binary inside the sandbox
> - Run the software inside Windows Sandbox — it cannot touch your files, browser, or main system
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
  "sac_original_state": null,
  "cleanup_complete": false
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

**File count guard:** Cap reads at 500 files maximum. Use the GitHub API file tree to count files first. If the repo has more than 500 files, apply this priority order and stop when the cap is reached:
1. Entry points and install scripts (always read)
2. Files containing network/subprocess/eval patterns (search via API)
3. Files in `src/`, `lib/`, `core/` directories
4. Remaining files sorted by extension risk: `.py > .js > .ts > .sh > .ps1 > .go > other`

If the cap is reached, note it in the report: "File count capped at 500 of [N] total — [N] files not reviewed." This prevents exhausting the GitHub API rate limit (5,000 req/hour) on large repos.

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

### 2bâ€“2d. Sandbox static analysis (Medium and Full)

**Medium and above only. All static analysis tools run inside Windows Sandbox — nothing from the target is written to the host machine.**

**Architecture:** Generate a Medium-mode sandbox config that:
1. Maps trufflehog and gitleaks binaries from host into sandbox (read-only) using paths discovered in the dep check
2. Maps `C:\sandbox\tool-output\` host folder into sandbox as `C:\sandbox\tool-output\` (read-write) — this is where tool results land
3. Clones the target repo inside the sandbox (no clone on host)
4. Installs Python-based tools (semgrep, bandit, pip-audit) fresh inside the sandbox via pip
5. Runs all static analysis tools inside the sandbox
6. Claude reads only the summarized output from the mapped tool-output folder — raw JSON is never reproduced in Claude's context

**10-minute hard timeout:** The Medium sandbox launch must complete within 10 minutes. If no `RESULT:` line appears in `setup-static.log` within 600 seconds of launch, kill the sandbox process, log `TIMEOUT: static analysis did not complete within 10 minutes`, and proceed to the report with whatever partial output exists.

**Before launching the Medium sandbox, create the output directory if it doesn't exist:**
```powershell
New-Item -ItemType Directory -Force -Path 'C:\sandbox\tool-output' | Out-Null
```

**Generate `.wsb` config for static analysis (Medium):**

Build a target-specific .wsb that maps:
- `C:\sandbox\scripts\` â†’ `C:\sandbox\scripts\` (read-only — bootstrap and setup scripts)
- `C:\sandbox\tool-output\` â†’ `C:\sandbox\tool-output\` (read-write — tool results)
- The directory containing the trufflehog binary (from `$trufflehogPath` in state) â†’ `C:\tools\trufflehog\` (read-only)
- The directory containing the gitleaks binary (from `$gitleaksPath` in state) â†’ `C:\tools\gitleaks\` (read-only)

No Sysinternals mapping needed for Medium (no process monitoring).
No target binary download needed (tools run against cloned source).

**Generate `C:\sandbox\scripts\setup-static.ps1`** with the following behavior inside the sandbox:

```powershell
# Inside sandbox — runs as part of bootstrap
Set-ExecutionPolicy Bypass -Scope Process -Force
New-Item -ItemType Directory -Force -Path 'C:\sandbox\tool-output' | Out-Null
Start-Transcript 'C:\sandbox\tool-output\setup-static.log'

# 1. Install Python analysis tools fresh inside sandbox
Write-Host "Installing Python tools..."
pip install --quiet semgrep bandit pip-audit 2>'C:\sandbox\tool-output\pip-install-stderr.txt'
Write-Host "Pip install stderr: $(Get-Content 'C:\sandbox\tool-output\pip-install-stderr.txt' -Raw)"

# 2. Clone the target repo (hooks disabled — prevents hook execution during clone)
$targetUrl = '{{TARGET_CLONE_URL}}'
$cloneDir  = 'C:\target'
git clone --depth 1 --config core.hooksPath=NUL $targetUrl $cloneDir 2>&1
if (-not (Test-Path $cloneDir)) {
    Write-Host "RESULT: Clone failed"
    Stop-Transcript; exit 1
}
Write-Host "Clone complete — $((Get-ChildItem $cloneDir -Recurse -File).Count) files"

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
} else { Write-Host "SKIP bandit — no Python files found" }

# 5. Run trufflehog (mapped binary from host)
$trufflehogExe = 'C:\tools\trufflehog\{{TRUFFLEHOG_BIN}}'
if (Test-Path $trufflehogExe) {
    Write-Host "Running trufflehog..."
    & $trufflehogExe filesystem $cloneDir --json 2>'C:\sandbox\tool-output\trufflehog-stderr.txt' |
        Out-File 'C:\sandbox\tool-output\trufflehog.json' -Encoding UTF8
    if ($LASTEXITCODE -ne 0) {
        Write-Host "TOOL ERROR trufflehog exit=$LASTEXITCODE stderr=$(Get-Content 'C:\sandbox\tool-output\trufflehog-stderr.txt' -Raw)"
    } else { Write-Host "trufflehog complete" }
} else { Write-Host "SKIP trufflehog — binary not found at $trufflehogExe" }

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
} else { Write-Host "SKIP gitleaks — binary not found at $gitleaksExe" }

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
- `{{TARGET_CLONE_URL}}` — the target's GitHub URL (e.g. `https://github.com/foo/bar`)
- `{{TRUFFLEHOG_BIN}}` — filename of the trufflehog binary (basename of `$trufflehogPath`)
- `{{GITLEAKS_BIN}}` — filename of the gitleaks binary (basename of `$gitleaksPath`)

**Launch the Medium sandbox and wait for completion:**

Write the generated .wsb and setup-static.ps1 files, then launch:
```powershell
$wsbPath = "C:\sandbox\$targetName-static.wsb"
$generatedWsb | Out-File $wsbPath -Encoding UTF8 -Force
Start-Process WindowsSandbox -ArgumentList $wsbPath -WindowStyle Normal
Write-Host "Medium sandbox launched - waiting for static analysis (max 10 min)..."
```

Poll `C:\sandbox\tool-output\setup-static.log` for the `RESULT:` line (written by setup-static.ps1 on completion):
```powershell
$deadline = (Get-Date).AddSeconds(600)
$resultFound = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 15
    $log = Get-Content 'C:\sandbox\tool-output\setup-static.log' -ErrorAction SilentlyContinue
    if ($log -match 'RESULT:') {
        $resultFound = $true
        Write-Host "Static analysis complete."
        break
    }
    $elapsed = [int]((Get-Date) - ($deadline.AddSeconds(-600))).TotalSeconds
    Write-Host "Still running - ${elapsed}s elapsed. Watching for RESULT..."
}
if (-not $resultFound) {
    Get-Process -Name WindowsSandboxClient, WindowsSandboxServer -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host "TIMEOUT: static analysis did not complete within 10 minutes"
    # Continue to report with whatever partial output exists in C:\sandbox\tool-output\
}
```

Tell the user: "Sandbox analysis [complete / timed out after 10 minutes]. Reading results..."

**Critical rules for all tool output:**
- Never print raw JSON blobs into Claude's conversation — always parse and summarize
- Always capture stderr from every tool run; surface errors in a "Tool Errors" section in the report
- If a tool crashes (non-zero exit + no output file), log it as a tool error — do NOT silently skip
- If semgrep crashes with a Unicode error: log the offending file path, skip it, continue full-scope scan — do NOT narrow the scan directory
- If a tool output file is empty or missing after the sandbox run, note it as a tool error

**After sandbox completes, read results from `C:\sandbox\tool-output\`:**

**2b — Semgrep findings:**

**Progress:** "Reading semgrep results..." When done: "Semgrep complete — [N findings / no findings / tool error: X]."

Parse `C:\sandbox\tool-output\semgrep.json`. Focus on HIGH and CRITICAL findings. Skip INFO-level noise.

**2c — Bandit findings (Python only):**

**Progress:** "Reading bandit results..." When done: "Bandit complete — [N findings / no findings]."

Parse `C:\sandbox\tool-output\bandit.json`. Flag HIGH and MEDIUM severity. Cross-reference with manual code inspection — bandit has false positives.

**2d — Secrets scan:**

**Progress:** "Reading secrets scan results..." When done: "Secrets scan complete — [N secrets found / no secrets found]."

Parse `C:\sandbox\tool-output\trufflehog.json` and `C:\sandbox\tool-output\gitleaks.json`.

Report any matches with file + line number. Rate HIGH if found in committed source. Do NOT print the full value — show first 8 chars + `...`

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
- GPL/AGPL in commercial contexts — MEDIUM (may require source disclosure)
- Unknown/unlicensed packages — HIGH (legal risk)
- License mismatches (project claims MIT but depends on GPL)

Save state after 2f completes.

---

## Phase 3 — Code quality assessment

**Medium and above only.**

**Execution model:** This phase uses source files already fetched via the GitHub API in Phase 2a. No additional tool execution, sandbox launch, or network calls are needed. All analysis is performed by Claude on the already-fetched code.

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

**Autoruns baseline and tshark capture — run before launching the sandbox:**


```powershell
New-Item -ItemType Directory -Force -Path 'C:\sandbox\autoruns' | Out-Null
New-Item -ItemType Directory -Force -Path 'C:\sandbox\tool-output' | Out-Null
$autorunsExe = 'C:\temp\security-tools\Sysinternals\autorunsc64.exe'
Write-Host "Taking Autoruns before-snapshot..."
& $autorunsExe /accepteula '-a' '*' -c -h -s -nobanner -o 'C:\sandbox\autoruns\autoruns-before.csv' '*'

# Start tshark BEFORE sandbox launches - captures all early network activity including sandbox boot
$tsharkProc = Start-Process tshark -ArgumentList '-i "vEthernet (Default Switch)" -w C:\sandbox\tool-output\network-capture.pcap' -PassThru -WindowStyle Hidden
Write-Host "tshark capture started (PID $($tsharkProc.Id)) on vEthernet (Default Switch)"
```

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

**VirusTotal scan of download URL (Full mode, if VT_API_KEY is set):**

Before launching the sandbox, check the download URL against VirusTotal. This catches trojanized release binaries that pass static analysis clean.

```powershell
if ($env:VT_API_KEY -and $targetUrl) {
    Write-Host "Checking download URL against VirusTotal..."
    $encoded = [uri]::EscapeDataString($targetUrl)
    $submit = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/urls" -Method POST `
        -Headers @{"x-apikey" = $env:VT_API_KEY} `
        -Body "url=$encoded" -ContentType "application/x-www-form-urlencoded" `
        -ErrorAction SilentlyContinue
    if ($submit.data.id) {
        $analysisId = $submit.data.id
        Start-Sleep -Seconds 20
        $result = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/analyses/$analysisId" `
            -Headers @{"x-apikey" = $env:VT_API_KEY} -ErrorAction SilentlyContinue
        $stats = $result.data.attributes.stats
        # stats.malicious, stats.suspicious, stats.undetected, stats.harmless
        if ($stats.malicious -gt 0) {
            Write-Host "CRITICAL: VirusTotal flagged download URL — $($stats.malicious) engines detect malicious content"
        } elseif ($stats.suspicious -gt 0) {
            Write-Host "HIGH: VirusTotal flagged download URL as suspicious — $($stats.suspicious) engines"
        } else {
            Write-Host "VirusTotal: download URL clean ($($stats.undetected + $stats.harmless) engines checked)"
        }
    } else {
        Write-Host "VirusTotal: URL submission failed (API error or rate limit) — proceeding without check"
    }
} else {
    Write-Host "VirusTotal: skipped (VT_API_KEY not set)"
}
```

If `malicious > 0`: stop before launching the sandbox and warn the user:
> "VirusTotal flagged the download URL as malicious ([N] engines). This is a strong signal the release binary has been tampered with or is outright malware. I strongly recommend not running this in the sandbox. Do you want to abort?"

Wait for explicit confirmation before proceeding if flagged malicious.

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

**While monitoring `C:\sandbox\tool-output\stream.log`, give the user a heartbeat every 30 seconds:**
> "Still running — [elapsed]s. You'll see output here as it comes in. Nothing to do — just keep an eye on this window."

**When stream.log shows a retry attempt:**
Tell the user immediately:
> "The sandbox stopped responding — restarting automatically. Attempt [N] of 2. Everything we've found so far is saved."

**Stop tshark after the sandbox closes:**

```powershell
Stop-Process -Id $tsharkProc.Id -Force -ErrorAction SilentlyContinue
Write-Host "tshark capture stopped"
```

**After the sandbox run, read `stream.log` and `setup.log` to determine outcome:**

- If `setup.log` contains `"RESULT: Binary could not be launched"` — **do not retry**. Record as a sandbox finding: "Binary blocked — likely SAC/WDAC policy or missing dependency. Dynamic analysis not possible on this system without further configuration." Proceed to write the report.
- If the sandbox exited before `setup.log` appeared (mapped-folder failure) — retry **once only**, then report the failure.
- If the binary launched successfully — run post-run analysis before writing the report.

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

**PID chain analysis** — the network log shows *where* connections went; the PID chain shows *who made them*. This catches process injection, LOL-bins, and unexpected child process spawning.

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

## Phase 5 — Cleanup and write the report

**Cleanup before writing the report** — delete all target files from the host regardless of scan outcome:

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

Update state to record cleanup completed (in case scan was interrupted and resume is triggered):
```powershell
$state = Get-Content "$HOME\canary-reports\$targetSlug-state.json" | ConvertFrom-Json
$state | Add-Member -NotePropertyName cleanup_complete -NotePropertyValue $true -Force
$state | ConvertTo-Json | Out-File "$HOME\canary-reports\$targetSlug-state.json" -Encoding UTF8 -Force
```

Note the cleanup result in the report. If deletion failed for any file, log the path and reason — do not silently skip.

**Progress:** "Writing report..."

Write the report to `~/canary-reports/<target-name>-<date>-canary-report.md`

Format for plain-text readability — no markdown tables, no `---` dividers, no heavy bold syntax. The report must look clean when viewed as raw text in an editor, not just when rendered.


**Verdict selection (internal — do not write this block into the report):**
- Safe: no significant findings; normal use path is low risk
- Caution: notable findings the user should review; risks are manageable with care
- Unsafe (hidden threat): malicious behavior found — C2, credential theft, auto-execution
- Unsafe (dangerous by design): normal use path exposes serious risk without a hidden backdoor — exploit collections, C2 tools, repos where AV triggers on clone. Make the distinction explicit in the report.

```
# Canary Security Report: <target>

Date: <date>
Target: <url or path>
Evaluation: <Quick / Medium / Full> — Static Analysis
Tool: Canary v2.8


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


## VirusTotal

Include this section only if VT_API_KEY was set during the scan. If not configured, write:
"Not evaluated — set VT_API_KEY to enable binary hash checks against 70+ AV engines."

If configured, report results for each binary scanned:
  Binary: <filename>
  Engines checked: <N>
  Detections: <N malicious, N suspicious> — or "Clean"

If the download URL was scanned (Full mode):
  Download URL: <url (truncated if long)>
  Detections: <N malicious, N suspicious> — or "Clean"

If binaries were present but the cap of 10 was hit, note how many were scanned vs total.


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

If the repo has unverified binaries, high-severity findings, or any sandbox-worthy behavior (even if verdict is âš ï¸ Caution), include:
  - "To observe what this software actually does at runtime, run `/canary <target> full` — this runs it inside Windows Sandbox with network and process monitoring."


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
Canary v2.8 — use at your own risk. This tool reduces risk but does not guarantee safety.
No security evaluation is a substitute for your own judgment. Review findings before
installing any software. Report issues at https://github.com/AppDevOnly/canary
```

Cache read % = cache_read / (input + cache_read) * 100, rounded to nearest integer.
```

After writing the report, delete the state file — the scan is complete:
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

- **Verdict at the top** — âœ… / âš ï¸ / âŒ — users need to see this immediately
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

- **Never clone target code to the host machine** — Quick uses GitHub API only; Medium and Full clone inside sandbox only; no scan tier ever writes target code to the host filesystem
- **Never write raw tool output (JSON, log files) to Claude's context as code blocks** — parse and summarize; raw exploit signatures in tool output can trigger AV on host
- Read source before running anything
- Never execute code from the target during static analysis phases (2a-2d)
- Never transmit target source code to external services (exception: package metadata to PyPI/npmjs for version checking)
- Label all permission requests as `[Claude]` or `[software under test]`
- If a secret is found, do NOT print the full value — show first 8 chars + `...`
- Always capture stderr from every tool run — never swallow errors silently; surface in a "Tool Errors" section in the report
- Auto-cleanup is mandatory — delete all target files, sandbox outputs, and temp files after every scan regardless of how it ends (normal exit, error, or user interrupt)
- Never screenshot the VM terminal — stream logs in real time via `stream.log`; screenshots miss timing and can't be automated
- Only one sandbox instance at a time — check `Get-Process WindowsSandboxServer` before launch; the watchdog's PID guard handles this automatically but confirm on first run
- Never put config files in the output folder — the output folder is read-write for the sandbox, so a malicious target could modify its own config. Keep config in a separate read-only mapped folder
- **Folder isolation**: C:\sandbox\tool-output\ is the only sandbox-writable folder (for tool results). C:\sandbox\autoruns\ is host-only and never mapped into the sandbox — a malicious binary cannot overwrite the persistence baseline.
- **Path sanitization**: targetSlug and targetName must be stripped to [a-zA-Z0-9_-] before use in any file path or folder name — prevents path traversal from a repo named something like ../../Windows/System32/evil.
- Procmon filenames are timestamped — avoids overwrite prompts on retry; setup.ps1 must use `$ts = Get-Date -Format 'yyyyMMdd-HHmmss'` in the Procmon filename
- On any interrupted Full scan: check state file for `sac_original_state` and restore SAC before doing anything else
- On any interrupted Medium or Full scan: run the cleanup block from Phase 5 before exiting — never leave target files on the host
