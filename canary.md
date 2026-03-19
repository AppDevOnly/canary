---
description: Evaluate code for security issues, dependency vulnerabilities, bugs, and quality problems before installing
version: 2.3
---

# /canary
# canary-version: 2.3

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

1. Read the local skill file version from the `# /canary` header or the version line in `canary.md`
2. Fetch the remote version:
```bash
gh api repos/AppDevOnly/canary/contents/canary.md --jq '.content' | base64 -d | grep "Canary v"
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

Canary works best with specialized tools installed. Quick and Medium need very little. Full mode needs more — but canary walks the user through every install. No tool is skipped silently.

### Quick and Medium tools

| Tool | Required for | Install command |
|------|-------------|-----------------|
| `gh` | All GitHub targets | `winget install GitHub.cli` (Windows) / `brew install gh` (Mac/Linux) |
| `pip-audit` | Python CVE scanning | `pip install pip-audit` |
| `npm` | Node CVE scanning | Install Node.js from https://nodejs.org |
| `semgrep` | Multi-language static analysis | `pip install semgrep` |
| `bandit` | Python security linting | `pip install bandit` |
| `trufflehog` | Git history secrets scan | `winget install trufflesecurity.trufflehog` (Windows) / `brew install trufflehog` (Mac) |
| `gitleaks` | Fast secrets scan | `winget install gitleaks` (Windows) / `brew install gitleaks` (Mac) |

### Full mode tools (sandbox)

| Tool | Required for | Install |
|------|-------------|---------|
| Windows Sandbox | Isolated execution environment | Enable via Optional Features → Windows Sandbox (requires reboot) |
| Sysinternals Suite | Procmon (process monitor) + Autoruns (persistence baseline) | Download from Microsoft, extract to `C:\temp\security-tools\Sysinternals\` |
| Wireshark / tshark | Network capture | `winget install WiresharkFoundation.Wireshark` |
| Docker | Sandbox fallback (Linux/Mac) | `winget install Docker.DockerDesktop` |

### Tool install behavior

Full mode requires participation from the user — several tools need to be installed on their machine before the scan can run. This is expected and normal. When a tool is missing:

Tell the user: "Full mode uses several specialized tools to give you a complete picture. Some of these may not be installed yet — I'll check right now and walk you through anything that's missing. Each install takes about a minute and I'll handle it step by step. Once everything's ready I'll run the scan without interrupting you again."

Then for each missing tool: "I need [tool] to [do X]. Want me to walk you through installing it? It'll take about [time]. Once it's installed I'll pick up right where we left off."

Install, verify, and continue. Never skip a tool silently — note it as a limitation in the report if the user declines.

---

## Phase 1 — Identify the target

Parse `<target>`:
- **GitHub URL** → fetch repo contents via GitHub API (no clone needed for static analysis)
- **Local path** → read files directly
- **`pip:<name>`** → fetch from PyPI: source tarball or wheel, read metadata + scripts
- **`npm:<name>`** → fetch from npmjs: read package.json, scripts, index

If no target is provided, ask the user what they'd like to evaluate and explain the supported formats.

**After the user chooses a tier, present a single consent summary before doing anything else:**

Tailor the consent block to the chosen tier. Use this exact template:

> "Here's everything I'll do during this [Quick / Medium / Full] evaluation — I'll ask once and then run without interruptions.
>
> **[Claude] — all of this is me, not the software being evaluated:**
> - Fetch repo metadata and file tree from GitHub API
> - Read source files directly from GitHub (no download to your machine)
> - Search for secrets, hardcoded credentials, and suspicious patterns in the code
> *(Medium + Full only)* Run `semgrep`, `bandit`, `trufflehog`, and `gitleaks` on your machine for deeper static analysis
> *(Medium + Full only)* Run `pip-audit` and/or `npm audit` to check dependencies for known CVEs
> *(Medium + Full only)* Check tool availability — walk you through any missing installs before starting
> - Write a report to `~/canary-reports/`
> - Save a note to memory so future sessions know this eval is done
>
> *(Full only)* **[software under test] — this is the code running on your machine:**
> - Download the target release binary to a temporary folder
> - Launch Windows Sandbox (or Docker) and run the software inside it
> - Observe what network connections it makes, what files it creates, whether it tries to persist
> - Sandbox is destroyed after evaluation — nothing persists to your main system
>
> Ready to proceed?"

Wait for a yes before starting. Do not ask for permission again during the evaluation unless a genuinely unexpected action comes up that wasn't listed above.

**After the user chooses Full mode, run a preflight check before touching the target:**

Tell the user upfront: "Full mode uses several specialized tools to give you a complete picture. Some of these may not be installed yet — I'll check right now and walk you through anything that's missing. Each install takes about a minute and I'll handle it step by step. Once everything's ready I'll run the scan without interrupting you again."

Check all tools in one pass:
```bash
gh auth status
pip-audit --version
npm --version
semgrep --version
bandit --version
trufflehog --version
gitleaks version
tshark --version
```
```powershell
Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
Test-Path 'C:\temp\security-tools\Sysinternals\Procmon64.exe'
Test-Path 'C:\temp\security-tools\Sysinternals\Autoruns64.exe'
```

Handle all missing tools now, before Phase 2. Walk through each install one at a time — confirm it works before moving to the next.

For Quick and Medium, only check `gh`, `pip-audit`, `npm`, `semgrep`, `bandit`, `trufflehog`, and `gitleaks` — sandbox tools aren't needed.

**Before starting, tell the user:**

> "Canary v2.3
>
> Everything I do during this evaluation is [Claude] — I'm fetching and reading code on your behalf using the GitHub API and other tools. I won't run anything from this software on your machine unless you choose Full mode, in which case those actions will be clearly labeled [software under test] and I'll confirm with you before running anything."

Then ask:

> "How thorough should I be?
>
> - **Quick** — I'll scan the most important files (entry points, install scripts, anything that runs at startup) for red flags. Takes about a minute.
> - **Medium** — I'll read the full codebase, check all dependencies for known security vulnerabilities, scan for accidentally committed secrets, and assess code quality. Takes a few minutes.
> - **Full** — Everything in Medium, plus I'll run it in an isolated sandbox and watch what it actually does on your machine (what network connections it makes, what files it touches, whether it tries to persist anything). Takes longer and requires Windows Sandbox, Wireshark, and Sysinternals. If any of these aren't installed, I'll walk you through it — each takes about a minute."

---

## Phase 2 — Static security analysis

### 2a. Code inspection

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

### 2b. Semgrep static analysis

**Medium and above only.**

If semgrep is available, run against the local clone or downloaded source:
```bash
semgrep --config=auto --json 2>/dev/null | grep -i "severity\|message\|path\|line"
```

Focus on HIGH and CRITICAL findings. Skip INFO-level noise. If semgrep isn't available, note it in the report and rely on manual code inspection.

### 2c. Bandit (Python projects only)

**Medium and above only.**

If the project is Python and bandit is available:
```bash
bandit -r . -f json 2>/dev/null | grep -i "issue_severity\|issue_text\|filename\|line_number"
```

Flag HIGH and MEDIUM severity findings. Cross-reference with manual code inspection — bandit has false positives.

### 2d. Secrets scan

**Medium and above only.**

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

### 2e. Dependency audit

**Medium and above only.**

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

### 2f. License compliance

**Medium and above only.**

Summarize licenses used by direct dependencies. Flag:
- GPL/AGPL in commercial contexts — MEDIUM (may require source disclosure)
- Unknown/unlicensed packages — HIGH (legal risk)
- License mismatches (project claims MIT but depends on GPL)

---

## Phase 3 — Code quality assessment

**Medium and above only.**

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

---

## Phase 4 — Dynamic sandbox (full mode only)

*Skip this phase if the user chose Quick or Medium, or if no sandbox is available.*

**Important:** Before running anything from the target, warn the user if static analysis already found serious issues (CRITICAL findings). Give them the option to stop here rather than run potentially hostile code even in a sandbox.

If Windows Sandbox is available:

**Autoruns baseline — run before launching the sandbox:**

```powershell
$autorunsExe = 'C:\temp\security-tools\Sysinternals\Autoruns64.exe'
if (Test-Path $autorunsExe) {
    & $autorunsExe /accepteula /a * /x /c C:\sandbox\output\autoruns-before.csv
    Write-Host "Autoruns baseline saved."
}
```

After the sandbox run, take a second snapshot and diff the two to detect any persistence the software attempted to install. Flag any new entries as HIGH.

**Pre-flight: check Smart App Control (SAC) state before launching.**

```powershell
powershell -NoProfile -Command "(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState"
```

- `0` = Off — proceed normally
- `1` = Evaluation mode — unsigned binaries may be blocked; warn the user
- `2` = On — unsigned binaries **will** be blocked; warn the user that dynamic analysis results may be limited

If SAC is On or Evaluation, tell the user:
> "Smart App Control is active on your machine. This may prevent unsigned binaries from running inside the sandbox. I'll attempt to disable it for the sandbox session, but if the binary is blocked, I'll note it as a finding and write the report based on static analysis."

Before launching, warn the user:

> "I'm about to start the sandbox. Here's what to expect:
> - A Windows Sandbox window will open — this is normal. Don't close it.
> - Additional windows may appear as the software launches inside the sandbox.
> - **You don't need to interact with any of those windows.** Just keep an eye on this Claude window — I'll report everything I observe here as it happens.
> - When the evaluation is done, the sandbox will close automatically and I'll write the report.
> - **If anything looks wrong or gets stuck, just tell me in plain English** — describe what you're seeing and I'll figure out what to do. You don't need to know any commands."

**After the sandbox run, read `stream.log` and `setup.log` to determine outcome:**

- If `setup.log` contains `"RESULT: Binary could not be launched"` — **do not retry**. Record as a sandbox finding: "Binary blocked — likely SAC/WDAC policy or missing dependency. Dynamic analysis not possible on this system without further configuration." Proceed to write the report.
- If the sandbox exited before `setup.log` appeared (mapped-folder failure) — retry **once only**, then report the failure.
- If the binary launched successfully — report network connections, file/registry artifacts, and persistence behavior from the logs.

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

**Write `setup.ps1` for this target** (generated fresh — see Phase 4 setup script guidance below), then launch:

```powershell
powershell -NoExit -File C:\sandbox\scripts\run-watchdog.ps1 -WsbFile $wsbPath
```

Monitor `C:\sandbox\output\stream.log` in real time. Report progress to the user as it streams.

```
→ Use the /test-install protocol for full sandbox evaluation
→ See ~/.claude/commands/test-install.md for the complete sandbox procedure
```

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

Write the report to `~/canary-reports/<target-name>-<date>-canary-report.md`

Format for plain-text readability — no markdown tables, no `---` dividers, no heavy bold syntax. The report must look clean when viewed as raw text in an editor, not just when rendered.

```
# Canary Security Report: <target>

Date: <date>
Target: <url or path>
Evaluation: <Quick / Medium / Full> — Static Analysis
Tool: Canary v2.3


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

After writing the report, ask the user: "Want me to save a note so future sessions know this evaluation is done?"

---

## Troubleshooting

At any point during the evaluation, the user can describe a problem in plain English and canary should respond helpfully. Examples:
- "something popped up asking me to allow a network connection" → advise what to do
- "the sandbox window closed early" → diagnose and offer to re-run
- "it's been sitting here for 5 minutes" → check what's stuck and recover
- "I see an error that says X" → interpret and fix

Never require the user to run commands themselves to diagnose an issue. If something is wrong, canary figures it out and handles it.

---

## Output rules

- **Verdict at the top** — ✅ / ⚠️ / ❌ — users need to see this immediately
- **Plain English** — explain what each finding means and why it matters, as if the user has no security background
- **Actionable** — every finding includes a suggested fix or workaround
- **Honest about limits** — note if a check wasn't possible (e.g. tool not installed, private repo)
- **Rate every finding:** CRITICAL / HIGH / MEDIUM / LOW / INFO
- **No unsolicited comparisons** — don't compare to other reports unless the user asks

---

## Edge cases

**No target provided:** Ask what they'd like to evaluate and show supported formats. Don't error.

**Resuming a paused evaluation:** If memory indicates an evaluation was paused waiting for tier selection, re-present the exact tier prompt from Phase 1 (Quick / Medium / Full with the canonical descriptions). Do not paraphrase or invent alternate tier names.

**Private repo / access failure:** Tell the user clearly: "I wasn't able to access this repo — it may be private or the URL may be incorrect. If it's private, make sure you're logged in with `gh auth login`."

**Monorepo / multi-package repo:** List the packages/apps found and ask which one(s) to evaluate, or offer to evaluate all of them.

**Target looks hostile during static analysis:** If CRITICAL findings appear before Phase 4, warn the user: "I've already found serious issues in the static analysis. Do you still want me to run this in a sandbox, or is the static report enough?" Don't proceed to sandbox automatically.

---

## Security rules (always enforce)

- Read source before running anything
- Never execute code from the target during static analysis
- Never transmit target source code to external services (exception: package metadata to PyPI/npmjs for version checking)
- Label all permission requests as `[Claude]` or `[software under test]`
- If a secret is found, do NOT print the full value — show first 8 chars + `...`
