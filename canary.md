---
description: Evaluate code for security issues, dependency vulnerabilities, bugs, and quality problems before installing
---

# /canary

Evaluate code before you trust it. Canary reads source code, checks for security issues, scans for known vulnerabilities, and can run the code in an isolated sandbox — then gives you a plain-English verdict.

## Usage
```
/canary <target>
```
Where `<target>` is a GitHub URL, local path, `pip:<package>`, or `npm:<package>`.

---

## Tool availability

**Always use `gh api <endpoint> --jq '<filter>'` for GitHub API calls and JSON parsing.** Do not use standalone `jq`, `python3`, or `python` for JSON parsing — they are not reliably available on Windows. If you need to parse JSON outside of a `gh api` call, use `grep` or string matching instead.

Before starting the evaluation, check for required tools and offer to install any that are missing. Do not skip silently — pause, walk the user through the install, then resume.

| Tool | Required for | Install command |
|------|-------------|-----------------|
| `gh` | All GitHub targets | `winget install GitHub.cli` (Windows) / `brew install gh` (Mac/Linux) |
| `pip-audit` | Python dependency audit | `pip install pip-audit` |
| `npm` | Node dependency audit | Install Node.js from https://nodejs.org |
| Docker | Full mode (sandbox fallback) | `winget install Docker.DockerDesktop` |
| Windows Sandbox | Full mode (preferred on Windows) | Enable via "Turn Windows features on or off" → Windows Sandbox |

If a tool is missing, say: "I need [tool] to [do X]. Want me to walk you through installing it? It'll take about [time]. Once it's installed I'll pick up right where we left off." Then install, verify, and continue.

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
> *(Medium + Full only)* Run `pip-audit` and/or `npm audit` on your machine to check for known CVEs
> *(Medium + Full only)* Read `~/.claude/settings.json` to check tool availability
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

Check all tools needed for Full mode in one pass:
- `gh auth status` — GitHub CLI authenticated
- `pip-audit --version` — Python dependency audit
- `npm --version` — Node dependency audit
- Windows Sandbox: `Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM` (PowerShell)
- Docker: `docker --version`

If anything is missing, handle all installs now before starting Phase 2. Tell the user: "Before I start, let me make sure you have everything needed for a Full evaluation. I found [X] missing. Let's get those installed now so the scan runs uninterrupted."

For Quick and Medium, only check `gh` — the other tools aren't needed.

**Before starting, tell the user:**

> "Canary v2.3
>
> Everything I do during this evaluation is [Claude] — I'm fetching and reading code on your behalf using the GitHub API and other tools. I won't run anything from this software on your machine unless you choose Full mode, in which case those actions will be clearly labeled [software under test] and I'll confirm with you before running anything."

Then ask:

> "How thorough should I be?
>
> - **Quick** — I'll scan the most important files (entry points, install scripts, anything that runs at startup) for red flags. Takes about a minute.
> - **Medium** — I'll read the full codebase, check all dependencies for known security vulnerabilities, scan for accidentally committed secrets, and assess code quality. Takes a few minutes.
> - **Full** — Everything in Medium, plus I'll run it in an isolated sandbox and watch what it actually does on your machine (what network connections it makes, what files it touches, whether it tries to persist anything). Takes longer and requires Windows Sandbox or Docker."

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

### 2b. Secrets scan

**Medium and above only.**

Search for patterns indicating hardcoded secrets:
- Long random strings adjacent to words: key, token, secret, password, api, auth
- AWS key patterns: `AKIA[0-9A-Z]{16}`
- Private key headers: `-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`
- Common service patterns: `sk-[a-zA-Z0-9]{32,}`, `ghp_[a-zA-Z0-9]{36}`

Report any matches with file + line number. Rate HIGH if found in committed source. Do NOT print the full value — show first 8 chars + `...`

### 2c. Dependency audit

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

### 2d. License compliance

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

Before launching, warn the user:

> "I'm about to start the sandbox. Here's what to expect:
> - A Windows Sandbox window will open — this is normal. Don't close it.
> - Additional windows may appear as the software launches inside the sandbox.
> - **You don't need to interact with any of those windows.** Just keep an eye on this Claude window — I'll report everything I observe here as it happens.
> - When the evaluation is done, the sandbox will close automatically and I'll write the report."

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
