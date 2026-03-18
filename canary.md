---
description: Evaluate code for security issues, dependency vulnerabilities, bugs, and quality problems before installing
---

# /canary

Evaluate code before you trust it. Canary checks GitHub repos, local projects, pip packages, and npm packages for security issues, dependency vulnerabilities, hardcoded secrets, bugs, and code quality problems.

## Usage
```
/canary <target>
```
Where `<target>` is a GitHub URL, local path, `pip:<package>`, or `npm:<package>`.

## What Canary does

1. **Static analysis** — read source before anything runs; flag suspicious patterns
2. **Secrets scan** — detect hardcoded API keys, tokens, credentials
3. **Dependency audit** — CVEs, outdated packages, license issues
4. **Code quality** — bad practices, anti-patterns, complexity, missing tests
5. **Dynamic sandbox** *(if available)* — run in isolation with network + process monitoring
6. **Structured report** — verdict, findings table, fix recommendations

---

## Phase 1 — Identify the target

Parse `<target>`:
- **GitHub URL** → fetch repo contents via GitHub API (no clone needed for static analysis)
- **Local path** → read files directly
- **`pip:<name>`** → fetch from PyPI: source tarball or wheel, read metadata + scripts
- **`npm:<name>`** → fetch from npmjs: read package.json, scripts, index

Ask the user: "I'll evaluate `<target>`. Should I just do a quick static check, or run it in a sandbox too? (quick / full)"
- **Quick** — static analysis only (Phases 2–4). Faster, no sandbox needed.
- **Full** — static + dynamic sandbox run (all phases). Requires Windows Sandbox or Docker.

---

## Phase 2 — Static security analysis

### 2a. Code inspection

Read these files first (in order of risk):
1. Entry points: `__main__.py`, `main.py`, `index.js`, `cli.py`, `app.py`
2. Install/setup scripts: `setup.py`, `pyproject.toml`, `package.json`, `Makefile`, `*.sh`, `*.ps1`
3. Any file with network calls, subprocess calls, or `eval()`/`exec()`

Flag these patterns (rate each CRITICAL / HIGH / MEDIUM / LOW / INFO):

| Pattern | Severity | Example |
|---|---|---|
| `eval()` / `exec()` on external input | CRITICAL | `eval(response.text)` |
| Subprocess with shell=True on external input | CRITICAL | `subprocess.run(user_input, shell=True)` |
| Hardcoded IP addresses (non-localhost) | HIGH | `"192.168.1.100"` in source |
| Outbound connections to unexpected domains | HIGH | `requests.get("http://evil.com")` |
| `os.system()` / `subprocess` calls | MEDIUM | May be legitimate; check args |
| `install_requires` with no version pins | MEDIUM | Unpinned deps allow supply chain attacks |
| `postinstall` / `prepare` scripts in package.json | HIGH | Runs at install time, before user review |
| `__import__` / dynamic imports | MEDIUM | Can obfuscate what's loaded |
| Base64-encoded strings | HIGH | Common obfuscation technique |
| Writes to startup/autorun locations | CRITICAL | Registry Run keys, ~/.bashrc, cron |

### 2b. Secrets scan

Search for patterns indicating hardcoded secrets:

```
# Key patterns to search:
- [A-Za-z0-9]{32,} adjacent to words: key, token, secret, password, api, auth
- AWS key patterns: AKIA[0-9A-Z]{16}
- Private key headers: -----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----
- Common service patterns: sk-[a-zA-Z0-9]{32,}, ghp_[a-zA-Z0-9]{36}
```

Report any matches with file + line number. Rate HIGH if found in committed source.

### 2c. Dependency audit

**Python projects** — check `requirements.txt`, `pyproject.toml`, `setup.py`:
```bash
pip-audit -r requirements.txt --format json 2>/dev/null || echo "pip-audit not available"
```

**Node projects** — check `package.json`:
```bash
npm audit --json 2>/dev/null || echo "npm audit not available"
```

If audit tools aren't available, manually check the top-level dependencies against known CVE patterns and flag any that are:
- More than 2 major versions behind latest
- Known to have had critical CVEs (e.g., `log4j`, `lodash < 4.17.21`, `requests < 2.20.0`)

### 2d. License compliance

Summarize licenses used by direct dependencies. Flag:
- GPL/AGPL in commercial contexts (MEDIUM — may require source disclosure)
- Unknown/unlicensed packages (HIGH — legal risk)
- License mismatches (e.g., project claims MIT but depends on GPL)

---

## Phase 3 — Code quality assessment

Rate each finding CRITICAL / HIGH / MEDIUM / LOW / INFO.

**Anti-patterns to flag:**
- Imports inside try/except blocks (obscures dependencies, hides silent failures)
- Bare `except:` without exception type (swallows all errors silently)
- Mutable default arguments (`def foo(x=[])`)
- `TODO`/`FIXME`/`HACK` comments in critical paths
- No test files present (`test_*.py`, `*.test.js`, `spec/`)
- Test coverage below 30% if coverage data available
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

*Skip this phase if user chose "quick" or no sandbox is available.*

If Windows Sandbox is available:
```
→ Use the /test-install protocol for full sandbox evaluation
→ See ~/.claude/commands/test-install.md for the complete sandbox procedure
```

If Docker is available (cross-platform fallback):
```bash
# Build a minimal isolation container
docker run --rm --network=none -v "$(pwd):/target:ro" python:3.11-slim bash -c "
    cd /target && pip install . 2>&1 | tail -20
    echo 'Install complete'
"
```

Note: Docker provides filesystem isolation but limited network/process monitoring compared to Windows Sandbox.

---

## Phase 5 — Write the report

Write the report to:
- **Local:** `~/canary-reports/<target-name>-<date>-canary-report.md`

Structure:

```markdown
# Canary Report: <target> — <date>

## Verdict
✅ Safe / ⚠️ Caution / ❌ Unsafe

**One-sentence summary of why.**

---

## Findings

| # | Severity | Category | Finding | File:Line |
|---|---|---|---|---|
| 1 | CRITICAL | Security | ... | src/main.py:42 |
| 2 | HIGH | Secrets | ... | config.py:15 |
| 3 | MEDIUM | Quality | ... | utils.py:88 |

---

## Security Analysis
[network, process, persistence, credential handling]

## Dependency Audit
[CVEs found, license issues, version lag]

## Code Quality
[anti-patterns, complexity, test coverage, undocumented requirements]

## Bugs Found
[specific bugs with file:line, description, suggested fix]

## Recommendation
[Install or not. Specific caveats and required actions before installing.]
```

---

## Output rules

- **Verdict at the top** — ✅ / ⚠️ / ❌ — users need to see this immediately
- **Plain English** — explain what each finding means and why it matters
- **Actionable** — every finding includes a suggested fix or workaround
- **Honest about limits** — note if a check wasn't possible (e.g., tool not installed)
- Rate every finding: `CRITICAL / HIGH / MEDIUM / LOW / INFO`

---

## Security rules (always enforce)

- Read source before running anything
- Never execute code from the target during static analysis
- Never transmit target source code to external services (exception: package metadata to PyPI/npmjs for version checking)
- Label all permission requests as `[Claude]` or `[software under test]`
- If a secret is found, do NOT print the full value — show first 8 chars + `...`
