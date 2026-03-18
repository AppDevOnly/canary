# Canary

**Automated security testing for code — no security background needed.**

Canary is a Claude Code skill that evaluates GitHub repos, local projects, pip packages, and npm packages for security issues, vulnerabilities, hardcoded secrets, and bugs. It gives you a plain-English verdict before you install or run anything.

Named after the canary in a coal mine: it goes in first so you don't have to.

---

## What it checks

- **Security** — network connections, process behavior, persistence attempts, hardcoded credentials
- **Dependency vulnerabilities** — known CVEs (pip-audit, npm-audit), license compliance
- **Secrets** — API keys, tokens, and credentials accidentally committed to source
- **Code quality** — bad practices, anti-patterns, complexity, missing tests
- **Bugs** — runtime errors, edge cases, logic gaps
- **Undocumented requirements** — hidden API keys, missing tools, silent failures

Every finding is rated: `CRITICAL / HIGH / MEDIUM / LOW / INFO`

Every report ends with a plain-English verdict: ✅ Safe / ⚠️ Caution / ❌ Unsafe

---

## Install

**PowerShell (Windows):**
```powershell
irm https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 | iex
```

**macOS / Linux / Git Bash:**
```bash
curl -sSL https://raw.githubusercontent.com/AppDevOnly/canary/main/install.sh | bash
```

**Requirements:** [Claude Code](https://github.com/anthropics/claude-code) must be installed first.

The installer:
- Copies `canary.md` into `~/.claude/commands/` so `/canary` is available in Claude Code
- Deploys sandbox infrastructure to `C:\sandbox\scripts\` (Windows only)
- Checks that Windows Sandbox and Sysinternals are available for Full mode and tells you exactly what to do if they're not

---

## Usage

Launch Claude Code, then run:

```
/canary <target>
```

Where `<target>` is:
- A GitHub URL: `/canary https://github.com/someuser/somerepo`
- A local path: `/canary ~/projects/my-app`
- A pip package: `/canary pip:requests`
- An npm package: `/canary npm:lodash`

Canary will ask how thorough you want it to be, then run the evaluation.

---

## Keeping canary up to date

```
/canary update
```

Checks your installed version against the repo and reinstalls if behind — updates both the skill and the sandbox infrastructure. Restart Claude Code after updating.

---

## Evaluation levels

**Quick** — Scans entry points and install scripts for red flags. About a minute.

**Medium** — Full codebase read, dependency CVE scan, secrets scan, code quality analysis. A few minutes.

**Full** — Everything in Medium, plus runs the software in an isolated sandbox to observe what it actually does: network connections, files created, registry writes, persistence attempts. Requires Windows Sandbox and Sysinternals (see below).

---

## Full mode prerequisites (Windows only)

Full mode runs the target software in a Windows Sandbox and watches its behavior in real time.

**1. Windows Sandbox**
Enable via Settings > System > Optional Features > Windows Sandbox, or:
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
```
Requires a reboot. Windows 10/11 Pro or Enterprise only.

**2. Sysinternals Suite**
Download from https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite
Extract to `C:\temp\security-tools\Sysinternals\`

The installer checks both and walks you through anything that's missing.

---

## What you get

A structured plain-text report saved to `~/canary-reports/`:

1. **Verdict** — ✅ / ⚠️ / ❌ with one-sentence rationale
2. **Executive summary** — non-technical overview with risk counts
3. **Findings** — each issue with severity, plain-English explanation, and fix
4. **Security analysis** — network, process, persistence, credentials
5. **Dependency audit** — CVEs, outdated packages, license issues
6. **Code quality** — bad practices, complexity, test coverage
7. **Sandbox results** — what the software actually did at runtime (Full only)
8. **Recommendation** — exactly what to do next

---

## Who this is for

Anyone who wants to check code before trusting it — developers, tinkerers, and non-technical users alike. You don't need a security background to use Canary or understand its reports.

---

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).
