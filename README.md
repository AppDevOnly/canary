# Canary

**Automated security testing for code — no security background needed.**

Canary is a Claude Code skill that evaluates GitHub repos, local projects, pip packages, and npm packages for security issues, vulnerabilities, hardcoded secrets, and bugs. It gives you a plain-English verdict before you install or run anything.

Named after the canary in a coal mine: it goes in first so you don't have to.

## What it checks

- **Security** — network connections, process behavior, persistence attempts, hardcoded credentials
- **Dependency vulnerabilities** — known CVEs (pip-audit, npm-audit), license compliance
- **Secrets** — API keys, tokens, and credentials accidentally committed to source
- **Code quality** — bad practices, anti-patterns, complexity, missing tests
- **Bugs** — runtime errors, edge cases, logic gaps
- **Undocumented requirements** — hidden API keys, missing tools, silent failures

Every finding is rated: `CRITICAL / HIGH / MEDIUM / LOW / INFO`

Every report ends with a plain-English verdict: ✅ Safe / ⚠️ Caution / ❌ Unsafe

## Install (one line)

**macOS / Linux / Git Bash:**
```bash
curl -sSL https://raw.githubusercontent.com/AppDevOnly/canary/main/install.sh | bash
```

**PowerShell (Windows):**
```powershell
irm https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 | iex
```

This copies `canary.md` into `~/.claude/commands/` so the `/canary` command is available in Claude Code.

**Requirements:** [Claude Code](https://github.com/anthropics/claude-code) installed.

## Usage

First, launch Claude Code in your terminal:
```
claude
```

Then, inside the Claude Code session, run:
```
/canary <target>
```

Where `<target>` is:
- A GitHub URL: `/canary https://github.com/someuser/somerepo`
- A local path: `/canary ~/projects/my-app`
- A pip package: `/canary pip:requests`
- An npm package: `/canary npm:lodash`

Canary will ask how thorough you want it to be, then walk you through the evaluation step by step.

## Evaluation levels

**Quick** — Scans the most important files (entry points, install scripts, anything that runs at startup) for red flags. Takes about a minute.

**Medium** — Reads the full codebase, checks all dependencies for known vulnerabilities, scans for accidentally committed secrets, and assesses code quality. Takes a few minutes.

**Full** — Everything in Medium, plus runs the code in an isolated sandbox to watch what it actually does on your machine. Requires Windows Sandbox or Docker.

## What you get

A structured plain-text report covering:

1. **Verdict** — Safe / Caution / Unsafe with one-sentence rationale
2. **Executive summary** — non-technical overview with risk counts
3. **Findings** — each issue with severity, plain-English explanation, and fix
4. **Security analysis** — network, process, persistence, credentials
5. **Dependency audit** — CVEs, outdated packages, license issues
6. **Code quality** — bad practices, complexity, test coverage
7. **Recommendation** — exactly what to do before you install or use it

Reports are saved to `~/canary-reports/`.

## Who this is for

Anyone who wants to check code before trusting it — developers, tinkerers, and non-technical users alike. You don't need a security background to use Canary or understand its reports.

## Contributing

Issues and PRs welcome.

---

*Built on top of the [test-install](https://github.com/AppDevOnly/sandbox-eval) sandbox evaluation framework.*
