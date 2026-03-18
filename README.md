# Canary

**Test code before you trust it.**

Canary is a Claude skill that evaluates GitHub repos, local projects, pip packages, and npm packages for security issues, code quality problems, dependency vulnerabilities, and bugs — before you install or run anything.

Named after the canary in a coal mine: it goes in first so you don't have to.

---

## What it checks

- **Security** — network connections, process behavior, persistence attempts, hardcoded credentials
- **Dependency vulnerabilities** — known CVEs (pip-audit, npm-audit), license compliance
- **Secrets** — API keys, tokens, and credentials accidentally committed to source
- **Code quality** — bad practices, anti-patterns, complexity, missing tests
- **Bugs** — runtime errors, crash reproduction, edge cases
- **Undocumented requirements** — hidden API keys, missing tools, silent failures

Every finding is rated: `CRITICAL / HIGH / MEDIUM / LOW / INFO`

Every report ends with a plain-English verdict: ✅ Safe / ⚠️ Caution / ❌ Unsafe

---

## Install (one line)

```bash
curl -sSL https://raw.githubusercontent.com/AppDevOnly/canary/main/install.sh | bash
```

This copies `canary.md` into `~/.claude/commands/` so the `/canary` command is available in Claude Code.

**Requirements:** [Claude Code](https://github.com/anthropics/claude-code) installed.

---

## Usage

```
/canary <target>
```

Where `<target>` is:
- A GitHub URL: `/canary https://github.com/someuser/somerepo`
- A local path: `/canary ~/projects/my-app`
- A pip package: `/canary pip:requests`
- An npm package: `/canary npm:lodash`

Canary walks you through the evaluation step by step and produces a structured report at the end.

---

## What you get

A structured report covering:

1. **Verdict** — Safe / Caution / Unsafe with one-sentence rationale
2. **Security findings** — network, process, persistence, credentials
3. **Dependency audit** — CVEs, outdated packages, license issues
4. **Code quality** — bad practices, complexity, test coverage
5. **Bugs found** — with reproduction steps and suggested fixes
6. **Recommendation** — install or not, with specific caveats

See [examples/](examples/) for sample reports.

---

## Who this is for

Independent developers and tinkerers who want to quickly check code they're about to install — without needing a security background or a dedicated security team.

---

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

*Built on top of the [test-install](https://github.com/AppDevOnly/sandbox-eval) sandbox evaluation framework.*
