# Contributing to Canary

## What we're building

A Claude skill (`canary.md`) that independent developers can install in one line and use to evaluate code before installing it. The target user has no security background — output must be plain English, actionable, and honest about what was and wasn't checked.

## Ways to contribute

- **Add detection patterns** — new secrets patterns, anti-patterns, or CVE indicators to `canary.md`
- **Add example reports** — run Canary on real open-source projects and submit the report to `examples/`
- **Improve the install script** — Windows support, better error messages
- **Add tool integrations** — Semgrep rules, pip-audit, Bandit, Trufflehog
- **Bug reports** — if a finding was wrong or missed, open an issue

## Guidelines

- Keep `canary.md` self-contained — it should work as a standalone Claude skill without any external dependencies beyond Claude Code
- Every finding must include a suggested fix or workaround, not just a description of the problem
- Plain English over security jargon — if you have to explain what a term means, just use the plain English version
- Don't flag things that aren't actionable

## Report format

If you're submitting an example report, use the template from `examples/autoresearchclaw-v0.5.0-canary-report.md` as a reference. Reports should be reproducible — someone else should be able to follow your steps and get the same findings.
