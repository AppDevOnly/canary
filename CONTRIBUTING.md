# Contributing to Canary

## What we're building

A Claude skill that anyone can install in one line and use to evaluate code before running it. The target user has no security background — output must be plain English, actionable, and honest about what was and wasn't checked.

Canary grows with the user. The skill file (`canary.md`) is the brain, but it's backed by sandbox infrastructure that ships with the repo and gets better over time. Contributions can improve either layer.

## Repo structure

```
canary/
  canary.md                    — the Claude skill (installed to ~/.claude/commands/)
  install.ps1                  — Windows installer: skill + sandbox infrastructure + prereq checks
  install.sh                   — bash installer (skill only; Linux/Mac)
  sandbox/
    run-watchdog.ps1           — sandbox orchestration: launches Windows Sandbox, streams logs,
                                 handles retries, cleans up. Installed to C:\sandbox\scripts\.
    bootstrap.cmd              — runs inside the sandbox on login; waits for mapped folders,
                                 then launches setup.ps1
    sandbox-template.wsb       — base Windows Sandbox config; canary generates a target-specific
                                 .wsb from this for each Full mode scan
  tools/
    check-deps.sh              — dependency checker
  examples/                    — example canary reports on real open-source projects
```

## Ways to contribute

**canary.md (the skill)**
- Add detection patterns — new secrets patterns, anti-patterns, CVE indicators
- Improve phase logic — better static analysis, smarter reporting
- Add target types — GitLab, Bitbucket, Docker Hub, VS Code extensions, Cargo, NuGet, Ruby Gems
- Fix edge cases — private repos, monorepos, unusual project structures

**sandbox infrastructure**
- `run-watchdog.ps1` — reliability improvements, better stall detection, cross-platform support
- `bootstrap.cmd` — startup robustness
- `sandbox-template.wsb` — mapped folder improvements
- Docker fallback — for Full mode on Linux/Mac

**install scripts**
- `install.sh` — add sandbox infrastructure deployment for Linux/Mac (Docker fallback path)
- Better prereq detection and guidance

**examples**
- Run canary on real open-source projects and submit the report to `examples/`

## Guidelines

- **Plain English over security jargon** — if you have to explain what a term means, just use the plain English version
- **Every finding needs a fix** — don't flag things that aren't actionable
- **Honest about limits** — if a check wasn't possible, say so clearly
- **Sandbox infrastructure is shared** — changes to `run-watchdog.ps1` or `bootstrap.cmd` affect every user who runs `/canary update`, so test carefully

## Testing changes

To test canary skill changes:
1. Edit `~/.claude/commands/canary.md` directly
2. Start a new Claude Code session and run `/canary <some target>`
3. When satisfied, submit a PR — the install script pulls from `main`

To test sandbox infrastructure changes:
1. Edit files in `C:\sandbox\scripts\` directly
2. Run a Full mode scan with `/canary <target>` and choose Full
3. Verify `C:\sandbox\output\stream.log` shows expected behavior

## Report format

Example reports are in `examples/`. Reports should be plain-text readable — no raw markdown, no ASCII tables. Follow the format from an existing example.
