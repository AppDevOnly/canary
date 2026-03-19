# Canary Changelog

## v2.5 (2026-03-19)

### Added
- Per-level dependency checks: Quick, Medium, and Full each verify exactly the tools they need before starting — no assumptions
- pip/Python availability check before attempting any pip installs
- winget availability check before attempting any winget installs
- Admin rights check for Full mode (required for Procmon, tshark, SAC registry)
- Scan state persistence: progress saved to ~/canary-reports/<target>-state.json after each phase completes
- Resume logic: /canary <target> detects partial scans and offers to continue from where it left off; SAC state restored if scan was interrupted mid-sandbox
- Progress messages at every phase transition ("Starting secrets scan...", "Secrets scan complete — 0 findings")
- 30-second heartbeat during long-running operations (semgrep, sandbox wait)
- Plain-English feedback when watchdog retries ("The sandbox stopped responding — restarting. Attempt N of 2.")
- Autoruns baseline (autoruns-before.csv) and after-snapshot (autoruns-after.csv) integrated into run-watchdog.ps1 — persistence detection is now fully automated
- Dynamic tshark Wi-Fi interface detection — no longer hardcoded as interface 6

### Changed
- Sandbox timeouts reduced: SetupTimeout 150s → 60s, StallTimeout 300s → 90s, Interactive 3600s → 600s, MaxRetries 3 → 2
- Quick scan description clarified: explicitly states it uses Claude's built-in analysis only, no external tools
- Dependency checks happen before the consent block, not after — user sees what's missing before committing to the scan
- Tool install flow improved: pip/winget availability checked before attempting tool installs

### Fixed
- Silent failure when gh auth not configured for GitHub targets in Quick/Medium scans
- tshark Wi-Fi interface hardcoded as 6 — wrong on machines with different NIC ordering
- Autoruns not automated — was described in canary.md but not wired into watchdog

---

## v2.4 (2026-03-18)

### Added
- analyze-pid-chain.ps1 added to repo (sandbox/) and deployed by install.ps1 — ships with canary for all users
- PID chain analysis in Phase 4: detects process injection, LOL-bins, and unexpected process ancestry chains
- Post-run DNS/IP queries from network-vswitch.log
- Autoruns diff with full autorunsc64.exe flags
- Interactive vs automated mode choice before watchdog launch
- SAC plain-English consent prompt with real "no" path (static report still produced if user declines)
- SAC fix: watchdog launched via Start-Process powershell so SAC policy change takes effect in new session
- SAC re-enable after scan with user-facing verification instructions
- Report template SAC caveat: always documents SAC state and how to verify it was restored
- Security rules expanded: no VM screenshots, no config in output folder, one sandbox at a time, timestamped Procmon filenames

### Changed
- check-deps.sh updated with full tool list (gitleaks, tshark, Autoruns64, Procmon64, sandbox scripts)
- Autoruns baseline command updated to use full autorunsc64.exe flags (-a '*' -c -h -s -nobanner)
- canary.md path for analyze-pid-chain.ps1 updated to C:\sandbox\scripts\

### Removed
- test-install.md (content fully absorbed into canary.md)
- start-monitors.ps1 (superseded by run-watchdog.ps1)
- bootstrap.ps1 (duplicate of bootstrap.cmd)
- patch-code-agent.py, autorun.flag (wrong directory, obsolete)

---

## v2.3 (2026-03-18)

### Added
- Sandbox infrastructure (run-watchdog.ps1, bootstrap.cmd, sandbox-template.wsb) added to repo — ships with canary, no longer local-only
- install.ps1 deploys sandbox infrastructure to C:\sandbox\scripts\ and checks prerequisites (Windows Sandbox, Sysinternals)
- run-watchdog.ps1: -WsbFile parameter, single-instance PID guard, sentinel file replaces pipeline.log race condition, procmon .pml cleanup (keep 3)
- canary.md: target-specific .wsb generation from template, SAC pre-flight check, no-retry on "RESULT: Binary could not be launched"
- setup.ps1: SAC state logged first, case-insensitive exe search, exact error captured, sentinel written after Stop-Transcript
- Single upfront consent prompt (tier-aware, [Claude] vs [software under test] labels)
- /canary update self-update command

### Changed
- Windows compatibility: always use gh api --jq for JSON parsing — no standalone jq or python3
- Version string made grep-able: # canary-version: 2.3 in canary.md

---

## v2.2 and earlier

Initial development. Pen-test report format, three evaluation tiers (Quick/Medium/Full), plain-English UX, single-line installer.
