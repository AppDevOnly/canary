# Canary

**Automated security testing for code — no security background needed.**

Canary is a Claude Code skill that evaluates GitHub repos, GitLab and Bitbucket repos, local projects, pip and npm packages, Cargo crates, NuGet packages, Docker images, and VS Code extensions for security issues, vulnerabilities, hardcoded secrets, and bugs. It gives you a plain-English verdict before you install or run anything.

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

Every report ends with a plain-English verdict: [OK] Safe / [!] Caution / [X] Unsafe

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

### Verify the installer before running (optional but recommended)

The `irm | iex` pattern runs a remote script directly. If you want to verify it first:

```powershell
# Download without running
Invoke-WebRequest https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 -OutFile install.ps1

# Verify SHA256 matches the value below
(Get-FileHash install.ps1 -Algorithm SHA256).Hash.ToLower()

# If it matches, run it
powershell -ExecutionPolicy Bypass -File install.ps1
```

**Current SHA256 hashes:**
```
install.ps1   ebe54599b3acc0f99fd3cc502a91804c1555c5510bff01fe74acf150b729d5bb
```

> [!] The main risk with `irm | iex` is a compromised AppDevOnly account -- a supply chain attack could replace install.ps1 with something malicious. Verifying the hash guards against that. Hashes are updated with each release.

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
- A GitHub/GitLab/Bitbucket URL: `/canary https://github.com/someuser/somerepo`
- A local path: `/canary ~/projects/my-app`
- A pip package: `/canary pip:requests`
- An npm package: `/canary npm:lodash`
- A Cargo crate: `/canary cargo:serde`
- A NuGet package: `/canary nuget:Newtonsoft.Json`
- A Docker image: `/canary docker:nginx`
- A VS Code extension: `/canary vscode:publisher.extension-name`

To review a pull request for supply chain risk:
```
/canary pr https://github.com/someuser/somerepo/pull/123
```

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

## Example reports

- [Code scan: hsliuping/TradingAgents-CN](https://appdevonly.github.io/canary/examples/code-scan-TradingAgents-CN.html) -- [!] Caution, Quick mode
- [Email analysis: iCloud phishing](https://appdevonly.github.io/canary/examples/email-analysis-icloud-phishing.html) -- [X] Phishing

---

## What you get

A structured plain-text report saved to `~/canary-reports/`:

1. **Verdict** — [OK] / [!] / [X] with one-sentence rationale
2. **Executive summary** — non-technical overview with risk counts
3. **Findings summary** — severity breakdown at a glance
4. **Findings** — each issue with severity, plain-English explanation, and fix
5. **Security analysis** — network, process, persistence, credentials
6. **Dependency audit** — CVEs, outdated packages, license issues
7. **Code quality** — bad practices, complexity, test coverage
8. **Sandbox results** — what the software actually did at runtime (Full only)
9. **Recommendation** — exactly what to do next

---

## Who this is for

Anyone who wants to check code before trusting it — developers, tinkerers, and non-technical users alike. You don't need a security background to use Canary or understand its reports.

---

## Acknowledgments

Canary uses the [MITRE ATT&CK®](https://attack.mitre.org) framework to classify and tag security
findings. MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Technique mappings
reference the ATT&CK knowledge base, published under the Creative Commons Attribution 4.0 license.

---

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).
