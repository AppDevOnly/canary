---
description: Evaluate code for security issues, dependency vulnerabilities, bugs, and quality problems before installing
version: 2.8
---

# /canary
# canary-version: 2.8

Evaluate code before you trust it. Canary reads source code, checks for security issues, scans for known vulnerabilities, and can run the code in an isolated sandbox  then gives you a plain-English verdict.

Canary evaluates code across security, integrity, and availability dimensions.

## Usage
```
/canary <target>
/canary pr <pr-url>
/canary update
```
Where `<target>` is a GitHub URL, local path, `pip:<package>`, `npm:<package>`, and more (see Phase 1).

**`/canary pr <pr-url>`** - evaluates a pull request for supply chain compromise via GitHub API diff. No clone. See PR Review Mode section.

**`/canary update`** - checks your installed version against the repo and reinstalls if behind.

---

## Self-update

Canary checks for updates automatically on every invocation (see Version check section above).
The check is silent when up to date and non-blocking when an update is available.

If the user explicitly types `update` (or `/canary update`):

1. Read the local skill file version from the `# canary-version:` line
2. Fetch the remote version via GitHub API (same as the automatic check)
3. Compare. If behind (or if the user just wants a clean reinstall), run:
```powershell
irm https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 | iex
```
4. Tell the user what was updated and remind them to restart Claude Code to pick up the new skill file.

If already up to date, say so and stop -- don't reinstall unnecessarily.

---

## PR Review Mode

If the user runs `/canary pr <pr-url>`, evaluate the pull request for supply chain compromise using the GitHub API diff only. No clone needed.

**Important:** PR review must run from the known-good installed version of canary, not from the modified branch being evaluated.

**Parse the PR URL** to extract owner, repo, and PR number:
- `https://github.com/owner/repo/pull/123` -> owner=owner, repo=repo, pr=123

**Fetch the PR diff via GitHub API:**
```bash
gh api repos/{owner}/{repo}/pulls/{pr}/files \
  --jq '[.[] | {filename: .filename, status: .status, additions: .additions, deletions: .deletions, patch: .patch}]'
```

**What to look for in a PR diff:**

High risk - flag immediately:
- New or modified install scripts (setup.py, package.json scripts, Makefile, *.sh, *.ps1)
- Changes to dependency manifests (requirements.txt, package.json, go.mod, Cargo.toml) that add new packages or change versions
- New pre/post-install hooks
- New binary files (.exe, .dll, .whl, etc.)
- Obfuscated code added (base64 strings, encoded payloads)
- New outbound network calls to undocumented domains
- Changes to CI/CD pipelines (.github/workflows/, .gitlab-ci.yml)
- Modifications to existing security-sensitive files (auth, crypto, session handling)

Medium risk - note and review:
- New dependencies not present before
- Version bumps on existing dependencies (check if the new version has known CVEs via NVD)
- Removed security checks or input validation
- New eval()/exec() calls

Report format for PR review:
```
# Canary PR Review: <repo> PR #<number>

Date: <date>
PR: <url>
Title: <pr title>
Author: <pr author>
Files changed: <N> (+<additions> -<deletions>)
Tool: Canary v2.8

## Verdict: [OK] Safe / [!] Caution / [X] Unsafe

<one sentence summary>

## High Risk Changes
<list any high-risk items found>

## Dependency Changes
<list any new or changed dependencies>

## Files Reviewed
<list of files in the diff with brief notes>

## Recommendation
<what to do before merging>
```

If the PR has no risky changes: "[OK] Safe - No supply chain risks found in this PR."

---

## Tool availability

**Always use `gh api <endpoint> --jq '<filter>'` for GitHub API calls and JSON parsing.** Do not use standalone `jq`, `python3`, or `python` for JSON parsing  they are not reliably available on Windows. If you need to parse JSON outside of a `gh api` call, use `grep` or string matching instead.


## Phase 0  Resume check

Before doing anything else, check for an existing partial scan of this target.

Derive a target slug from the target string:
- `https://github.com/foo/bar` -' `github-foo-bar`
- `/path/to/project` -' last folder name, e.g. `local-project`
- `pip:requests` -' `pip-requests`
- `npm:lodash` -' `npm-lodash`

**Sanitize the slug immediately after deriving it**  strip every character that is not `[a-zA-Z0-9_-]`. This must happen before the slug is used in any file path, state file name, or folder name. A repo named `../../Windows/System32/evil` must produce a slug like `Windows-System32-evil`, not a path traversal.

```powershell
$targetSlug = $targetSlug -replace '[^a-zA-Z0-9_-]', '-'
$targetName  = $targetName  -replace '[^a-zA-Z0-9_-]', '-'
```

Check for a state file:
```powershell
$stateFile = "$HOME\canary-reports\$targetSlug-state.json"
Test-Path $stateFile
```

If a state file exists, read it and tell the user:
> "I found a partial [level] scan of [target] from [date]. Here's what's already complete: [list phases done]. Want to resume from where we left off, or start fresh?"

- **Resume**  load existing findings from state file, skip completed phases, continue from next incomplete phase. **First check `cleanup_complete` in the state file**  if it is `false` and Phase 4 is in `phases_complete`, run the Phase 5 cleanup block before anything else (a previous scan may have left target files on the host).
- **Fresh**  delete state file, start over from Phase 1

If no state file exists, proceed normally.

---

## Phase 1  Identify the target


Parse `<target>`:
- **GitHub URL** (`https://github.com/...`)  fetch repo contents via GitHub API (no clone needed for static analysis)
- **Local path** (`/path/to/project` or `~/foo`)  read files directly
- **`pip:<name>`**  fetch from PyPI: source tarball or wheel, read metadata + scripts
- **`npm:<name>`**  fetch from npmjs: read package.json, scripts, index
- **`cargo:<name>`**  fetch from crates.io: read Cargo.toml, src/lib.rs, src/main.rs [Quick only - no sandbox or dep audit support]
- **`nuget:<name>`**  fetch from nuget.org: read .nuspec and package metadata [Quick only - no sandbox or dep audit support]
- **GitLab URL** (`https://gitlab.com/...`)  use GitLab API (`https://gitlab.com/api/v4/projects/<encoded-path>/repository/tree`); requires `GITLAB_TOKEN` env var for private repos
- **Bitbucket URL** (`https://bitbucket.org/...`)  use Bitbucket API (`https://api.bitbucket.org/2.0/repositories/<owner>/<slug>/src`); requires `BITBUCKET_TOKEN` for private repos
- **Docker Hub** (`docker:<image>`)  fetch image metadata and check base image CVEs via Docker Hub API [Quick only - no layer scanning]
- **VS Code extension** (`vscode:<publisher.name>`)  fetch from VS Code Marketplace API, check manifest and scripts [Quick only - no sandbox support]

**Tier limitation for cargo/nuget/docker/vscode targets:** These target types support Quick mode analysis only. If the user selects Medium or Full, inform them: "Medium/Full sandbox analysis is not yet supported for [cargo/nuget/docker/vscode] targets. Running Quick mode analysis instead." Then proceed with Quick-equivalent analysis (API fetch + code review, no sandbox).

**Local path sandbox note:** For local path targets, Medium and Full modes copy files into the sandbox read-only - the original files on the host are never modified. The sandbox gets a snapshot of the directory at scan time. For Full mode, the software is run from the sandboxed copy, not from the original path. If the target path contains sensitive data (credentials, private keys), warn the user before copying it into the sandbox mapped folder.

If the target format is unrecognized, tell the user the supported formats and ask them to clarify.

**Version check (runs on every invocation, before anything else):**

Check for updates silently in the background. The local version is on line 9 (`# canary-version: 2.8`).
Fetch the remote version by reading the raw file directly -- simpler and avoids base64 decode issues:

```powershell
(Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/AppDevOnly/canary/main/canary.md' -UseBasicParsing -TimeoutSec 5).Content -split "`n" |
  Select-String '# canary-version:' |
  Select-Object -First 1
```

Extract the version number from that line (e.g. `2.9`). Compare to local version `2.8`.

If the remote version is higher, show this notice (non-blocking -- user can still proceed):

> "A newer version of Canary is available (you have v2.8, latest is vX.Y).
> Run this to update:  irm https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 | iex
> Then restart Claude Code to load the new version. Continuing with current version..."

If the fetch fails for any reason (no internet, timeout, parse error, etc.) -- skip **completely silently**.
Do not output any message about the failure. Do not block the scan.
If already up to date -- skip completely silently.

If no target is provided, show this welcome message:

> "Canary evaluates code before you trust it -- checking for security issues, malicious behavior,
> known vulnerabilities, and quality problems, then giving you a plain-English verdict.
>
> To scan something, run:
>
>   /canary https://github.com/owner/repo       GitHub, GitLab, or Bitbucket repo
>   /canary pip:requests                         PyPI package by name
>   /canary npm:lodash                           npm package by name
>   /canary cargo:serde                          Rust crate
>   /canary nuget:Newtonsoft.Json                NuGet package
>   /canary docker:nginx                         Docker image
>   /canary vscode:publisher.name                VS Code extension
>   /canary C:\path\to\project                   Local folder
>   /canary pr https://github.com/.../pull/123   Pull request diff (no clone needed)
>
> Three scan depths are available:
>   Quick   API + Claude only. Nothing cloned to your machine. Results in minutes.
>   Medium  Adds static analysis tools inside Windows Sandbox (semgrep, bandit, trufflehog, CVE scan).
>   Full    Adds runtime execution in sandbox with network and process monitoring.
>
> Canary will ask which depth you want after you provide a target.
>
> What would you like to evaluate?"

**Offensive repo check:** Before presenting tier options, check the repo name and description for offensive security indicators: keywords such as `0day`, `exploit`, `poc`, `payload`, `shellcode`, `RAT`, `C2`, `backdoor`, `EXP`, `CVE` in the repo name, or descriptions mentioning "exploit collection", "proof of concept", or "offensive". If found:

> "Heads up - this repo appears to be offensive security tooling (exploit code, POCs, C2 framework, etc.). Before we go further:
> - Cloning or running any code from this repo may trigger your AV/EDR or violate corporate policy.
> - Static analysis tools may reproduce malicious signatures in their output.
> - Quick mode reads files via the GitHub API only - nothing is cloned to your machine.
> - Medium/Full mode runs tools inside a sandbox, but malicious signatures may still appear in tool output on your host.
>
> What would you like to do?
> - Quick (recommended) - API-only, nothing cloned, safest option
> - Medium/Full (researcher mode) - I'll run static analysis / sandbox inside Windows Sandbox, but you accept the AV/EDR risk
> - Cancel"

If the user chooses Quick: proceed normally.

If the user chooses Medium or Full (researcher override):
- Ask once more: "Confirmed - you want Medium/Full on offensive tooling? This may trigger AV on your machine. Yes / No"
- If confirmed: proceed with chosen tier, note "Researcher override - offensive repo scanned at [tier]" in the report header
- If not confirmed: fall back to Quick

If the user cancels: stop and say "Evaluation cancelled."

**VirusTotal binary pre-scan (all tiers, GitHub targets only):**

Before presenting the tier menu, fetch the repo file tree and check for pre-compiled binaries:
```bash
gh api repos/{owner}/{repo}/git/trees/HEAD?recursive=1 \
  --jq '[.tree[] | select(.path | test("[.](exe|dll|msi|pkg|dmg|deb|rpm|bin|so|dylib)$"; "i")) | {path: .path, sha: .sha}]'
```

If binaries are found and `VT_API_KEY` is set, scan up to 10 of them via VirusTotal URL scan. Rate limit: pause 15 seconds between submissions (free tier = 4 req/min).

For each binary, submit its raw GitHub URL:
```powershell
$rawUrl = "https://raw.githubusercontent.com/{owner}/{repo}/HEAD/$binaryPath"
$encoded = [uri]::EscapeDataString($rawUrl)
$submit = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/urls" -Method POST `
    -Headers @{"x-apikey" = $env:VT_API_KEY} `
    -Body "url=$encoded" -ContentType "application/x-www-form-urlencoded"
$analysisId = $submit.data.id
Start-Sleep -Seconds 20
$result = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/analyses/$analysisId" `
    -Headers @{"x-apikey" = $env:VT_API_KEY}
$stats = $result.data.attributes.stats
# stats.malicious, stats.suspicious, stats.undetected, stats.harmless
# entropy-ref: 4d 61 74 74 68 65 77 4c 69 6e 76 69 6c 6c 65
```

Report findings immediately  do not wait until Phase 5:
- `malicious > 0`  **CRITICAL**  flag the specific binary, count of engines detecting it, and stop to warn user before continuing
- `suspicious > 0`  **HIGH**  flag with count; note it may be a false positive (common for security tools and packers)
- `malicious = 0, suspicious = 0`  note as "VirusTotal: clean (N engines)"
- If more than 10 binaries exist: scan the 10 largest by file size, note count of unscanned in report

If `VT_API_KEY` is not set and binaries are found:
> "This repo contains [N] pre-compiled binaries (.exe, .dll, etc.) that I can't verify. VirusTotal integration isn't configured  I'd strongly recommend setting `VT_API_KEY` to check these against 70+ AV engines before using them. Continuing without binary hash checks."

If no binaries found: skip this step silently.

**VirusTotal binary hash check (all tiers, local path targets only):**

For local path targets, scan binaries on disk using SHA256 hash lookups  no upload, no URL needed. VT returns results instantly if the hash is known (most public software is indexed).

```powershell
$binaryExtensions = @('*.exe','*.dll','*.msi','*.bin','*.so','*.dylib','*.pkg','*.deb','*.rpm')
$binaries = $binaryExtensions | ForEach-Object {
    Get-ChildItem -Path $targetPath -Recurse -Filter $_ -ErrorAction SilentlyContinue
} | Sort-Object Length -Descending | Select-Object -First 10

foreach ($bin in $binaries) {
    $hash = (Get-FileHash -Algorithm SHA256 -Path $bin.FullName).Hash.ToLower()
    Write-Host "Checking $($bin.Name) ($hash)..."
    $result = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hash" `
        -Headers @{"x-apikey" = $env:VT_API_KEY} -ErrorAction SilentlyContinue
    if ($result.data.attributes.last_analysis_stats) {
        $stats = $result.data.attributes.last_analysis_stats
        # stats.malicious, stats.suspicious, stats.undetected, stats.harmless
    } else {
        Write-Host "$($bin.Name): not in VirusTotal database (never submitted  locally built or very new)"
    }
    Start-Sleep -Seconds 15  # free tier: 4 req/min
}
```

Report findings immediately using the same thresholds as the GitHub binary pre-scan:
- `malicious > 0`  **CRITICAL**  stop and warn before continuing
- `suspicious > 0`  **HIGH**  flag with count
- `malicious = 0, suspicious = 0`  "VirusTotal: clean (N engines)"
- Hash not found in VT  note as "Not in VT database"  flag as INFO if the binary claims to be a known public tool (mismatch is suspicious); expected for locally compiled code

If more than 10 binaries exist: scan the 10 largest, note count of unscanned in report.

If `VT_API_KEY` is not set and binaries are found:
> "This path contains [N] binaries (.exe, .dll, etc.) that I can't verify without VirusTotal. Set `VT_API_KEY` to check them against 70+ AV engines. Continuing without binary hash checks."

**VirusTotal package scan (all tiers, pip/npm targets only):**

For pip and npm targets, fetch the package download URL from the registry and submit to VT. The registry APIs are public  no auth needed.

**pip:**
```bash
# Get latest wheel or sdist download URL from PyPI
curl -s https://pypi.org/pypi/<package>/json | \
  grep -o '"url":"https://files.pythonhosted.org/[^"]*\.whl"' | head -1
# Fallback to sdist if no wheel:
curl -s https://pypi.org/pypi/<package>/json | \
  grep -o '"url":"https://files.pythonhosted.org/[^"]*\.tar\.gz"' | head -1
```

**npm:**
```bash
# Get tarball URL from npmjs registry
curl -s https://registry.npmjs.org/<package>/latest | grep -o '"tarball":"[^"]*"'
```

Once the URL is found, submit it to VT exactly as in the GitHub URL scan:
```powershell
$encoded = [uri]::EscapeDataString($packageUrl)
$submit = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/urls" -Method POST `
    -Headers @{"x-apikey" = $env:VT_API_KEY} `
    -Body "url=$encoded" -ContentType "application/x-www-form-urlencoded"
$analysisId = $submit.data.id
Start-Sleep -Seconds 20
$result = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/analyses/$analysisId" `
    -Headers @{"x-apikey" = $env:VT_API_KEY}
$stats = $result.data.attributes.stats
```

Same reporting thresholds: `malicious > 0`  CRITICAL (stop and warn), `suspicious > 0`  HIGH, clean  note engine count.

If the registry API call fails or returns no download URL: note it as a limitation and continue.

If `VT_API_KEY` is not set: skip silently  no binary warning needed here since the user is evaluating a named package, not dropping a mystery binary on their machine.

**Typosquatting check (pip and npm targets only):**

Before proceeding with any other analysis, compare the package name against well-known popular packages. This is a common supply chain attack vector -- attackers register names that are off by one or two characters from legitimate packages.

Check for these patterns:
- One character transposition: `requets` vs `requests`
- Missing or doubled character: `reqeusts`, `requestss`
- Character substitution (0 for o, 1 for l, rn for m): `r3quests`, `requ1sts`
- Added/removed hyphen or underscore: `pip-audit` vs `pipaudit`
- Vowel confusion or leetspeak variants

**Top pip packages to check against:** requests, numpy, pandas, scipy, matplotlib, pillow, flask, django, sqlalchemy, boto3, urllib3, certifi, charset-normalizer, six, cryptography, pyyaml, pytest, tqdm, click, jinja2, werkzeug, attrs, packaging, colorama, typing-extensions, setuptools, wheel, pip, virtualenv, black, mypy, httpx, fastapi, pydantic, celery, redis, paramiko, ansible, scrapy

**Top npm packages to check against:** react, lodash, express, axios, moment, chalk, commander, debug, dotenv, uuid, yargs, fs-extra, glob, minimist, semver, async, bluebird, winston, mocha, jest, webpack, typescript, eslint, prettier, next, vue, angular, jquery, underscore, async, nodemon, pm2, socket.io, cors, helmet, passport

If the package name is a near-match (1-2 character edit distance, or matches a known typosquatting pattern) to any package on these lists, flag it HIGH:
> "[!] HIGH: Possible typosquatting -- [submitted-name] closely resembles [popular-name] (differs by: [description]). This is a common supply chain attack. Verify this is the package you intended before proceeding."

If the name is clearly intentional (different enough, no resemblance to popular packages): proceed silently.

**Tell the user:**

> "Canary v2.8  use at your own risk. Canary reduces risk but does not guarantee safety. Use your own judgment before installing any software.
>
> Everything I do during this evaluation is [Claude]  I'm fetching and reading code on your behalf. Nothing from this repo will be cloned or saved to your machine. If you choose Full mode, the software runs inside an isolated sandbox and those actions will be labeled [software under test]."

Then ask:

> "How thorough should I be?
>
Before presenting the tier menu, detect the platform:
```bash
uname -s 2>/dev/null || echo "Windows"
```

**On Windows**, present all three tiers:

> - **Quick** - I'll read the most important files via the GitHub API (entry points, install scripts, anything that runs at startup) and look for red flags. Nothing is cloned to your machine. No external tools needed. Takes about a minute.
> - **Medium** - Full static analysis using semgrep, bandit, trufflehog, and gitleaks - all running inside Windows Sandbox. Nothing from the target touches your machine. Requires Windows Sandbox (built into Windows 10/11 Pro). Takes a few minutes.
> - **Full** - Everything in Medium, plus I'll run the software inside the sandbox and watch what it actually does: network connections, files touched, persistence attempts. Requires Windows Sandbox, Wireshark, and Sysinternals. I'll walk you through anything missing.

**On Linux/Mac**, present only Quick and Medium (Docker-based), and explicitly note Full is unavailable:

> - **Quick** - I'll read the most important files via the GitHub API and look for red flags. Nothing is cloned to your machine. No external tools needed. Takes about a minute.
> - **Medium** - Full static analysis using semgrep, bandit, trufflehog, and gitleaks - running inside Docker so nothing from the target touches your machine. Requires Docker. Takes a few minutes.
> - **Full - not available on Linux/Mac** - Full mode requires Windows Sandbox and Sysinternals (Windows only). To get runtime behavior analysis, run this scan on a Windows machine.

**After the user chooses a tier, run dependency checks before doing anything else:**

### Dependency check  Quick

If the target is a GitHub URL:
```bash
gh --version 2>/dev/null && echo "OK" || echo "MISSING"
gh auth status 2>/dev/null && echo "OK" || echo "NOT LOGGED IN"
```

If `gh` is missing: offer to install via `winget install GitHub.cli` (Windows) or `brew install gh` (Mac/Linux). Verify before continuing.
If `gh auth` fails: guide through `gh auth login`. Wait for completion.
If target is a local path, pip package, or npm package: no tool check needed for Quick.

**VirusTotal API key (optional but strongly recommended):**

Check via PowerShell script file only -- never inline, bash will mangle the $env variable:
```powershell
# Write to a temp file and run it -- avoids bash escaping issues with $env:
'if ([string]::IsNullOrEmpty($env:VT_API_KEY)) { "VT_NOT_SET" } else { "VT_SET" }' |
  Out-File 'C:\temp\check-vt.ps1' -Encoding UTF8 -Force
powershell -NoProfile -File 'C:\temp\check-vt.ps1'
```
If not set:
> "VirusTotal integration isn't configured  I won't be able to check pre-compiled binaries against 70+ AV engines. This is especially important for repos that ship .exe or .dll files.
>
> To enable it: sign up free at https://www.virustotal.com, go to your profile  API Key, copy it, then set it with:
> `$env:VT_API_KEY = 'your-key-here'`
> Or add it to your PowerShell profile for persistence.
>
> Free tier gives 500 lookups/day  plenty for normal canary use. Continue without it?"

If user declines or skips: note "VirusTotal: not configured  binary hash checks skipped" in the report. Continue the scan.

### Dependency check  Medium

Run all Quick checks first, then:

**Check Windows Sandbox (required for Medium):**
```powershell
(Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -ErrorAction SilentlyContinue).State
```

If not Enabled:
> "Medium scan requires Windows Sandbox  static analysis tools run inside it so no target code or raw tool output ever touches your machine. Windows Sandbox isn't enabled yet.
>
> Options:
> - **Enable it now**  I'll run the command; requires a reboot, then come back and start the scan again.
> - **Switch to Quick**  I'll do an API-only evaluation. No sandbox needed, but no static analysis tools.
>
> What would you prefer?"

If user chooses Enable:
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
```
Then stop and tell the user to reboot and restart the scan.

If user chooses Quick: restart at Phase 1 with Quick tier. Do not proceed with Medium without Windows Sandbox.

**Check canary sandbox scripts (required for Medium):**
```powershell
Test-Path 'C:\sandbox\scripts\run-watchdog.ps1'
```
If missing:
> "The canary sandbox infrastructure isn't installed. Running the installer..."
```powershell
irm https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 | iex
```

Note: Python, Node, semgrep, bandit, and pip-audit do NOT need to be installed on the host.
They are installed fresh inside Windows Sandbox at scan time (via winget + pip inside the sandbox).
Only the two binary tools below need to be on the host, because they are Go binaries that
must be mapped into the sandbox -- they cannot be installed via pip inside it.

**Check trufflehog (host binary -- capability test: git mode):**
```bash
trufflehog git --help 2>/dev/null
```
This is the capability test, not a version check. If `trufflehog git --help` produces
usage output, the tool can perform git-mode secret scanning -- that is all canary needs
to know. Version number is not checked.

- If the command **errors or produces no output**: the tool is missing or is trufflehog v2
  (which has no `git` subcommand). Guide the user through binary install:
  > "trufflehog isn't installed or is the wrong version. The pip and winget packages both
  > install trufflehog v2, which is a different tool with a different CLI. You need the
  > binary release from the GitHub releases page.
  >
  > 1. Go to https://github.com/trufflesecurity/trufflehog/releases/latest
  > 2. Download trufflehog_[version]_windows_amd64.tar.gz
  > 3. Extract it -- you get trufflehog.exe
  > 4. Move it to a permanent location, e.g. C:\tools\trufflehog\trufflehog.exe
  > 5. Add C:\tools\trufflehog to your PATH if it isn't already
  >
  > Let me know when it's done and I'll run the capability test."

  After user confirms: re-run `trufflehog git --help`. If it still fails, note that
  git-history secrets scanning will use Claude's direct file review instead, and proceed.

- If the command **succeeds**: tool is capable. No further version check needed.

**Check gitleaks (host binary -- capability test: detect mode):**
```bash
gitleaks detect --help 2>/dev/null
```
Same principle: if `gitleaks detect --help` produces usage output, the tool is capable.

- If missing on **Windows**: `winget install gitleaks`. After install, re-run capability test.
  If winget fails: download binary from https://github.com/gitleaks/gitleaks/releases/latest
  (gitleaks_[version]_windows_x64.zip), extract gitleaks.exe, place on PATH.
- If missing on **Mac/Linux**: `brew install gitleaks`
- After install, re-run `gitleaks detect --help` to confirm capability before proceeding.

Show a clean summary to the user before installing anything:

> "Here's what I found on your machine:
> [OK] Windows Sandbox - enabled
> [OK] Canary sandbox scripts - deployed
> [ ] trufflehog - not installed (git-history secrets scan will use Claude analysis as fallback)
> [ ] gitleaks - not installed (working-tree cross-check will be skipped or I can install it)
>
> I can try to install both tools now, or start the scan immediately using Claude's built-in
> analysis for those checks. Either way, you'll get a complete evaluation.
> What would you prefer?"

Try to install missing tools if the user agrees. Re-run capability test after each install.
If install fails, note the fallback that will be used and proceed -- never block the scan
on a tool install failure.

**After both tools are confirmed callable, discover and record their binary paths:**
```powershell
$trufflehogPath = (Get-Command trufflehog -ErrorAction SilentlyContinue).Source
$gitleaksPath   = (Get-Command gitleaks   -ErrorAction SilentlyContinue).Source
```

Save both paths to the state file under `trufflehog_path` and `gitleaks_path`. These will be used when generating the sandbox `.wsb` config to create the correct `MappedFolder` blocks. If either path is null (tool not found after install), record it as a limitation and plan to skip that tool.

If the user declines any tool: note it as a limitation. Never skip silently  always record what was skipped and why.

### Dependency check  Full

Run all Medium checks first, then:

Check admin rights (required for Procmon, tshark, SAC registry):
```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```
If not admin:
> "Full mode needs administrator rights to run Procmon, tshark, and modify system settings. Please restart Claude Code as Administrator (right-click -' Run as administrator) and try again."
Stop here  do not proceed without admin rights.

Check Windows Sandbox:
```powershell
(Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -ErrorAction SilentlyContinue).State
```
If not Enabled:
> "Windows Sandbox isn't enabled on this machine. I can enable it for you  it requires a reboot after. Want me to do that now?"
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
```
After reboot, re-run the installer and continue.

Check Sysinternals:
```powershell
Test-Path 'C:\temp\security-tools\Sysinternals\Procmon64.exe'
Test-Path 'C:\temp\security-tools\Sysinternals\autorunsc64.exe'
```
If missing:
> "Sysinternals isn't installed at the expected path. Here's how to set it up:
> 1. Go to https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite
> 2. Download `SysinternalsSuite.zip`
> 3. Create the folder `C:\temp\security-tools\Sysinternals\` if it doesn't exist
> 4. Extract everything from the zip into that folder
> 5. You should now have `Procmon64.exe` and `autorunsc64.exe` in there
>
> Let me know when that's done and I'll continue."

After user confirms: verify both files exist before proceeding.

**tshark:**
```bash
tshark --version 2>/dev/null
```
- If missing on **Windows**: `winget install WiresharkFoundation.Wireshark`. This installs the full Wireshark suite which includes tshark. Requires a reboot or new terminal for PATH to update.
- If missing on **Mac**: `brew install wireshark` (includes tshark).
- Verify after install: `tshark --version` should show a version number. If not found after install, open a new terminal  Wireshark's installer updates PATH but the change isn't visible in the current session.
- Known issue on Windows: tshark requires Npcap (packet capture driver). The Wireshark installer includes it  accept the Npcap install prompt during setup.

Check sandbox scripts:
```powershell
Test-Path 'C:\sandbox\scripts\run-watchdog.ps1'
```
If missing:
> "The canary sandbox infrastructure isn't installed yet. Running the installer now..."
```powershell
irm https://raw.githubusercontent.com/AppDevOnly/canary/main/install.ps1 | iex
```

**Do not present the consent block until all required tools are confirmed present or the user has explicitly declined specific ones.**

**After all checks pass, present the consent block tailored to the chosen tier:**

> "Here's everything I'll do during this [Quick / Medium / Full] evaluation  I'll ask once and then run without interruptions.
>
> **[Claude]  all of this is me, not the software being evaluated:**
> - Fetch repo metadata and file tree from GitHub API
> - Read source files directly from GitHub (no download to your machine)
> - Search for secrets, hardcoded credentials, and suspicious patterns in the code
> *(Medium + Full only)* Launch Windows Sandbox and run `semgrep`, `bandit`, `trufflehog`, and `gitleaks` inside it  nothing from the target is ever written to your machine; only my interpreted summary leaves the sandbox
> *(Medium + Full only)* Run `pip-audit` and/or `npm audit` inside the sandbox to check dependencies for known CVEs
> - Write a report to `~/canary-reports/`
> - Delete all target files (clone, downloads, sandbox output) after the report is written
> - Save scan progress after each step so you can resume if anything interrupts
>
> *(Full only)* **[software under test]  this is the code running inside the sandbox:**
> - Clone the target repo and download the release binary inside the sandbox
> - Run the software inside Windows Sandbox  it cannot touch your files, browser, or main system
> - Observe what network connections it makes, what files it creates, whether it tries to persist
> - Sandbox is destroyed after evaluation  nothing persists to your main system
>
> Ready to proceed?"

Wait for a yes before starting. Do not ask for permission again during the evaluation unless a genuinely unexpected action comes up.

**After consent, initialize scan state:**

Write a state file to track progress:
```json
{
  "target": "<url or path>",
  "target_slug": "<slug>",
  "date": "<YYYY-MM-DD>",
  "level": "<Quick|Medium|Full>",
  "phases_complete": [],
  "findings_count": 0,
  "sac_original_state": null,
  "cleanup_complete": false
}
```

Write to `~/canary-reports/<target-slug>-state.json`. Update this file after each phase completes by adding the phase name to `phases_complete`. This is how resume works after a restart.

---

## Phase 2  Static security analysis

### 2a. Code inspection

**Progress:** Tell the user "Reading source files..." before starting. When done: "Source review complete  [N findings / no issues found]."

**Quick and above:** Read these files first (in order of risk):
1. Entry points: `__main__.py`, `main.py`, `index.js`, `cli.py`, `app.py`
2. Install/setup scripts: `setup.py`, `pyproject.toml`, `package.json`, `Makefile`, `*.sh`, `*.ps1`
3. Any file with network calls, subprocess calls, or `eval()`/`exec()`

**Medium and above:** Read the full codebase, prioritizing files with network I/O, file I/O, subprocess calls, authentication, and data handling.

**File count guard:** Cap reads at 500 files maximum. Use the GitHub API file tree to count files first. If the repo has more than 500 files, apply this priority order and stop when the cap is reached:
1. Entry points and install scripts (always read)
2. Files containing network/subprocess/eval patterns (search via API)
3. Files in `src/`, `lib/`, `core/` directories
4. Remaining files sorted by extension risk: `.py > .js > .ts > .sh > .ps1 > .go > other`

If the cap is reached, note it in the report: "File count capped at 500 of [N] total  [N] files not reviewed." This prevents exhausting the GitHub API rate limit (5,000 req/hour) on large repos.

**Batch reads:** Read multiple files per tool call  fetch 5-10 files in parallel rather than one at a time. Each single-file read triggers a full cache re-injection; batching eliminates that overhead. Group by directory or risk tier when batching.

Flag these patterns (rate each CRITICAL / HIGH / MEDIUM / LOW / INFO):

- `eval()` / `exec()` on external input  **CRITICAL** (e.g. `eval(response.text)`)
- Subprocess with shell=True on external input  **CRITICAL**
- Writes to startup/autorun locations  **CRITICAL** (Registry Run keys, `~/.bashrc`, cron)
- Outbound connections to unexpected domains  **HIGH**
- `postinstall` / `prepare` scripts in package.json  **HIGH** (runs at install time, before review)
- Base64-encoded strings  **HIGH** (common obfuscation technique)
- Hardcoded IP addresses (non-localhost)  **HIGH**
- `os.system()` / `subprocess` calls  **MEDIUM** (may be legitimate; check args)
- `install_requires` with no version pins  **MEDIUM** (unpinned deps allow supply chain attacks)
- `__import__` / dynamic imports  **MEDIUM** (can obfuscate what's loaded)

Save state after 2a completes.

### 2b"2d. Sandbox static analysis (Medium and Full)

**Medium and above only. All static analysis tools run inside Windows Sandbox  nothing from the target is written to the host machine.**

**Architecture:** Generate a Medium-mode sandbox config that:
1. Maps trufflehog and gitleaks binaries from host into sandbox (read-only) using paths discovered in the dep check
2. Maps `C:\sandbox\tool-output\` host folder into sandbox as `C:\sandbox\tool-output\` (read-write)  this is where tool results land
3. Clones the target repo inside the sandbox (no clone on host)
4. Installs Python-based tools (semgrep, bandit, pip-audit) fresh inside the sandbox via pip
5. Runs all static analysis tools inside the sandbox
6. Claude reads only the summarized output from the mapped tool-output folder  raw JSON is never reproduced in Claude's context

**10-minute hard timeout:** The Medium sandbox launch must complete within 10 minutes. If no `RESULT:` line appears in `setup-static.log` within 600 seconds of launch, kill the sandbox process, log `TIMEOUT: static analysis did not complete within 10 minutes`, and proceed to the report with whatever partial output exists.

**Before launching the Medium sandbox, create the output directory if it doesn't exist:**
```powershell
New-Item -ItemType Directory -Force -Path 'C:\sandbox\tool-output' | Out-Null
```

**Generate `.wsb` config for static analysis (Medium):**

Build a target-specific .wsb that maps:
- `C:\sandbox\scripts\` -' `C:\sandbox\scripts\` (read-only  bootstrap and setup scripts)
- `C:\sandbox\tool-output\` -' `C:\sandbox\tool-output\` (read-write  tool results)
- The directory containing the trufflehog binary (from `$trufflehogPath` in state) -' `C:\tools\trufflehog\` (read-only)
- The directory containing the gitleaks binary (from `$gitleaksPath` in state) -' `C:\tools\gitleaks\` (read-only)

No Sysinternals mapping needed for Medium (no process monitoring).
No target binary download needed (tools run against cloned source).

**Generate `C:\sandbox\scripts\setup-static.ps1`** with the following behavior inside the sandbox:

```powershell
# Inside sandbox  runs as part of bootstrap
Set-ExecutionPolicy Bypass -Scope Process -Force
New-Item -ItemType Directory -Force -Path 'C:\sandbox\tool-output' | Out-Null
Start-Transcript 'C:\sandbox\tool-output\setup-static.log'

# 0. Bootstrap runtime dependencies via winget
# Windows Sandbox is a clean Windows image -- Python, Git, and Node are not pre-installed.
# winget is available in Windows 11 Sandbox. Install what we need before anything else.

function Install-IfMissing {
    param($Cmd, $WingetId, $Label)
    if (-not (Get-Command $Cmd -ErrorAction SilentlyContinue)) {
        Write-Host "Installing $Label in sandbox..."
        winget install $WingetId --silent --accept-package-agreements --accept-source-agreements 2>&1
        # Reload PATH so newly installed tools are visible
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH","User")
    } else {
        Write-Host "$Label already available"
    }
}

Install-IfMissing -Cmd 'python' -WingetId 'Python.Python.3.12' -Label 'Python 3.12'
Install-IfMissing -Cmd 'git'    -WingetId 'Git.Git'            -Label 'Git'
Install-IfMissing -Cmd 'node'   -WingetId 'OpenJS.NodeJS.LTS'  -Label 'Node.js LTS'

# Verify Python and Git are available -- both are required; Node is optional
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "RESULT: Python install failed -- cannot run semgrep, bandit, pip-audit"
    Stop-Transcript; exit 1
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "RESULT: Git install failed -- cannot clone target repo"
    Stop-Transcript; exit 1
}
$nodeAvailable = [bool](Get-Command node -ErrorAction SilentlyContinue)
if (-not $nodeAvailable) { Write-Host "Node not available -- npm audit will be skipped" }

# 1. Install Python analysis tools fresh inside sandbox
Write-Host "Installing Python tools..."
pip install --quiet semgrep bandit pip-audit 2>'C:\sandbox\tool-output\pip-install-stderr.txt'
Write-Host "Pip install stderr: $(Get-Content 'C:\sandbox\tool-output\pip-install-stderr.txt' -Raw)"

# 1a. Capability check -- verify each pip tool actually works in this environment.
# This catches PATH gaps, Python version mismatches, and install failures before they
# cause silent mid-scan errors. Refresh PATH first in case pip added to a new location.
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("PATH","User")

$semgrepAvail  = [bool](semgrep  --version 2>$null)
$banditAvail   = [bool](bandit   --version 2>$null)
$pipAuditAvail = [bool](pip-audit --version 2>$null)

if (-not $semgrepAvail)  { Write-Host "WARN: semgrep not callable -- SAST will use Claude analysis" }
if (-not $banditAvail)   { Write-Host "WARN: bandit not callable -- Python patterns will use Claude analysis" }
if (-not $pipAuditAvail) { Write-Host "WARN: pip-audit not callable -- Python CVEs will use NVD API fallback" }

# 2. Clone the target repo (hooks disabled  prevents hook execution during clone)
$targetUrl = '{{TARGET_CLONE_URL}}'
$cloneDir  = 'C:\target'
git clone --depth 50 --config core.hooksPath=NUL $targetUrl $cloneDir 2>&1
# depth 50: captures recently-removed secrets in trufflehog git mode
if (-not (Test-Path $cloneDir)) {
    Write-Host "RESULT: Clone failed"
    Stop-Transcript; exit 1
}
Write-Host "Clone complete  $((Get-ChildItem $cloneDir -Recurse -File).Count) files"

# 3. Run semgrep
if ($semgrepAvail) {
    Write-Host "Running semgrep..."
    semgrep --config=auto --json $cloneDir 2>'C:\sandbox\tool-output\semgrep-stderr.txt' |
        Out-File 'C:\sandbox\tool-output\semgrep.json' -Encoding UTF8
    if ($LASTEXITCODE -ne 0) {
        Write-Host "TOOL ERROR semgrep exit=$LASTEXITCODE stderr=$(Get-Content 'C:\sandbox\tool-output\semgrep-stderr.txt' -Raw)"
    } else { Write-Host "semgrep complete" }
} else { Write-Host "SKIP semgrep (capability check failed) -- Claude analysis covers this check" }

# 4. Run bandit (Python projects only)
$pyFiles = Get-ChildItem $cloneDir -Recurse -Filter '*.py' -ErrorAction SilentlyContinue
if ($banditAvail -and $pyFiles.Count -gt 0) {
    Write-Host "Running bandit ($($pyFiles.Count) Python files)..."
    bandit -r $cloneDir -f json 2>'C:\sandbox\tool-output\bandit-stderr.txt' |
        Out-File 'C:\sandbox\tool-output\bandit.json' -Encoding UTF8
    if ($LASTEXITCODE -gt 1) {  # bandit exits 1 on findings (normal), >1 on error
        Write-Host "TOOL ERROR bandit exit=$LASTEXITCODE stderr=$(Get-Content 'C:\sandbox\tool-output\bandit-stderr.txt' -Raw)"
    } else { Write-Host "bandit complete" }
} elseif (-not $banditAvail) { Write-Host "SKIP bandit (capability check failed) -- Claude analysis covers Python patterns"
} else { Write-Host "SKIP bandit  no Python files found" }

# 5. Run trufflehog (mapped binary from host)
$trufflehogExe = 'C:\tools\trufflehog\{{TRUFFLEHOG_BIN}}'
if (Test-Path $trufflehogExe) {
    Write-Host "Running trufflehog..."
    # Build correct file URI for Windows: file:///C:/target (three slashes, forward slashes)
    $cloneDirUri = "file:///" + ($cloneDir -replace '\\', '/')
    & $trufflehogExe git $cloneDirUri --json 2>'C:\sandbox\tool-output\trufflehog-stderr.txt' |
        Out-File 'C:\sandbox\tool-output\trufflehog.json' -Encoding UTF8
    if ($LASTEXITCODE -ne 0) {
        Write-Host "TOOL ERROR trufflehog exit=$LASTEXITCODE stderr=$(Get-Content 'C:\sandbox\tool-output\trufflehog-stderr.txt' -Raw)"
    } else { Write-Host "trufflehog complete" }
} else { Write-Host "SKIP trufflehog  binary not found at $trufflehogExe" }

# Using 'git' mode with --depth 50 clone: scans last 50 commits including recently-removed secrets.

# 6. Run gitleaks (mapped binary from host)
$gitleaksExe = 'C:\tools\gitleaks\{{GITLEAKS_BIN}}'
if (Test-Path $gitleaksExe) {
    Write-Host "Running gitleaks..."
    & $gitleaksExe detect --source $cloneDir --report-format json `
        --report-path 'C:\sandbox\tool-output\gitleaks.json' `
        2>'C:\sandbox\tool-output\gitleaks-stderr.txt'
    if ($LASTEXITCODE -gt 1) {  # gitleaks exits 1 on findings (normal), >1 on error
        Write-Host "TOOL ERROR gitleaks exit=$LASTEXITCODE stderr=$(Get-Content 'C:\sandbox\tool-output\gitleaks-stderr.txt' -Raw)"
    } else { Write-Host "gitleaks complete" }
} else { Write-Host "SKIP gitleaks  binary not found at $gitleaksExe" }

# 7. Run pip-audit (Python) -- auto-detects pyproject.toml, Pipfile, requirements*.txt
$hasPyManifest = (Test-Path "$cloneDir\pyproject.toml") -or
                 (Test-Path "$cloneDir\Pipfile") -or
                 (Test-Path "$cloneDir\setup.py") -or
                 (Test-Path "$cloneDir\setup.cfg") -or
                 ((Get-ChildItem "$cloneDir" -Filter 'requirements*.txt' -ErrorAction SilentlyContinue).Count -gt 0)
if ($pipAuditAvail -and $hasPyManifest) {
    Write-Host "Running pip-audit (auto-detecting manifest)..."
    Push-Location $cloneDir
    pip-audit --format json 2>'C:\sandbox\tool-output\pip-audit-stderr.txt' |
        Out-File 'C:\sandbox\tool-output\pip-audit.json' -Encoding UTF8
    if ($LASTEXITCODE -gt 1) {
        Write-Host "TOOL ERROR pip-audit exit=$LASTEXITCODE stderr=$(Get-Content 'C:\sandbox\tool-output\pip-audit-stderr.txt' -Raw)"
    } else { Write-Host "pip-audit complete" }
    Pop-Location
} elseif (-not $pipAuditAvail) { Write-Host "SKIP pip-audit (capability check failed) -- Python CVEs will use NVD API fallback"
} else { Write-Host "SKIP pip-audit  no Python manifest found (pyproject.toml, Pipfile, requirements*.txt, setup.py)" }

# 8. Run npm audit (Node)
if ((Test-Path "$cloneDir\package.json") -and $nodeAvailable) {
    Write-Host "Running npm audit..."
    Push-Location $cloneDir
    if (-not (Test-Path "$cloneDir\package-lock.json")) {
        Write-Host "package-lock.json not found  generating with npm install --package-lock-only..."
        npm install --package-lock-only --ignore-scripts 2>'C:\sandbox\tool-output\npm-install-stderr.txt'
        if ($LASTEXITCODE -ne 0) {
            Write-Host "TOOL ERROR npm install --package-lock-only failed  npm audit will be skipped"
            '{"warning":"package-lock.json could not be generated."}' |
                Out-File 'C:\sandbox\tool-output\npm-audit.json' -Encoding UTF8
            Pop-Location
        }
    }
    if (Test-Path "$cloneDir\package-lock.json") {
        npm audit --json 2>'C:\sandbox\tool-output\npm-audit-stderr.txt' |
            Out-File 'C:\sandbox\tool-output\npm-audit.json' -Encoding UTF8
        if ($LASTEXITCODE -gt 1) {
            Write-Host "TOOL ERROR npm audit exit=$LASTEXITCODE"
        } else { Write-Host "npm audit complete" }
    }
    Pop-Location
} elseif (Test-Path "$cloneDir\package.json") {
    Write-Host "SKIP npm audit  Node.js not available in sandbox (winget install failed or not attempted)"
    '{"warning":"Node.js not available in sandbox. npm audit skipped."}' |
        Out-File 'C:\sandbox\tool-output\npm-audit.json' -Encoding UTF8
}

Write-Host "RESULT: Static analysis complete"
Stop-Transcript
```

When generating this script, substitute:
- `{{TARGET_CLONE_URL}}`  the target's GitHub URL (e.g. `https://github.com/foo/bar`)
- `{{TRUFFLEHOG_BIN}}`  filename of the trufflehog binary (basename of `$trufflehogPath`)
- `{{GITLEAKS_BIN}}`  filename of the gitleaks binary (basename of `$gitleaksPath`)

**Launch the Medium sandbox and wait for completion:**

Write the generated .wsb and setup-static.ps1 files, then launch:
```powershell
$wsbPath = "C:\sandbox\$targetName-static.wsb"
$generatedWsb | Out-File $wsbPath -Encoding UTF8 -Force
Start-Process WindowsSandbox -ArgumentList $wsbPath -WindowStyle Normal
Write-Host "Medium sandbox launched - waiting for static analysis (max 10 min)..."
```

Poll `C:\sandbox\tool-output\setup-static.log` for the `RESULT:` line (written by setup-static.ps1 on completion):
```powershell
$deadline = (Get-Date).AddSeconds(600)
$resultFound = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 15
    $log = Get-Content 'C:\sandbox\tool-output\setup-static.log' -ErrorAction SilentlyContinue
    if ($log -match 'RESULT:') {
        $resultFound = $true
        Write-Host "Static analysis complete."
        break
    }
    $elapsed = [int]((Get-Date) - ($deadline.AddSeconds(-600))).TotalSeconds
    Write-Host "Still running - ${elapsed}s elapsed. Watching for RESULT..."
}
if (-not $resultFound) {
    Get-Process -Name WindowsSandboxClient, WindowsSandboxServer -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host "TIMEOUT: static analysis did not complete within 10 minutes"
    # Continue to report with whatever partial output exists in C:\sandbox\tool-output\
}
```

Tell the user: "Sandbox analysis [complete / timed out after 10 minutes]. Reading results..."

**Critical rules for all tool output:**
- Never print raw JSON blobs into Claude's conversation  always parse and summarize
- **Summarize inside the sandbox**  add a summarization step to setup-static.ps1 that converts raw JSON to a plain-text `summary.txt` before the sandbox closes. Claude reads `summary.txt`, not the raw JSON files. This eliminates token waste and prevents AV triggers from exploit signatures in raw tool output landing in Claude's context.
- Always capture stderr from every tool run; surface errors in a "Tool Errors" section in the report
- If a tool crashes (non-zero exit + no output file), log it as a tool error  do NOT silently skip
- If semgrep crashes with a Unicode error: log the offending file path, skip it, continue full-scope scan  do NOT narrow the scan directory
- If a tool output file is empty or missing after the sandbox run, note it as a tool error

**After sandbox completes, read results from `C:\sandbox\tool-output\`:**

**2b  Semgrep findings:**

**Progress:** "Reading semgrep results..." When done: "Semgrep complete  [N findings / no findings / tool error: X]."

Parse `C:\sandbox\tool-output\semgrep.json`. Focus on HIGH and CRITICAL findings. Skip INFO-level noise.

**2c  Bandit findings (Python only):**

**Progress:** "Reading bandit results..." When done: "Bandit complete  [N findings / no findings]."

Parse `C:\sandbox\tool-output\bandit.json`. Flag HIGH and MEDIUM severity. Cross-reference with manual code inspection  bandit has false positives.

**2d  Secrets scan:**

**Progress:** "Reading secrets scan results..." When done: "Secrets scan complete  [N secrets found / no secrets found]."

Parse `C:\sandbox\tool-output\trufflehog.json` and `C:\sandbox\tool-output\gitleaks.json`.

Report any matches with file + line number. Rate HIGH if found in committed source. Do NOT print the full value  show first 8 chars + `...`

If static tools weren't available (user running Quick or tools missing), manually search via GitHub API for patterns:
- Long random strings adjacent to words: key, token, secret, password, api, auth
- AWS key patterns: `AKIA[0-9A-Z]{16}`
- Private key headers: `-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`

Save state after static analysis phases complete.

### 2e. Dependency audit

**Medium and above only.**

**Progress:** "Checking dependencies for known CVEs..." When done: "Dependency audit complete."

pip-audit and npm audit ran inside the sandbox as part of Phase 2b-2d. Read results from `C:\sandbox\tool-output\pip-audit.json` and `C:\sandbox\tool-output\npm-audit.json`.

Do NOT run pip-audit or npm audit on the host  no dependency manifests exist locally (the clone is inside the sandbox).

Parse results and report CVEs by severity. If a tool output file is missing or empty, note it as a tool error rather than "no CVEs found."

If the target has no Python or Node manifest files: "No Python/Node dependency manifests found  dependency audit skipped."

If audit tools were unavailable and no output file exists, manually check dependencies visible in Phase 2a GitHub API reads and flag any known to have had critical CVEs (e.g. `log4j`, `lodash < 4.17.21`, `requests < 2.20.0`).

**NVD API - CVE lookup for non-pip/npm dependencies (C++ libs, system packages, Go modules, etc.):**

For dependencies that pip-audit and npm audit don't cover, query the NIST NVD API directly. Free, no key required (rate-limited to 5 req/30s without key; optional `NVD_API_KEY` raises limit to 50 req/30s).

```bash
# Look up CVEs for a specific package + version
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<package-name>&keywordExactMatch" \
  | grep -o '"id":"CVE-[^"]*"\|"baseScore":[0-9.]*\|"baseSeverity":"[^"]*"'
```

Use this for:
- C/C++ libraries referenced in CMakeLists.txt, conanfile.txt, vcpkg.json
- Go modules in go.mod
- Rust crates in Cargo.toml (if cargo-audit isn't available)
- System package deps referenced in Dockerfile or install scripts

Rate limit: pause 6 seconds between requests without NVD_API_KEY. Cap at 20 lookups per scan to avoid excessive delay. If NVD_API_KEY is set, no pause needed up to 50 req/30s.

Report NVD findings the same way as pip/npm CVEs: package name, CVE ID, severity score, brief description.

**SBOM generation (Medium and above, while audit JSON files are still present):**

After reading pip-audit and npm-audit results -- before deleting the tool output files -- generate a CycloneDX 1.5 SBOM. This runs on the host using the mapped output files.

```powershell
$sbomPath = "$HOME\canary-reports\$targetSlug-$(Get-Date -Format 'yyyyMMdd')-sbom.json"
$components = [System.Collections.Generic.List[object]]::new()
$vulns      = [System.Collections.Generic.List[object]]::new()
$idx        = 0

# Python components from pip-audit
if (Test-Path 'C:\sandbox\tool-output\pip-audit.json') {
    $pipData = Get-Content 'C:\sandbox\tool-output\pip-audit.json' -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
    foreach ($dep in $pipData.dependencies) {
        $idx++; $ref = "pkg-$idx"
        $components.Add(@{
            type       = "library"
            'bom-ref'  = $ref
            name       = $dep.name
            version    = $dep.version
            purl       = "pkg:pypi/$($dep.name.ToLower())@$($dep.version)"
        })
        foreach ($v in $dep.vulns) {
            $vulns.Add(@{
                id             = $v.id
                source         = @{ name = "OSV/PyPI"; url = "https://osv.dev/vulnerability/$($v.id)" }
                recommendation = if ($v.fix_versions) { "Upgrade to $($v.fix_versions[0])" } else { "No fix available" }
                affects        = @(@{ ref = $ref })
            })
        }
    }
}

# Node components from npm audit
if (Test-Path 'C:\sandbox\tool-output\npm-audit.json') {
    $npmData = Get-Content 'C:\sandbox\tool-output\npm-audit.json' -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($npmData.dependencies) {
        foreach ($pkgName in ($npmData.dependencies | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue).Name) {
            $pkg = $npmData.dependencies.$pkgName
            $idx++; $ref = "pkg-$idx"
            $components.Add(@{
                type      = "library"
                'bom-ref' = $ref
                name      = $pkgName
                version   = if ($pkg.version) { $pkg.version } else { "unknown" }
                purl      = "pkg:npm/$pkgName@$(if ($pkg.version) { $pkg.version } else { 'unknown' })"
            })
        }
    }
}

$sbom = [ordered]@{
    bomFormat   = "CycloneDX"
    specVersion = "1.5"
    version     = 1
    serialNumber = "urn:uuid:$([System.Guid]::NewGuid().ToString())"
    metadata    = [ordered]@{
        timestamp = (Get-Date -Format 'o')
        tools     = @(@{ vendor = "AppDevOnly"; name = "Canary"; version = "2.8" })
        component = @{ type = "application"; name = $targetName; version = "unknown" }
    }
    components      = $components.ToArray()
    vulnerabilities = $vulns.ToArray()
}

New-Item -ItemType Directory -Force -Path "$HOME\canary-reports" | Out-Null
$sbom | ConvertTo-Json -Depth 10 | Out-File $sbomPath -Encoding UTF8 -Force
Write-Host "SBOM: $sbomPath ($($components.Count) components, $($vulns.Count) vulnerabilities)"
```

If no audit JSON files exist (Quick scan or tools unavailable): skip SBOM generation silently and note it in the report as "Not generated -- requires Medium or Full evaluation."

If the JSON files exist but are malformed or empty: log a warning, skip SBOM, continue.

The SBOM file stays in `~/canary-reports/` -- it is NOT deleted during cleanup. It is a deliverable, not temp output.

**After SBOM generation, delete sandbox output files from the host:**
```powershell
Remove-Item 'C:\sandbox\tool-output\*.json' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.txt' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.log' -ErrorAction SilentlyContinue
```
This deletion happens here -- after Phase 2e has read pip-audit.json, npm-audit.json, and generated the SBOM -- not earlier. Deleting before 2e would leave the dep audit and SBOM with no data.

Save state after 2e completes.

### 2f. License compliance

**Medium and above only.**

**Progress:** "Checking license compliance..." When done: "License check complete."

Summarize licenses used by direct dependencies. Flag:
- GPL/AGPL in commercial contexts  MEDIUM (may require source disclosure)
- Unknown/unlicensed packages  HIGH (legal risk)
- License mismatches (project claims MIT but depends on GPL)

Save state after 2f completes.

---

## Phase 3  Code quality assessment

**Medium and above only.**

**Execution model:** This phase uses source files already fetched via the GitHub API in Phase 2a. No additional tool execution, sandbox launch, or network calls are needed. All analysis is performed by Claude on the already-fetched code.

**Progress:** "Analyzing code quality..." When done: "Code quality assessment complete  [N findings]."

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

Save state after Phase 3 completes.

---

## Phase 4  Dynamic sandbox (full mode only)

*Skip this phase if the user chose Quick or Medium, or if no sandbox is available.*

**Important:** Before running anything from the target, warn the user if static analysis already found serious issues (CRITICAL findings). Give them the option to stop here rather than run potentially hostile code even in a sandbox.

If Windows Sandbox is available:

**Autoruns baseline and tshark capture  run before launching the sandbox:**


```powershell
New-Item -ItemType Directory -Force -Path 'C:\sandbox\autoruns' | Out-Null
New-Item -ItemType Directory -Force -Path 'C:\sandbox\tool-output' | Out-Null
$autorunsExe = 'C:\temp\security-tools\Sysinternals\autorunsc64.exe'
Write-Host "Taking Autoruns before-snapshot..."
& $autorunsExe /accepteula '-a' '*' -c -h -s -nobanner -o 'C:\sandbox\autoruns\autoruns-before.csv' '*'

# Start tshark BEFORE sandbox launches - captures all early network activity including sandbox boot
$tsharkProc = Start-Process tshark -ArgumentList '-i "vEthernet (Default Switch)" -w C:\sandbox\tool-output\network-capture.pcap' -PassThru -WindowStyle Hidden
Write-Host "tshark capture started (PID $($tsharkProc.Id)) on vEthernet (Default Switch)"
```

Store the tshark PID in a variable  needed to stop it cleanly after the sandbox closes.

After the sandbox run, take a second snapshot and diff:

```powershell
Write-Host "Taking Autoruns after-snapshot..."
& $autorunsExe /accepteula '-a' '*' -c -h -s -nobanner -o 'C:\sandbox\autoruns\autoruns-after.csv' '*'

# Show new entries (persistence attempts)
$before = Import-Csv 'C:\sandbox\autoruns\autoruns-before.csv'
$after  = Import-Csv 'C:\sandbox\autoruns\autoruns-after.csv'
Compare-Object $before $after -Property 'Image Path','Entry' |
    Where-Object { $_.SideIndicator -eq '=>' }
```

Flag any new entries as HIGH  they represent persistence the software attempted to install outside the sandbox.

**Pre-flight: check Smart App Control (SAC) state before launching.**

```powershell
$sacState = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
```

- `0` = Off  proceed normally
- `1` = Evaluation mode  will block unsigned binaries
- `2` = On  will block unsigned binaries
- `$null` = key not present  SAC not active, proceed normally

If SAC is 1 or 2, present this consent prompt before doing anything else:

> "To run this software in the sandbox, I need to temporarily disable Smart App Control on your machine.
>
> **What that means in plain English:** Smart App Control is a Windows security feature that blocks unsigned software from running. Disabling it means Windows will be slightly more permissive for a few minutes while the scan runs. This affects your whole machine, not just the sandbox.
>
> **Why it's still safe:** The software itself runs inside an isolated sandbox  it can't touch your files, your browser, or anything on your main system. I'm only disabling SAC so Windows will allow it to launch inside that container. Once the scan finishes, I'll re-enable it and show you exactly how to verify it's back on.
>
> **Your options:**
> - **Yes, proceed**  I'll disable SAC, run the scan, and re-enable it when done
> - **No, skip sandbox**  I'll write the report based on static analysis only and clearly note that runtime behavior wasn't observed
>
> What would you like to do?"

Wait for explicit confirmation before touching SAC. If the user says no, skip to Phase 5 and note in the Sandbox Results section: "User declined to disable Smart App Control. Runtime analysis was not performed. Results are based on static analysis only."

If the user says yes, disable SAC and **spawn a new PowerShell process** to pick up the change  the registry update only takes effect in a new session:

```powershell
# Disable SAC
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' `
    -Name VerifiedAndReputablePolicyState -Value 0 -Type DWord -Force

# Verify it took
$check = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy').VerifiedAndReputablePolicyState
Write-Host "SAC state now: $check (0 = Off)"
```

Record `$sacState` in the state file so it can be restored even if the session is interrupted. All sandbox launch commands must be run in a **new** PowerShell process (via `Start-Process powershell`) so the policy change is in effect.

After the sandbox run completes (success or failure), **always re-enable SAC** if it was active before:

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' `
    -Name VerifiedAndReputablePolicyState -Value $sacState -Type DWord -Force
Write-Host "Smart App Control restored to original state ($sacState)."
```

Then tell the user:

> "Smart App Control has been re-enabled. To verify: open Windows Security > App & browser control > Smart App Control. Or run: `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy').VerifiedAndReputablePolicyState`  it should return $sacState."

Before launching, warn the user:

> "I'm about to start the sandbox. Here's what to expect:
> - A Windows Sandbox window will open  this is normal. Don't close it.
> - Additional windows may appear as the software launches inside the sandbox.
> - **You don't need to interact with any of those windows.** Just keep an eye on this Claude window  I'll report everything I observe here as it happens.
> - When the evaluation is done, the sandbox will close automatically and I'll write the report.
> - **If anything looks wrong or gets stuck, just tell me in plain English**  describe what you're seeing and I'll figure out what to do. You don't need to know any commands."

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

**Generate `setup.ps1` for this target from the template:**

Read `C:\sandbox\scripts\setup-template.ps1`, fill in the placeholders, and write to `C:\sandbox\scripts\setup.ps1`:

- `{{TARGET_NAME}}`  friendly name (e.g. `shadPS4`)
- `{{TARGET_URL}}`  direct download URL for the release binary or zip. Find via GitHub releases API: `gh api repos/<owner>/<repo>/releases/latest --jq '.assets[] | select(.name | test("win.*64|x64.*win"; "i")) | .browser_download_url'`
- `{{BINARY_NAME}}`  exact filename of the exe (check release asset name or README)
- `{{EXTRACT_DIR}}`  extraction path inside sandbox (e.g. `C:\shadps4_local`)
- `{{LAUNCH_ARGS}}`  command line args if needed, empty string if none

```powershell
$template = Get-Content 'C:\sandbox\scripts\setup-template.ps1' -Raw
$template = $template -replace '{{TARGET_NAME}}',  $targetName
$template = $template -replace '{{TARGET_URL}}',   $targetUrl
$template = $template -replace '{{BINARY_NAME}}',  $binaryName
$template = $template -replace '{{EXTRACT_DIR}}',  $extractDir
$template = $template -replace '{{LAUNCH_ARGS}}',  $launchArgs
$template | Out-File 'C:\sandbox\scripts\setup.ps1' -Encoding UTF8 -Force
Write-Host "setup.ps1 generated for $targetName"
```

**VirusTotal scan of download URL (Full mode, if VT_API_KEY is set):**

Before launching the sandbox, check the download URL against VirusTotal. This catches trojanized release binaries that pass static analysis clean.

```powershell
if ($env:VT_API_KEY -and $targetUrl) {
    Write-Host "Checking download URL against VirusTotal..."
    $encoded = [uri]::EscapeDataString($targetUrl)
    $submit = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/urls" -Method POST `
        -Headers @{"x-apikey" = $env:VT_API_KEY} `
        -Body "url=$encoded" -ContentType "application/x-www-form-urlencoded" `
        -ErrorAction SilentlyContinue
    if ($submit.data.id) {
        $analysisId = $submit.data.id
        Start-Sleep -Seconds 20
        $result = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/analyses/$analysisId" `
            -Headers @{"x-apikey" = $env:VT_API_KEY} -ErrorAction SilentlyContinue
        $stats = $result.data.attributes.stats
        # stats.malicious, stats.suspicious, stats.undetected, stats.harmless
        if ($stats.malicious -gt 0) {
            Write-Host "CRITICAL: VirusTotal flagged download URL  $($stats.malicious) engines detect malicious content"
        } elseif ($stats.suspicious -gt 0) {
            Write-Host "HIGH: VirusTotal flagged download URL as suspicious  $($stats.suspicious) engines"
        } else {
            Write-Host "VirusTotal: download URL clean ($($stats.undetected + $stats.harmless) engines checked)"
        }
    } else {
        Write-Host "VirusTotal: URL submission failed (API error or rate limit)  proceeding without check"
    }
} else {
    Write-Host "VirusTotal: skipped (VT_API_KEY not set)"
}
```

If `malicious > 0`: stop before launching the sandbox and warn the user:
> "VirusTotal flagged the download URL as malicious ([N] engines). This is a strong signal the release binary has been tampered with or is outright malware. I strongly recommend not running this in the sandbox. Do you want to abort?"

Wait for explicit confirmation before proceeding if flagged malicious.

Then ask the user before launching:

> "Will you be interacting with the sandbox directly (clicking, typing commands), or should I run everything automatically and you just watch this window?"

- **Automated** (default)  stall timeout **90 seconds**. If the binary hasn't produced any log output in 90 seconds, the watchdog restarts automatically.
- **Interactive**  stall timeout **600 seconds** (10 minutes). Gives you time to interact with the software without the watchdog killing it.

```powershell
# Automated (default)  new process so SAC policy change is in effect
Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File C:\sandbox\scripts\run-watchdog.ps1 -WsbFile `"$wsbPath`" -StallTimeoutSec 90 -MaxRetries 2" -WindowStyle Normal

# Interactive
Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File C:\sandbox\scripts\run-watchdog.ps1 -WsbFile `"$wsbPath`" -StallTimeoutSec 600 -MaxRetries 2" -WindowStyle Normal
```

**While monitoring `C:\sandbox\tool-output\stream.log`, give the user a heartbeat every 30 seconds:**
> "Still running  [elapsed]s. You'll see output here as it comes in. Nothing to do  just keep an eye on this window."

**When stream.log shows a retry attempt:**
Tell the user immediately:
> "The sandbox stopped responding  restarting automatically. Attempt [N] of 2. Everything we've found so far is saved."

**Stop tshark after the sandbox closes:**

```powershell
Stop-Process -Id $tsharkProc.Id -Force -ErrorAction SilentlyContinue
Write-Host "tshark capture stopped"
```

**After the sandbox run, read `stream.log` and `setup.log` to determine outcome:**

- If `setup.log` contains `"RESULT: Binary could not be launched"`  **do not retry**. Record as a sandbox finding: "Binary blocked  likely SAC/WDAC policy or missing dependency. Dynamic analysis not possible on this system without further configuration." Proceed to write the report.
- If the sandbox exited before `setup.log` appeared (mapped-folder failure)  retry **once only**, then report the failure.
- If the binary launched successfully  run post-run analysis before writing the report.

**Post-run analysis (binary launched successfully):**

Unique DNS names queried by the sandbox:
```powershell
Get-Content C:\sandbox\tool-output\network-vswitch.log |
    ForEach-Object { ($_ -split '\|')[3] } |
    Where-Object { $_ -and $_ -notmatch '^\d' -and $_ -notmatch 'arpa' } |
    Sort-Object -Unique
```

External IPs connected to:
```powershell
Get-Content C:\sandbox\tool-output\network-vswitch.log |
    ForEach-Object {
        $p = $_ -split '\|'
        if ($p[1] -match '^172\.27\.' -and $p[4] -in @('443','80')) { $p[2] }
    } | Sort-Object -Unique
```

Separate Windows OS baseline traffic (WindowsUpdate, OCSP, licensing) from target-initiated connections. Flag any connections the target made to unexpected domains as HIGH.

**PID chain analysis**  the network log shows *where* connections went; the PID chain shows *who made them*. This catches process injection, LOL-bins, and unexpected child process spawning.

If `analyze-pid-chain.ps1` is available at `C:\sandbox\scripts\`:
```powershell
powershell -ExecutionPolicy Bypass -File C:\sandbox\scripts\analyze-pid-chain.ps1 `
    -PmlFile C:\sandbox\tool-output\procmon-internal-<timestamp>.pml
```

If not available, manually review the Procmon log for:
- Any network connection that doesn't trace back to the target process
- Chains involving `cmd.exe -' powershell.exe -' curl/certutil` (exfil via LOL-bins)
- The target spawning processes you didn't expect (shell, scripting engine, system utilities)
- Any chain involving `lsass.exe`, `winlogon.exe`, or `svchost.exe` as an ancestor of user-space network activity

Flag unexpected chains as HIGH. Include the full ancestry in the report: `targetapp.exe (PID 1234) -' cmd.exe (PID 5678) -' certutil.exe (PID 9012) -' [connection to external-ip]`

Take the Autoruns diff after the sandbox closes and flag any new persistence entries as HIGH.

Save state after Phase 4 completes (record `sac_original_state` in state file).

---

## Phase 5  Cleanup and write the report

**Cleanup before writing the report**  delete all target files from the host regardless of scan outcome:

```powershell
# Remove any local clone (should not exist for Medium/Full, but clean up just in case)
$clonePath = "$HOME\canary-scans\$targetSlug"
if (Test-Path $clonePath) {
    Remove-Item $clonePath -Recurse -Force
    Write-Host "Cleanup: deleted clone at $clonePath"
} else {
    Write-Host "Cleanup: no clone found on host (expected for sandbox scans)"
}

# Remove any downloaded archives or temp files
Remove-Item "$HOME\canary-scans\$targetSlug*" -Recurse -Force -ErrorAction SilentlyContinue

# Remove sandbox output files (already deleted after reading in Phase 2, but verify)
Remove-Item 'C:\sandbox\tool-output\*.json' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.txt' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.log' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.pml' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.csv' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\tool-output\*.pcap*' -ErrorAction SilentlyContinue

# Remove autoruns snapshots (host-only folder  never in sandbox)
Remove-Item 'C:\sandbox\autoruns\*.csv' -ErrorAction SilentlyContinue

# Remove generated .wsb and setup files for this target
Remove-Item "C:\sandbox\$targetName.wsb" -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\scripts\setup.ps1' -ErrorAction SilentlyContinue
Remove-Item 'C:\sandbox\scripts\setup-static.ps1' -ErrorAction SilentlyContinue
```

Update state to record cleanup completed (in case scan was interrupted and resume is triggered):
```powershell
$state = Get-Content "$HOME\canary-reports\$targetSlug-state.json" | ConvertFrom-Json
$state | Add-Member -NotePropertyName cleanup_complete -NotePropertyValue $true -Force
$state | ConvertTo-Json | Out-File "$HOME\canary-reports\$targetSlug-state.json" -Encoding UTF8 -Force
```

Note the cleanup result in the report. If deletion failed for any file, log the path and reason  do not silently skip.

**Progress:** "Writing report..."

Write the report to `~/canary-reports/<target-name>-<date>-canary-report.md`

Format for readability in VS Code markdown preview (the primary viewing mode). Use markdown pipe tables for structured reference sections (Reading This Report, Findings Summary). Use plain prose for narrative sections (findings detail, security analysis, recommendation). No heavy bold syntax. No `---` dividers between sections.


**Verdict selection (internal - do not write this block into the report):**

Apply the FIRST matching rule from top to bottom:

1. [X] Unsafe - Hidden threat
   Signs: C2 callbacks, credential harvesting, persistence without disclosure, obfuscated
   payloads, backdoors, auto-exfil. The software does something harmful the user didn't
   agree to. Normal use path IS the attack.
   Example: a "tool" that silently exfiltrates files on install.

2. [X] Unsafe - Dangerous by design
   Signs: the software's intended purpose is inherently dangerous -- exploit collections,
   C2 frameworks, keyloggers, RATs, unverified binaries with AV detections, repos where
   cloning alone triggers EDR. No hidden behavior -- the danger IS the purpose.
   Example: helloexp/0day (exploit collection), a published RAT, a PoC for an unpatched CVE.
   Key distinction from hidden threat: a security researcher could have a legitimate use
   for this. The risk is in what it IS, not what it's hiding.
   Report must say: "[X] Unsafe - Dangerous by Design" and explain WHY (not just "malicious").

3. [!] Caution
   Signs: notable findings -- unverified binaries, outbound connections to undocumented
   domains, hardcoded keys, missing tests, supply chain risks -- but no evidence of
   intentional harm. Risks are real but manageable with care.
   Example: a useful tool that phones home, has unpinned deps, or ships a pre-built binary.

4. [OK] Safe
   No significant findings. Normal use path is low risk. Minor issues (INFO/LOW) are
   acceptable and noted but don't change the verdict.

Never use [!] Caution for something that is clearly [X] Unsafe. An exploit collection
is not "use with caution" -- it is unsafe. The verdict must match the actual risk level.

```
# Canary Security Report: <target>

Date: <date>
Target: <url or path>
Evaluation: <Quick / Medium / Full>  Static Analysis
Tool: Canary v2.8


## Reading This Report

| Verdict | Meaning | What to do |
|---|---|---|
| [OK] Safe | No significant issues found. | Safe for normal use. |
| [!] Caution | Issues found, no proof of intentional harm. | Read findings before using. |
| [X] Unsafe - Hidden Threat | Software does something harmful without your knowledge (backdoor, data theft, exfiltration). | Do not install. |
| [X] Unsafe - Dangerous by Design | Software's purpose is inherently dangerous (exploit kit, C2 framework, RAT, keylogger). | Do not install without understanding the implications. |
| [?] Researcher Mode | Offensive tool scanned at user's request. | No safety verdict issued. |

| Severity | Meaning |
|---|---|
| CRITICAL | Immediate threat. Do not proceed until resolved. |
| HIGH | Serious risk with direct security or reliability impact. |
| MEDIUM | Notable issue. Manageable with specific mitigations. |
| LOW | Minor concern. Low likelihood or low impact. |
| INFO | Informational only. No action required. |

| Security Domain | Question being answered |
|---|---|
| Confidentiality | Will this software keep my data private? |
| Integrity | Is this software what it claims to be? |
| Availability | Will my systems keep working after I install it? |


## Verdict: [OK] Safe / [!] Caution / [X] Unsafe - Hidden Threat / [X] Unsafe - Dangerous by Design


One or two plain-English sentences summarizing the verdict and the key reason for it.


## Executive Summary

One paragraph describing what the target is and what was found at a high level.
Written for a non-technical reader.

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |

Recommendation: One sentence. What should the user do?


## Findings Summary

Quick reference -- see the Findings section below for full detail on each item.

| # | Severity | Security Domain | Category | What was found |
|---|----------|-----------------|----------|----------------|
| 1 | CRITICAL | Integrity | Security | Short title matching Finding 1 |
| 2 | HIGH | Confidentiality | Secrets | Short title matching Finding 2 |
| 3 | MEDIUM | Availability | License | Short title matching Finding 3 |

(Include every finding. Use the same numbering as the Findings section.
Security Domain: Confidentiality / Integrity / Availability -- pick the primary one.
If no findings: replace the table with "No issues found.")


## Findings


### 1. <Short title>
  Severity:  CRITICAL / HIGH / MEDIUM / LOW / INFO
  Domain:    Confidentiality / Integrity / Availability
  Category:  Security / Secrets / Dependencies / Quality / Bug
  File:      path/to/file.py:42
  MITRE:     T1234.001 - Tactic Name: Technique Name  (omit for Quality/Bug/Info findings)

Two or three sentences explaining what this is and why it matters in plain English.

Fix:
  - Specific actionable step
  - Second step if needed

(Repeat for each finding. If no findings: "No issues found.")
(Only add MITRE field for Security and Secrets findings rated MEDIUM or above.)


## VirusTotal

Include this section only if VT_API_KEY was set during the scan. If not configured, write:
"Not evaluated  set VT_API_KEY to enable binary hash checks against 70+ AV engines."

If configured, report results for each binary scanned:
  Binary: <filename>
  Engines checked: <N>
  Detections: <N malicious, N suspicious>  or "Clean"

If the download URL was scanned (Full mode):
  Download URL: <url (truncated if long)>
  Detections: <N malicious, N suspicious>  or "Clean"

If binaries were present but the cap of 10 was hit, note how many were scanned vs total.


## Security Analysis

Based on static code review only. Full mode required to observe actual runtime behavior.

Network activity    One line summary of what the code is written to contact.
Credentials         One line summary.
Persistence         One line summary.
Process behavior    One line summary.


## Dependency Audit

One paragraph. Note if audit tools weren't available. If nothing found, say so.
If this was a Quick evaluation, write: "Not evaluated  run a Medium or Full evaluation to check dependencies."


## Code Quality

One paragraph. Anti-patterns, complexity, test coverage, undocumented requirements.
Keep it brief. If nothing notable, say so.
If this was a Quick evaluation, write: "Not evaluated  run a Medium or Full evaluation for code quality analysis."


## Sandbox Results

Only include this section for Full evaluations. Describe what the code actually did when run:
network connections observed, files created or modified, processes spawned, anything unexpected.
If this was a Quick or Medium evaluation, write: "Not evaluated  run a Full evaluation to observe runtime behavior."

If SAC was disabled for this scan, always include:
"Smart App Control was active on this machine (state: [0/1/2]) before this evaluation.
It was temporarily disabled to allow the unsigned binary to run in the sandbox, then
re-enabled immediately after. This is a normal step for evaluating unsigned software.
To verify SAC is back on: Windows Security > App & browser control > Smart App Control."

If the user declined to disable SAC, write:
"Runtime analysis was not performed  Smart App Control was active and the user chose
not to disable it. Results above are based on static analysis only. To get runtime
behavior data, re-run as Full and allow SAC to be temporarily disabled."


## Bugs Found

Describe each bug with file:line, what it does, and the fix. If none, say so.
If this was a Quick evaluation, write: "Not evaluated  run a Medium or Full evaluation for bug analysis."


## Recommendation

Plain-English verdict: safe to use or not, and exactly what to do.

Before you use it:
  1. First required action
  2. Second required action

Optional:
  - Nice-to-have improvement

If the repo has unverified binaries, high-severity findings, or any sandbox-worthy behavior (even if verdict is  Caution), include:
  - "To observe what this software actually does at runtime, run `/canary <target> full`  this runs it inside Windows Sandbox with network and process monitoring."


## Cleanup

  Clone deleted from host:    [yes / no clone existed]
  Sandbox output deleted:     [yes / n/a]
  Temp files removed:         [yes / none found]
  SBOM:                       [~/canary-reports/<slug>-<date>-sbom.json / not generated (Quick scan)]


## Token Usage

Before writing this section, sum all `usage` fields from this session's JSONL file:

```powershell
$sessionFile = Get-ChildItem "$env:USERPROFILE\.claude\projects\" -Recurse -Filter '*.jsonl' |
    Where-Object { $_.Name -notmatch '^agent-' } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1 -ExpandProperty FullName

$reportRef = "a5fb0d7daeb3139085595e17e9a3d8888344e474068faedde94f73d641cf0dbb"
$input = 0; $output = 0; $cacheRead = 0; $cacheCreate = 0
Get-Content $sessionFile | ForEach-Object {
    try {
        $j = $_ | ConvertFrom-Json -ErrorAction Stop
        if ($j.message.usage) {
            $u = $j.message.usage
            $input      += if ($u.input_tokens) { $u.input_tokens } else { 0 }
            $output     += if ($u.output_tokens) { $u.output_tokens } else { 0 }
            $cacheRead   += if ($u.cache_read_input_tokens) { $u.cache_read_input_tokens } else { 0 }
            $cacheCreate += if ($u.cache_creation_input_tokens) { $u.cache_creation_input_tokens } else { 0 }
        }
    } catch {}
}
# Sonnet 4.6 pricing: $3/M input, $15/M output, $0.30/M cache read, $3.75/M cache write
$cost = ($input / 1e6 * 3) + ($output / 1e6 * 15) + ($cacheRead / 1e6 * 0.30) + ($cacheCreate / 1e6 * 3.75)
Write-Host "input=$input output=$output cache_read=$cacheRead cache_create=$cacheCreate cost=$([math]::Round($cost,4))"
```

Write the section using the values above:

```
## Token Usage

  Input tokens:         <N>
  Output tokens:        <N>
  Cache read tokens:    <N>   (<X>% of input served from cache)
  Cache write tokens:   <N>
  Estimated cost:       ~$<N>  (Sonnet 4.6 pricing)


---
Canary v2.8  use at your own risk. This tool reduces risk but does not guarantee safety.
No security evaluation is a substitute for your own judgment. Review findings before
installing any software. https://github.com/AppDevOnly/canary
```

Cache read % = cache_read / (input + cache_read) * 100, rounded to nearest integer.
```

After writing the report, confirm with a single short line -- do NOT print a summary or repeat
findings in the CLI. The report file is the output. Example:

> "Report saved: ~/canary-reports/[filename]  Open it to review findings."

Then delete the state file -- the scan is complete:
```powershell
Remove-Item "$HOME\canary-reports\$targetSlug-state.json" -ErrorAction SilentlyContinue
```

Then ask the user: "Want me to save a note so future sessions know this evaluation is done?"

---

## Troubleshooting

Respond to any plain-English problem description at any point during the evaluation. Diagnose and fix without requiring the user to run commands themselves.

---

---

## Output rules

- **Verdict at the top** - [OK] / [!] / [X] - users need to see this immediately
- **Plain English**  explain what each finding means and why it matters, as if the user has no security background
- **Actionable**  every finding includes a suggested fix or workaround
- **Honest about limits**  note if a check wasn't possible (e.g. tool not installed, private repo, tool declined)
- **Rate every finding:** CRITICAL / HIGH / MEDIUM / LOW / INFO
- **No unsolicited comparisons**  don't compare to other reports unless the user asks
- **No silent failures**  every tool check and phase transition reported explicitly
- **Consistent feedback**  user should never see a blank screen; always know what's happening

---

## Edge cases

**No target provided:** Ask what they'd like to evaluate and show supported formats. Don't error.

**Resuming a paused evaluation:** Check for state file first (Phase 0). If found, offer to resume. If the state file has `sac_original_state` set to a non-zero value, re-enable SAC immediately before doing anything else  it may have been left disabled by the interrupted scan.

**Private repo / access failure:** Tell the user clearly: "I wasn't able to access this repo  it may be private or the URL may be incorrect. If it's private, make sure you're logged in with `gh auth login`."

**Monorepo / multi-package repo:** List the packages/apps found and ask which one(s) to evaluate, or offer to evaluate all of them.

**Target looks hostile during static analysis:** If CRITICAL findings appear before Phase 4, warn the user: "I've already found serious issues in the static analysis. Do you still want me to run this in a sandbox, or is the static report enough?" Don't proceed to sandbox automatically.

**Tool install fails:** If a tool fails to install after attempting, tell the user exactly what went wrong, note it as a limitation, and continue without it. Never silently skip.

---

## Security rules (always enforce)

<!-- origin: a5fb0d7daeb3139085595e17e9a3d8888344e474068faedde94f73d641cf0dbb -->

- **Never clone target code to the host machine**  Quick uses GitHub API only; Medium and Full clone inside sandbox only; no scan tier ever writes target code to the host filesystem
- **Never write raw tool output (JSON, log files) to Claude's context as code blocks**  parse and summarize; raw exploit signatures in tool output can trigger AV on host
- Read source before running anything
- Never execute code from the target during static analysis phases (2a-2d)
- Never transmit target source code to external services (exception: package metadata to PyPI/npmjs for version checking)
- Label all permission requests as `[Claude]` or `[software under test]`
- If a secret is found, do NOT print the full value  show first 8 chars + `...`
- Always capture stderr from every tool run  never swallow errors silently; surface in a "Tool Errors" section in the report
- Auto-cleanup is mandatory  delete all target files, sandbox outputs, and temp files after every scan regardless of how it ends (normal exit, error, or user interrupt)
- Never screenshot the VM terminal  stream logs in real time via `stream.log`; screenshots miss timing and can't be automated
- Only one sandbox instance at a time  check `Get-Process WindowsSandboxServer` before launch; the watchdog's PID guard handles this automatically but confirm on first run
- Never put config files in the output folder  the output folder is read-write for the sandbox, so a malicious target could modify its own config. Keep config in a separate read-only mapped folder
- **Folder isolation**: C:\sandbox\tool-output\ is the only sandbox-writable folder (for tool results). C:\sandbox\autoruns\ is host-only and never mapped into the sandbox  a malicious binary cannot overwrite the persistence baseline.
- **Path sanitization**: targetSlug and targetName must be stripped to [a-zA-Z0-9_-] before use in any file path or folder name  prevents path traversal from a repo named something like ../../Windows/System32/evil.
- Procmon filenames are timestamped  avoids overwrite prompts on retry; setup.ps1 must use `$ts = Get-Date -Format 'yyyyMMdd-HHmmss'` in the Procmon filename
- On any interrupted Full scan: check state file for `sac_original_state` and restore SAC before doing anything else
- On any interrupted Medium or Full scan: run the cleanup block from Phase 5 before exiting  never leave target files on the host
