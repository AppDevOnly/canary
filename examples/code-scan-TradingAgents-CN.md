# Canary Security Report: hsliuping/TradingAgents-CN -- [!] Caution

| Field | Value |
|-------|-------|
| Date | 2026-03-25 |
| Target | https://github.com/hsliuping/TradingAgents-CN |
| Evaluation | Quick -- Static Analysis |
| Tool | Canary v2.8 |


## Reading This Report

| Report Verdict | Meaning | What to do |
|---|---|---|
| [OK] Safe | No significant issues found. | Safe for normal use. |
| [!] Caution | Issues found, no proof of intentional harm. | Read findings before using. |
| [X] Unsafe - Hidden Threat | Software does something harmful without your knowledge (backdoor, data theft, exfiltration). | Do not install. |
| [X] Unsafe - Dangerous by Design | Software's purpose is inherently dangerous (exploit kit, C2 framework, RAT, keylogger). | Do not install without understanding the implications. |
| [?] Researcher Mode | Offensive tool scanned at user's request. | No safety verdict issued. |

| Findings Severity | Meaning |
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


## Verdict: [!] Caution

The code itself is not malicious, but the default Docker deployment ships with hardcoded database passwords and a well-known weak Application Programming Interface (API) secret in the public repository -- meaning a default install is insecure out of the box and anyone who clones the repo already knows your credentials.


## Executive Summary

TradingAgents-CN is a Chinese-language enhancement of the TradingAgents multi-agent Large Language Model (LLM) framework for analyzing Chinese A-share stocks using models including DeepSeek, Qwen, and Google Gemini. It is a substantial full-stack application (2,278 files) with a FastAPI backend, Vue 3 frontend, MongoDB, Redis, and an extensive set of financial data integrations. The code is not malicious. The concerns are deployment security and licensing: docker-compose.yml commits five default database passwords in plaintext, the app defaults to a well-known JWT secret, CORS and host policies default to open, and the repository carries a split license -- Apache 2.0 for the upstream framework layer, but a proprietary license covering the app/ and frontend/ directories that restricts commercial use and modification.

This is a static analysis only -- runtime behavior was not observed.

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 2 |
| Medium | 4 |
| Low | 0 |
| Info | 1 |

Recommendation: Safe to evaluate and run locally for personal research. Do not deploy as a service without addressing both HIGH findings first, and read the proprietary license before incorporating the app/ or frontend/ code into any commercial project.


## Findings Summary

| # | Severity | Domain | Category | Artifacts | What was found |
|---|----------|--------|----------|-----------|----------------|
| 1 | HIGH | Confidentiality | Secrets | docker-compose.yml | Five hardcoded database passwords committed to repo |
| 2 | HIGH | Confidentiality | Security | app/core/config.py:72 | Weak JWT default secret -- auth tokens forgeable on default deploy |
| 3 | MEDIUM | Availability | Security | app/core/config.py:24-26 | Wildcard CORS and DEBUG mode enabled by default |
| 4 | MEDIUM | Integrity | Security | requirements.txt:14 | Anti-scraping TLS fingerprint bypass library included as dependency |
| 5 | MEDIUM | Integrity | Dependencies | pyproject.toml, requirements.txt | Unpinned LangChain ecosystem dependencies |
| 6 | MEDIUM | Integrity | License | LICENSE, app/LICENSE | Proprietary license restricts app/ and frontend/ use |
| 7 | INFO | Availability | Quality | -- | Test quality not assessed at Quick tier |


## Findings


### 1. Five hardcoded database passwords committed to repo

| Field | Value |
|-------|-------|
| Severity | HIGH |
| Domain | Confidentiality |
| Category | Secrets |
| File | docker-compose.yml |
| MITRE | T1552.001 - Credential Access: Unsecured Credentials: Credentials In Files |

Anyone who clones this repo and runs `docker-compose up` gets a MongoDB instance, Redis cache, and MongoExpress admin panel secured only by `tradingagents123` -- a password now public in a repository with over 21,000 stars. The password appears in five locations in docker-compose.yml: `MONGO_INITDB_ROOT_PASSWORD`, `ME_CONFIG_MONGODB_ADMINPASSWORD`, `ME_CONFIG_BASICAUTH_PASSWORD`, `TRADINGAGENTS_REDIS_URL`, and the MongoDB connection string for the app service. The MongoExpress admin panel is particularly sensitive -- it exposes a full database management UI with no additional protection beyond this shared password. Because these credentials are in docker-compose.yml rather than an .env.example file, they are live regardless of whether the user creates a .env file.

**Fix:**
- Remove all hardcoded password values from docker-compose.yml; replace with `${MONGODB_PASSWORD}` and `${REDIS_PASSWORD}` environment variable references
- Generate strong random passwords before first deploy: `python -c "import secrets; print(secrets.token_urlsafe(24))"`
- If you have already deployed with the default password, rotate all five credential locations now

**Countermeasure:** Store credentials in a secrets manager (HashiCorp Vault, Docker Secrets, or a `.env` file excluded from version control) rather than in any committed file. (D3FEND: D3-STOG Secrets Management)


### 2. Weak default JWT secret -- authentication tokens are forgeable

| Field | Value |
|-------|-------|
| Severity | HIGH |
| Domain | Confidentiality |
| Category | Security |
| File | app/core/config.py:72 |
| MITRE | T1552.001 - Credential Access: Unsecured Credentials: Credentials In Files |

The application defaults `JWT_SECRET = "change-me-in-production"` if no environment variable is set. JSON Web Tokens (JWTs) are signed with this secret, so anyone who knows the value -- and it is now public in a repository with 21,000 stars -- can forge valid authentication tokens for any user account, including admin accounts. Any deployment that has not explicitly set `JWT_SECRET` in its environment is fully compromised before the first real user logs in.

**Fix:**
- Set `JWT_SECRET` to a cryptographically random value before deploying: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
- Add a startup check that refuses to launch if `JWT_SECRET` still matches the default value or is shorter than 32 characters

**Countermeasure:** Enforce secrets validation at startup -- reject well-known placeholder values and require minimum entropy before the application accepts requests. (D3FEND: D3-STOG Secrets Management)


### 3. Wildcard CORS and DEBUG mode enabled by default

| Field | Value |
|-------|-------|
| Severity | MEDIUM |
| Domain | Availability |
| Category | Security |
| File | app/core/config.py:24-26 |

`ALLOWED_ORIGINS: ["*"]` and `ALLOWED_HOSTS: ["*"]` mean the API will accept cross-origin requests from any domain, and `DEBUG: True` by default exposes stack traces and detailed error output. Combined, any deployment that does not override these settings is wider open than the developers likely intend. Cross-Origin Resource Sharing (CORS) wildcard in combination with JWT authentication creates a meaningful attack surface for cross-site request forgery on a deployed service.

**Fix:**
- Set `ALLOWED_ORIGINS` to the specific domains that should access your API
- Set `DEBUG=false` in your production .env file
- Set `ALLOWED_HOSTS` to your actual hostname


### 4. Anti-scraping TLS fingerprint bypass library

| Field | Value |
|-------|-------|
| Severity | MEDIUM |
| Domain | Integrity |
| Category | Security |
| File | requirements.txt:14 |

The dependency `curl-cffi>=0.6.0` is documented in a Chinese-language code comment as a tool to "simulate real browser TLS fingerprints to bypass anti-scraping detection" (`模拟真实浏览器TLS指纹，绕过反爬虫检测`). This library impersonates browser TLS handshakes to evade bot-detection systems. This is the intended, documented use -- not hidden behavior -- but it may violate the Terms of Service (ToS) of the data providers whose protections it is designed to circumvent. The config explicitly lists eastmoney.com in a NO_PROXY configuration, suggesting the scraping target is known and intentional.

**Fix:**
- Verify you have permission to scrape each data source this tool accesses
- Review whether eastmoney.com data use complies with their Terms of Service before relying on it for any production or commercial use


### 5. Unpinned LangChain ecosystem dependencies

| Field | Value |
|-------|-------|
| Severity | MEDIUM |
| Domain | Integrity |
| Category | Dependencies |
| File | pyproject.toml, requirements.txt |

The vast majority of dependencies use `>=` constraints with no upper bound -- for example `langchain-openai>=0.3.23`, `langgraph>=0.4.8`, `openai>=1.0.0,<2.0.0`. This means a supply chain compromise of any of these packages would automatically reach all users on their next install or `pip upgrade`. The LangChain ecosystem in particular is a meaningful supply chain target given its widespread adoption, and has a documented history of breaking changes between minor versions.

Severity is MEDIUM at minimum -- automated Common Vulnerabilities and Exposures (CVE) audit (pip-audit, npm audit) requires Medium or Full mode to determine whether any currently unpinned dependency has a known vulnerability.

**Fix:**
- Pin major dependencies to known-good versions in production: `langchain-openai==0.3.23`
- Use pip-audit or Dependabot to monitor for CVEs in pinned versions

**Countermeasure:** Integrate a Software Composition Analysis (SCA) tool (pip-audit, Dependabot, Snyk) into your CI pipeline to catch vulnerable dependency versions before they ship. (D3FEND: D3-SCF Software Composition Analysis)


### 6. Proprietary license restricts app/ and frontend/ use

| Field | Value |
|-------|-------|
| Severity | MEDIUM |
| Domain | Integrity |
| Category | License |
| File | LICENSE, app/LICENSE |

The repository carries a split license. The root LICENSE file grants Apache 2.0 for the upstream TradingAgents framework layer. A separate `app/LICENSE` file (covering the app/ and frontend/ directories -- the majority of novel code in this repo) carries a proprietary license that explicitly prohibits commercial use without written permission and restricts modification and redistribution. Anyone who forks this project, uses it in a commercial context, or incorporates the app/ or frontend/ code into another project without contacting the author is in violation of that license. The README does not prominently disclose this restriction.

**Fix:**
- If you are evaluating this for personal, non-commercial research use: no action required
- If you plan to use app/ or frontend/ code commercially or redistribute a modified version: contact the author before proceeding
- If you are building on top of this for a product: legal review is strongly recommended before the project advances


### 7. Test quality not assessed at Quick tier

| Field | Value |
|-------|-------|
| Severity | INFO |
| Domain | Availability |
| Category | Quality |
| File | -- |

507 test files exist in the repository, so test infrastructure is present. Test quality, coverage percentage, and whether the tests actually run against real dependencies could not be assessed at Quick tier.


## Security Analysis

| Area | What was observed |
|------|-------------------|
| Network activity | Contacts OpenAI, Google AI, DeepSeek, AliCloud DashScope APIs; eastmoney.com and Tushare/Baostock/AKShare for Chinese stock data. All documented and expected for this tool's stated purpose. curl-cffi is used to bypass TLS fingerprinting on some data sources. |
| Credentials | API keys read from environment variables (good practice). Default database passwords and JWT secret hardcoded in shipped files (bad). |
| Persistence | None detected. No writes to startup locations, cron, or registry. |
| Process behavior | No subprocess calls with shell=True observed. Standard FastAPI/Python process model. No obfuscated payloads. |


## Network Indicators

_(Include when deploying this software or building network-level defenses. All destinations below are documented in the codebase and consistent with the tool's stated purpose. None are indicators of malicious behavior -- they are included here for network policy and firewall rule purposes.)_

```
# AI provider APIs (expected -- core functionality)
api.openai.com
generativelanguage.googleapis.com
api.deepseek.com
dashscope.aliyuncs.com

# Chinese financial data sources
data.eastmoney.com
api.tushare.pro
api.baostock.com
akshare.akfamily.com (AKShare)

# Ports
443 (HTTPS -- all above endpoints)
```

Note: eastmoney.com is accessed via curl-cffi TLS fingerprint bypass (see Finding 4). The other endpoints use standard HTTPS. No hardcoded IP addresses or non-standard ports were observed.


## Dependency Audit

Automated dependency audit requires Medium or Full. Manual NVD review of direct dependencies found: no known critical CVEs in the dependency set as of 2026-03-25. The PyJWT, bcrypt, and cryptography packages are current. The primary risk is unpinned transitive dependencies in the LangChain ecosystem rather than specific known CVEs in pinned versions.

Note: unpinned dependencies were found (Finding 5). The MEDIUM severity on that finding is a lower bound -- any of those packages may have known CVEs that only a full pip-audit/npm-audit run (Medium or Full mode) can surface. Do not treat the absence of CVE findings here as a clean bill of health.


## Code Quality

Not evaluated -- run a Medium or Full evaluation for code quality analysis.


## Sandbox Results

Not evaluated -- run a Full evaluation to observe runtime behavior.


## Bugs Found

Not evaluated -- automated bug analysis runs at Medium or Full tier.


## Recommendation

Safe to install and run locally for personal, non-commercial research. Do not deploy as a service without addressing both HIGH findings first.

Before you expose this to any network:
1. Replace all five hardcoded passwords in docker-compose.yml with .env variable references and generate strong random values
2. Set `JWT_SECRET` to a cryptographically random value (32+ characters) in your .env file
3. Set `DEBUG=false`, `ALLOWED_ORIGINS` to your actual domain, and `ALLOWED_HOSTS` to your hostname

Before any commercial or redistributed use:
- Read app/LICENSE carefully and contact the author if you need commercial rights

For local personal use only:
- The credential defaults are inconvenient but not immediately dangerous if the ports (8000, 27017, 6379, 8081) are not exposed outside your machine

To observe what this software actually does at runtime, run `/canary https://github.com/hsliuping/TradingAgents-CN full` -- this runs it inside Windows Sandbox with network and process monitoring.

**Pivot Recommendations:**
- Run `/canary pip:curl-cffi quick` to evaluate the anti-scraping bypass library directly before relying on it
- Check git history for when the proprietary app/LICENSE was added -- the upstream TradingAgents project is Apache 2.0, so this restriction was added by the fork author
- Search VirusTotal passive DNS for eastmoney.com to assess the scraping target's infrastructure if ToS compliance matters for your use case
- If deploying: add api.tushare.pro and dashscope.aliyuncs.com to your egress allowlist and block all other unexpected outbound connections at the network layer


## MITRE ATT&CK

Techniques mapped from findings in this evaluation.
Full descriptions: https://attack.mitre.org

MITRE ATT&CK(R) is a registered trademark of The MITRE Corporation and is used in accordance with the MITRE ATT&CK Terms of Use. Technique mappings in this report reference the MITRE ATT&CK knowledge base, published under CC BY 4.0.
https://attack.mitre.org/resources/terms-of-use/

| Tactic | ID | Technique | Observed |
|--------|----|-----------|----------|
| TA0006 Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | Five plaintext database passwords and a weak JWT secret hardcoded in docker-compose.yml and config.py |
| TA0001 Initial Access | T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Unpinned >= constraints across LangChain ecosystem; a compromised package version would reach all users automatically |


## VirusTotal

Not evaluated -- no binaries found in this repository. Set `VT_API_KEY` to enable URL and binary checks if binaries are added in future releases.


## Cleanup

| Item | Status |
|------|--------|
| Target files / clone | No clone created (Application Programming Interface-only scan) |
| Sandbox output files | n/a (Quick scan) |
| Scan temp dir | n/a (Quick scan) |
| Software Bill of Materials (SBOM) | Not generated (Quick scan) |


## Token Usage

| Metric | Value |
|--------|-------|
| Input tokens | 29 |
| Output tokens | 6,547 |
| Cache read tokens | 4,388,727 (100% of input served from cache) |
| Cache write tokens | 27,233 |
| Estimated cost | ~$1.52 (Sonnet 4.6 pricing) |
| Repo / codebase size | Large (2,278 files) |

---
Canary v2.8 -- use at your own risk. This tool reduces risk but does not guarantee safety.
No security evaluation is a substitute for your own judgment. Review findings before
installing any software. https://github.com/AppDevOnly/canary

This report may reference the MITRE ATT&CK(R) knowledge base. MITRE ATT&CK(R) is a
registered trademark of The MITRE Corporation, used under CC BY 4.0.
https://attack.mitre.org
