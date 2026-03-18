# Canary Report: AutoResearchClaw v0.5.0 — 2026-03-18

## Verdict
⚠️ **Caution** — Safe to install from a security standpoint, but degrades significantly outside its intended ML/empirical research domain and requires several undocumented dependencies.

---

## Findings

| # | Severity | Category | Finding | Location |
|---|---|---|---|---|
| 1 | CRITICAL | Bug | `.format()` called on LLM-generated Python code containing dict literal braces — `KeyError` on every typical run | `code_agent.py:988` |
| 2 | HIGH | Quality | Two ML model classes (`InventoryOptimizationModel`, `AnomalyDetector`) have identical method signatures and bodies — likely copy-paste, no algorithmic difference | `models.py` |
| 3 | HIGH | Quality | `lm_head` modified during model loading instead of training loop — produces incorrect results on multi-dataset runs | `models.py` |
| 4 | HIGH | Fitness | Pipeline designed for empirical ML research; produces nonsensical output on business/economics/non-empirical topics | Architecture |
| 5 | MEDIUM | Quality | Import inside `try` block obscures dependencies and may hide silent failures | `setup.py` |
| 6 | MEDIUM | Bug | FigureAgent CodeGen fails every run — expects dict, receives str in response handler | `executor.py` |
| 7 | MEDIUM | Bug | Stage 9 YAML parse fails every run — LLM wraps response in markdown fence that parser doesn't strip | Stage 9 |
| 8 | MEDIUM | Dependency | Semantic Scholar API key undocumented — free tier rate-limited immediately; pipeline silently falls back to arXiv-only | README gap |
| 9 | MEDIUM | Dependency | Gemini API key undocumented — figure generation (`GEMINI_API_KEY`) silently skipped | README gap |
| 10 | MEDIUM | Dependency | Docker undocumented — stage 14 degrades from isolated execution to bare subprocess without warning | README gap |
| 11 | MEDIUM | Dependency | pdflatex/MiKTeX undocumented — 3 stages silently skipped without LaTeX | README gap |
| 12 | LOW | Bug | S2 circuit breaker trips on first contact without API key; cooldowns compound (120s → 240s) | Stage 4 |
| 13 | LOW | Quality | Config class has 0 non-dunder methods — empty shell | `config.py` |
| 14 | LOW | Quality | Hardcoded path `/workspace/data/hf` instead of `HF_CACHE` environment variable | `setup.py` |
| 15 | INFO | Security | Quality gate (score 2.0/3.0, threshold 3.0) is advisory only — pipeline continues via HITL override | Stage 20 |

---

## Security Analysis

**Verdict: Clean.** No unexpected outbound connections, no persistence mechanisms, no credential exfiltration.

### Network connections observed (Windows Sandbox, tshark)

| Destination | Purpose | Expected? |
|---|---|---|
| openrouter.ai | LLM inference | Yes (configured) |
| api.semanticscholar.org | Literature search | Yes |
| export.arxiv.org | Literature search | Yes |
| api.openalex.org | Literature search | Yes (undocumented but benign) |
| pypi.org, files.pythonhosted.org | pip install | Yes (setup only) |

### Process behavior

- All child processes spawn directly from `python.exe` — no `cmd.exe`, `powershell.exe`, or `certutil.exe` in chain
- No injection or living-off-the-land patterns
- No writes to system directories, registry, or startup locations
- No persistence (no scheduled tasks, no registry Run keys, no startup folder)
- Autoruns baseline: no changes pre/post install

### Credential handling

- `OPENROUTER_API_KEY` injected via environment variable at runtime ✅
- No hardcoded secrets found in source ✅

---

## Dependency Audit

No known CVEs identified in direct dependencies.

License: MIT — no compliance concerns.

**Undocumented runtime dependencies:**

| Dependency | Purpose | Impact if missing |
|---|---|---|
| Semantic Scholar API key | Literature search | Rate-limited immediately; arXiv-only fallback |
| `GEMINI_API_KEY` | Figure generation | Stage silently skipped |
| Docker | Stage 14 sandboxed code execution | Security downgrade to bare subprocess |
| pdflatex / MiKTeX | PDF compilation | 3 stages skipped; .tex output only |
| matplotlib | Chart generation | Skipped silently |

None of these are mentioned in the README.

---

## Code Quality

**Domain mismatch (HIGH):** AutoResearchClaw is designed for empirical ML research. On non-empirical topics (business, economics, policy), it:
- Generates ML experiment code (Llama-2, LoRA, Office-31 dataset) for business topics
- Stage 9 cannot produce valid experiment YAML — falls back to a generic template every run
- Stage 13 aborts after 3 iterations with no metrics — no meaningful metrics exist for a business domain
- Quality gate scores below threshold but pipeline continues via HITL override

The tool is not suitable for non-empirical research topics in its current form.

**Fallback behavior:**

| Scenario | Behavior | Rating |
|---|---|---|
| S2 rate limited | Circuit breaker + arXiv fallback | Graceful |
| Stage 9 YAML parse fails | Topic-derived fallback plan | Silent degradation |
| Stage 10 code repair crash | Hard failure, pipeline aborts | Hard failure (patchable) |
| matplotlib missing | Skip chart generation | Acceptable |
| pdflatex missing | Skip PDF, continue with .tex | Graceful |
| Docker missing | Bare subprocess; no user warning | Security downgrade |
| Quality gate fails | HITL override continues anyway | Gate is advisory only |

---

## Bugs Found

### Bug 1 — Stage 10 CODE_GENERATION crash (CRITICAL)

**Location:** `code_agent.py:988` — `_targeted_file_repair()`

**Description:** `.format(target_file=target_file)` called on a string containing LLM-generated Python code with dict literal curly braces. Causes `KeyError` on every run where generated code contains dicts — which is most runs.

```
KeyError: "\n  19 |     'initial_simplex_size'"
```

**Fix:** Convert plain string segments to f-strings, remove `.format()` call.

**Patch available:** `patch-code-agent.py` — converts the affected string and removes the `.format()` call.

---

### Bug 2 — Stage 14 FigureAgent CodeGen failure (MEDIUM)

**Location:** `executor.py` — FigureAgent path

**Description:** `"CodeGen failed: 'str' object has no attribute 'get'"` — response handler expects dict, receives str. Occurs every run.

**Fix:** Add type check before calling `.get()` on response; handle str case by parsing as JSON or returning error.

---

### Bug 3 — Stage 9 YAML parse failure (MEDIUM)

**Location:** Stage 9 EXPERIMENT_DESIGN

**Description:** LLM wraps YAML response in a markdown code fence (` ```yaml `). Parser doesn't strip the fence — falls back to generic plan.

**Fix:** Strip markdown code fences before parsing: `re.sub(r'^```\w*\n|```$', '', response, flags=re.MULTILINE)`.

---

## Output Quality (Best Run)

- Abstract: 122 words (target 150–250) — undershoots every run
- Introduction: 476 words (target 800–1,000) — undershoots every run
- Quality gate: 2.0/3.0 (threshold 3.0) — continued via HITL override
- 4 citation keys in paper not found in `references.bib`
- 403/608 citation verification checks timed out — marked SKIPPED
- LaTeX compilation: skipped (pdflatex not installed)
- Charts: none generated (FigureAgent bug + Gemini key missing)

---

## Recommendation

**Safe to install** from a security perspective. Use with these caveats:

1. **Apply the Stage 10 patch** before running — pipeline will crash without it on most topics
2. **Use only for empirical ML/CS research topics** — business, economics, and non-empirical topics produce low-quality output
3. **Add a Semantic Scholar API key** — free tier; dramatically improves literature coverage
4. **Install pdflatex** (MiKTeX) and **add a Gemini API key** to unlock 3 skipped stages
5. **Enable Docker** for stage 14 sandboxed code execution

---

*Report generated by [Canary](https://github.com/AppDevOnly/canary) — AutoResearchClaw v0.5.0 — 2026-03-18*
