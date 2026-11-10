# LLM triage: logging, privacy and evaluation protocol

Status: protocol defined and logging/privacy code implemented in cycle 2 (`vulnreview/llm_triage.py`).
The first real model runs are scheduled for cycle 3 (Report #3).

## What the model sees and returns

Input: one merged finding (tools, rule IDs, candidate CWEs, tool messages) and +/-8 source lines around
the flagged line. Output: one JSON object validated against `VERDICT_SCHEMA`:
`verdict` (true_positive / false_positive / uncertain), `confidence`, `cwe`, `explanation`,
`fix {description, patched_lines}`. Invalid output is logged and retried once, never repaired.

## Logging (one JSONL line per call, `llm_logs/`)

Timestamp, run id, attempt, finding, backend, endpoint, model name, **model digest** (Ollama), parameters
(**temperature 0, seed 42** by default), full system and user prompt, prompt SHA-256, raw response,
parsed verdict, validity, error, latency.

## Privacy

The default endpoint is a local Ollama server. A non-local endpoint is refused unless `--allow-hosted`
is given **and** every finding comes from `dev/`, `holdout/` or `securityeval/` (synthetic or public
code). Hosted models are used only for comparison runs.

## How the LLM layer will be evaluated

| Aspect | Measure | Target (objective) |
|---|---|---|
| Triage | Treat each verdict as a classifier over merged records, ground truth from the line-level labels: precision, recall, F1 of the records kept as `true_positive`; reduction of false-positive records vs. the SAST union; recall loss. `uncertain` counts as kept. | >= 50 % fewer false positives, <= 5 pp recall loss (O3) |
| Stability | Re-run with the same seed: share of identical verdicts; re-run with renamed identifiers (semantic-preserving): share of unchanged verdicts. | reported |
| CWE | exact / related / incorrect agreement of the model's `cwe` with the label (`cwe.agreement`). | reported vs. SAST baseline |
| Explanation | Two raters score each explanation 0-2 on: correct CWE named; source and sink lines named and present in the code; no invented API or line. Inter-rater kappa reported. | mean >= 1.5 |
| Patch | Apply `patched_lines`; check (1) the file still compiles (`py_compile`), (2) the original finding disappears on re-scan with all engines, (3) no new finding appears, (4) a reviewer confirms behaviour is preserved. | >= 80 % pass (1)-(3) (O4) |

Development (prompt wording) uses the dev split only; reported results use the holdout and SecurityEval splits.
