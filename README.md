# AI-Powered Vulnerability Detection and Secure Code Review System

Graduation project, Software Engineering, Maltepe University (SE 401, 2026-2027).
Author: Hakan Ege Sarıçayır. Supervisor: Prof. Dr. Asaf Varol.

A hybrid secure-code-review pipeline: deterministic SAST engines (Bandit, Semgrep, CodeQL) find
candidate weaknesses; their findings are normalised to CWE, merged and exported as SARIF 2.1.0; an LLM
layer (in progress) triages, explains and proposes fixes for those findings only.

## Layout

| Path | Content |
|---|---|
| `vulnreview/` | Pipeline v0.2: adapters, CWE logic, merge, evaluation, SARIF, runner, LLM triage prototype |
| `prototype/scan_pipeline.py` | Cycle-1 baseline used in Report #1 (commit `32b5c47`) |
| `bench/dev/` | Development set (18 cases, line-level labels) |
| `bench/holdout/` | Held-out set (26 cases), frozen in commit `3fefab1` before any scan |
| `datasets/securityeval/` | External set: labels committed, cases fetched by `scripts/fetch_securityeval.py` |
| `rules/` | Manifest of the curated Semgrep rules (`scripts/curate_semgrep_rules.py`) |
| `evidence/<run>/` | Raw outputs, command log, environment, results, SARIF, SHA256SUMS of each run |
| `review/` | Anonymised kit for the independent label review |
| `docs/` | Evaluation protocol, rule curation, non-CWE findings, LLM protocol |
| `tests/` | Unit tests (`python -m pytest`) |

## Reproduce the cycle-2 results

```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-lock.txt
git clone https://github.com/semgrep/semgrep-rules.git && git -C semgrep-rules checkout 16b9e6d
python scripts/curate_semgrep_rules.py semgrep-rules/python
python scripts/fetch_securityeval.py
# CodeQL CLI bundle 2.27.4 from https://github.com/github/codeql-action/releases
python -m vulnreview.run --splits dev holdout securityeval --repeat 5 \
    --semgrep-rules rules/semgrep-python-security.yaml \
    --semgrep-full semgrep-rules/python --codeql <path-to>/codeql
python -m pytest
```

CodeQL is used under the "academic research" terms of the GitHub CodeQL licence.
Semgrep rule texts are not redistributed (Semgrep Rules License); only their IDs are listed.
