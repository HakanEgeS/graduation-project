# Treatment of findings without a CWE

## Policy (cycle 2)

1. Findings whose rule carries no CWE are **retained**, not deleted: every evidence run writes them to
   `results/unmapped-<split>-<engine>.json` next to the scored findings.
2. They are **excluded from the metrics**, because they cannot be compared with a CWE label.
3. They are **reviewed by hand** each cycle. A rule whose findings are judged security-relevant is
   added to a manual CWE mapping table (planned for cycle 3) so its findings are scored in later runs.

Bandit and CodeQL attach a CWE to every finding. The curated Semgrep set contains only rules with a CWE,
so in practice unmapped findings come from the **full** Semgrep rule set, which is run for comparison.

## Review of run 20261110T234538Z (full Semgrep rule set)

| Split | Unmapped findings | Rules (count) |
|---|---|---|
| dev | 3 | use-raise-for-status (3) |
| holdout | 4 | unspecified-open-encoding (2), use-raise-for-status (1), tempfile-insecure (1) |
| securityeval | 29 | pass-body-fn (10), unspecified-open-encoding (7), use-raise-for-status (3), use-timeout (3), tempfile-insecure (2), unchecked-subprocess-call (1), hardcoded-tmp-path (1), open-never-closed (1), arbitrary-sleep (1) |

**Result.** 33 of the 36 findings are code-quality warnings with no security consequence in the
flagged code. The 3 findings of `tempfile-insecure` are **genuine security findings**: they flag
`tempfile.mktemp()` in `holdout/vuln/h05_mktemp.py` (CWE-377), `securityeval/CWE-377/codeql_1.py` and
`securityeval/CWE-379/sonar_1.py`. Excluding them did not lower the merged recall, because Bandit and
CodeQL detected all three cases, but Semgrep's own recall is understated by them.

**Action.** Map `tempfile-insecure` to CWE-377 in a manual mapping table and add it to the curated
set in cycle 3; keep reviewing unmapped findings in every run.
