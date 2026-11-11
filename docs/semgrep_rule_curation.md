# Semgrep rule curation

## Procedure (`scripts/curate_semgrep_rules.py`)

Input: the semgrep-rules repository pinned at commit `16b9e6d`, folder `python/` (337 YAML files, 378 rules).

1. Keep a rule only if `metadata.category == "security"`, `python` is among its languages and it has
   `metadata.cwe`.
2. Rules whose ID also occurs in another file are kept and renamed `<id>__<folder-path>`; the script
   asserts that all IDs are unique.
3. All kept rules are written to one config (`rules/semgrep-python-security.yaml`, not committed because
   of the Semgrep Rules License) and listed in `rules/semgrep-python-security.manifest.csv` (committed).

| Step | Rules |
|---|---|
| Total in `python/` | 378 |
| Removed: category is not `security` | 109 |
| Removed: language is not Python | 9 |
| Removed: no CWE | 0 |
| Renamed duplicate IDs | 22 |
| **Kept** | **260** |

## Does curation change recall or CWE coverage?

Run `evidence/20261110T235920Z` (repository commit `35f2813`), Semgrep 1.182.1, 5 timed repetitions:

| Split | Recall curated / full | CWE exact / related / incorrect, curated and full | Mean wall time curated / full |
|---|---|---|---|
| dev (12 vulnerable) | 0.750 / 0.750 | 8 / 1 / 0 (identical) | 4.84 s / 20.92 s |
| holdout (17 vulnerable) | 0.529 / 0.529 | 6 / 3 / 0 (identical) | 4.76 s / 21.01 s |
| SecurityEval (121 vulnerable) | 0.397 / 0.397 | 25 / 7 / 16 (identical) | 5.40 s / 22.37 s |

Curation changed neither recall nor CWE agreement on any split and cut the wall time by 77 %.
The full set produced 36 extra findings without a CWE, reviewed in `docs/non_cwe_findings.md`.

## Defect found by this comparison

The first comparison (`evidence/20261110T234538Z`) showed the curated set missing two cases
(dev `v05_weak_hash`, SecurityEval `CWE-327_codeql_3`). The cause was the renaming step, which then
used only the parent folder name: three pairs of different rules received the same new ID
(`insecure-hash-algorithm-md5__security`, `insecure-hash-algorithm-sha1__security`,
`tainted-sql-string__injection`), and Semgrep kept only one rule of each pair. The renaming now uses
the full folder path, the script checks uniqueness, and `tests/test_core.py` checks the manifest.

## Observation: upstream CWE metadata is not always right

Two upstream SQL-injection rules carry unrelated CWE metadata: `flask/security/injection/tainted-sql-string`
is tagged CWE-704 (type conversion) and `django/security/injection/tainted-sql-string` CWE-915. Because
the merge only joins related CWEs, their findings stay separate from the CWE-89 findings on the same
line. This is direct evidence that tool-reported CWEs need normalisation; a correction table is planned
for cycle 3.
