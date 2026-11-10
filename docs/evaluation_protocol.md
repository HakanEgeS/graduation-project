# Evaluation protocol (cycle 2, vulnreview 0.2.0)

## Data sets and their roles

| Split | Location | Cases | Labels | Role |
|---|---|---|---|---|
| dev | `bench/dev` | 18 (12 vulnerable, 6 safe) | own, sink line + CWE | Development. Used to build and tune the pipeline (merge key, CWE filter, rule curation). Results on it are optimistic by construction. |
| holdout | `bench/holdout` | 26 (17 vulnerable, 9 safe look-alikes) | own, sink line + CWE | Held-out. Written and committed (commit `3fefab1`) before any engine was run on it; never used for tuning. |
| securityeval | `datasets/securityeval` | 121 (all vulnerable, 69 CWEs) | dataset authors (Siddiq & Santos, 2022), CWE per file | External, independently labelled. File level only (no sink lines, no safe files, so precision is undefined). |

Own labels are partly checked by an independent reviewer (`review/`, 15 anonymised cases, seed 2026);
agreement is reported as raw agreement and Cohen's kappa.

## Unit of evaluation

* **Line level (dev, holdout).** A vulnerable case is *detected* when a merged record lies on its
  labelled sink line. A record on a sink line is a *true positive*; a record on another line of a
  vulnerable file is *off-target*; a record in a safe file is a *safe-file alarm*.
  Record precision = true-positive records / all records.
* **File level.** Any record in the file counts. Reported for SecurityEval and for comparison with Report #1.

## CWE agreement

For every detected case the candidate CWEs of the records on the sink line are compared with the
ground truth (`vulnreview/cwe.py`, MITRE CWE v4.9 via `cwe2` 3.0.0, view CWE-1000):

* **exact**: the ground-truth CWE is among the candidates;
* **related**: a candidate is an ancestor or descendant within two `ChildOf` links, or shares a direct parent;
* **incorrect**: otherwise.

CWE-exact recall = exact / all vulnerable cases.

## Uncertainty

Proportions are reported with 95 % Wilson score intervals. The sets are small, so the intervals are wide;
differences between engines are interpreted only when the intervals do not overlap.

## Runtime

Each engine runs `--repeat` times per split (CodeQL: 3). Mean, standard deviation, minimum and maximum
of wall-clock time are reported. Start-up cost is measured separately by running each engine on a
one-line file; *scan-only* time = mean total time - mean start-up time. Each repetition's findings are
fingerprinted to check that the engines are deterministic.

## Merge and non-CWE findings

* Records are merged only when they share file, line and a related CWE; all candidate CWEs, tools and
  rule IDs are kept (`vulnreview/merge.py`).
* Findings without a CWE are not scored. They are written to `unmapped-<split>-<engine>.json` in every
  evidence run and reviewed by hand (`docs/non_cwe_findings.md`).

## Evidence

Every run writes `evidence/<UTC-timestamp>/` with unedited raw engine outputs, the command log, the
environment, the console log, all derived results, the SARIF 2.1.0 export (validated against the OASIS
schema in `schemas/`) and `SHA256SUMS` covering outputs and benchmark inputs.
