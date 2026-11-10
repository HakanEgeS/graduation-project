"""Unit tests for CWE agreement, merging, evaluation and SARIF export."""
from pathlib import Path

from vulnreview import cwe
from vulnreview.adapters import Finding
from vulnreview.evaluate import evaluate, wilson
from vulnreview.merge import merge, split_unmapped
from vulnreview.sarif import to_sarif, validate

ROOT = Path(__file__).resolve().parent.parent


def test_cwe_norm():
    assert cwe.norm("CWE-089: SQL Injection") == "CWE-89"
    assert cwe.norm("external/cwe/cwe-022") == "CWE-22"
    assert cwe.norm(78) == "CWE-78"
    assert cwe.norm("no cwe here") is None


def test_cwe_agreement_levels():
    assert cwe.agreement("CWE-89", ["CWE-89"]) == "exact"
    assert cwe.agreement("CWE-798", ["CWE-259"]) == "related"      # 259 ChildOf 798
    assert cwe.agreement("CWE-328", ["CWE-327"]) == "related"      # 328 ChildOf 327
    assert cwe.agreement("CWE-95", ["CWE-78"]) == "incorrect"


def F(tool, line, cwes, file="dev/vuln/a.py"):
    return Finding(tool, "R", file, line, "MEDIUM", cwes, "m")


def test_merge_keeps_unrelated_weaknesses_on_same_line_apart():
    recs = merge([F("bandit", 3, ["CWE-89"]), F("semgrep", 3, ["CWE-89"]), F("semgrep", 3, ["CWE-295"])])
    assert len(recs) == 2
    sqli = next(r for r in recs if "CWE-89" in r["cwes"])
    assert sqli["tools"] == ["bandit", "semgrep"]


def test_merge_preserves_all_candidate_cwes():
    recs = merge([F("bandit", 2, ["CWE-259"]), F("semgrep", 2, ["CWE-798"])])
    assert len(recs) == 1 and recs[0]["cwes"] == ["CWE-259", "CWE-798"]


def test_unmapped_findings_are_separated():
    mapped, unmapped = split_unmapped([F("semgrep", 1, []), F("bandit", 1, ["CWE-78"])])
    assert len(mapped) == 1 and len(unmapped) == 1


def test_line_level_evaluation():
    labels = [{"case_id": "a", "path": "dev/vuln/a.py", "label": "vulnerable", "cwe": "CWE-89",
               "lines": {4}, "pattern": "direct"},
              {"case_id": "s", "path": "dev/safe/s.py", "label": "safe", "cwe": None,
               "lines": set(), "pattern": "safe"}]
    recs = merge([F("bandit", 4, ["CWE-89"]), F("bandit", 1, ["CWE-78"]),
                  F("bandit", 2, ["CWE-78"], file="dev/safe/s.py")])
    m = evaluate(recs, labels)
    assert m["recall"][0] == 1.0
    assert m["records_true_positive"] == 1 and m["records_off_target"] == 1
    assert m["records_in_safe_files"] == 1 and m["safe_files_flagged"] == 1
    assert m["cwe_agreement"]["exact"] == 1


def test_wilson_interval_bounds():
    p, lo, hi = wilson(11, 12)
    assert lo < p < hi and 0 <= lo and hi <= 1


def test_sarif_export_validates_against_oasis_schema():
    doc = to_sarif(merge([F("bandit", 4, ["CWE-89"]), F("semgrep", 4, ["CWE-89"])]), "test", {"bandit": "x"})
    assert validate(doc, ROOT / "schemas/sarif-schema-2.1.0.json") == []


def test_cwe_category_without_relations_does_not_crash():
    # CWE-730 is a category; cwe2 returns (None,) for its relations
    assert cwe.parents(730) == frozenset()
    assert cwe.agreement("CWE-730", ["CWE-400"]) in ("related", "incorrect")


def test_semgrep_scans_git_ignored_folders():
    from vulnreview.adapters import semgrep_cmd
    assert "--no-git-ignore" in semgrep_cmd(Path("x"), Path("r.yaml"))
