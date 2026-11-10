"""Cross-tool merging.

Merge key (v0.2): two findings are merged only if they are in the same file,
on the same line, AND their CWE sets are related (cwe.related). Two unrelated
weaknesses on one line therefore stay separate records. All candidate CWEs,
tools and rule IDs are preserved; no tool's CWE is discarded.
Findings without any CWE are not merged; they are returned separately for
manual review (see docs/non_cwe_findings.md).
"""
from __future__ import annotations

from collections import defaultdict

from . import cwe as cwelib
from .adapters import Finding

SEV_ORDER = {"LOW": 1, "INFO": 1, "NOTE": 1, "MEDIUM": 2, "WARNING": 2, "HIGH": 3, "ERROR": 3}


def _sev(s: str) -> int:
    if s.startswith("SCORE-"):
        try:
            v = float(s[6:])
            return 3 if v >= 7 else 2 if v >= 4 else 1
        except ValueError:
            return 2
    return SEV_ORDER.get(s, 1)


def _related_sets(a: set[str], b: set[str]) -> bool:
    return any(cwelib.related(x, y) for x in a for y in b)


def split_unmapped(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    mapped = [f for f in findings if f.cwes]
    unmapped = [f for f in findings if not f.cwes]
    return mapped, unmapped


def merge(findings: list[Finding]) -> list[dict]:
    by_line: dict[tuple[str, int], list[Finding]] = defaultdict(list)
    for f in findings:
        by_line[(f.file, f.line)].append(f)
    merged = []
    for (file, line), group in sorted(by_line.items()):
        clusters: list[dict] = []
        for f in group:
            target = next((c for c in clusters if _related_sets(set(c["cwes"]), set(f.cwes))), None)
            if target is None:
                target = {"file": file, "line": line, "cwes": [], "tools": [], "rules": [],
                          "severity": 0, "messages": []}
                clusters.append(target)
            target["cwes"] = sorted(set(target["cwes"]) | set(f.cwes))
            if f.tool not in target["tools"]:
                target["tools"].append(f.tool)
            target["rules"].append(f"{f.tool}:{f.rule_id}")
            target["severity"] = max(target["severity"], _sev(f.severity))
            target["messages"].append(f"[{f.tool}] {f.message}")
        merged.extend(clusters)
    for m in merged:
        m["tools"].sort()
        m["severity"] = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}[max(m["severity"], 1)]
    return merged
