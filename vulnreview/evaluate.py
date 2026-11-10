"""Evaluation against labelled benchmarks.

Line level (used when sink_lines are labelled):
  * a vulnerable case is DETECTED if a merged record lies on one of its sink lines;
  * a record is a TRUE POSITIVE if it lies on a sink line of a vulnerable case,
    otherwise it is an OFF-TARGET record (other line of a vulnerable file) or a
    SAFE-FILE ALARM (record in a safe file);
  * CWE agreement of a detected case = exact / related / incorrect (cwe.agreement),
    using all candidate CWEs of the records on the sink line.
File level is also reported, for comparison with Report #1.
Proportions carry 95 % Wilson score intervals.
"""
from __future__ import annotations

import csv
import math
from collections import Counter, defaultdict
from pathlib import Path

from . import cwe as cwelib


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    if n == 0:
        return (float("nan"), float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(p, 3), round(max(0.0, c - h), 3), round(min(1.0, c + h), 3))


def load_labels(path: Path) -> list[dict]:
    rows = list(csv.DictReader(path.open(newline="")))
    for r in rows:
        r["lines"] = {int(x) for x in r.get("sink_lines", "").split(";") if x.strip()}
        r["cwe"] = cwelib.norm(r.get("cwe")) if r.get("cwe") not in (None, "", "-") else None
    return rows


def evaluate(records: list[dict], labels: list[dict]) -> dict:
    by_file = defaultdict(list)
    for rec in records:
        by_file[rec["file"]].append(rec)
    vuln = [l for l in labels if l["label"] == "vulnerable"]
    safe = [l for l in labels if l["label"] == "safe"]
    line_level = all(l["lines"] for l in vuln)
    sink_index = {(l["path"], ln) for l in vuln for ln in l["lines"]}
    vuln_paths = {l["path"] for l in vuln}
    safe_paths = {l["path"] for l in safe}

    per_case, agree = [], Counter()
    detected_line = detected_file = 0
    for l in vuln:
        recs = by_file.get(l["path"], [])
        on_sink = [r for r in recs if r["line"] in l["lines"]] if line_level else recs
        hit_line = bool(on_sink)
        hit_file = bool(recs)
        detected_line += hit_line
        detected_file += hit_file
        cands = sorted({c for r in (on_sink if line_level else recs) for c in r["cwes"]})
        a = cwelib.agreement(l["cwe"], cands) if (hit_line and l["cwe"]) else "missed"
        agree[a] += 1
        per_case.append({"case": l["case_id"], "label": "vulnerable", "cwe": l["cwe"],
                         "pattern": l.get("pattern", ""), "detected": hit_line,
                         "tools": sorted({t for r in on_sink for t in r["tools"]}),
                         "reported_cwes": cands, "agreement": a})
    for l in safe:
        recs = by_file.get(l["path"], [])
        per_case.append({"case": l["case_id"], "label": "safe", "cwe": None,
                         "pattern": l.get("pattern", ""), "detected": bool(recs),
                         "tools": sorted({t for r in recs for t in r["tools"]}),
                         "reported_cwes": sorted({c for r in recs for c in r["cwes"]}),
                         "agreement": "false-alarm" if recs else "clean"})

    labelled = [r for r in records if r["file"] in vuln_paths | safe_paths]
    tp = sum((r["file"], r["line"]) in sink_index for r in labelled) if line_level else None
    off = sum(r["file"] in vuln_paths and (r["file"], r["line"]) not in sink_index for r in labelled) if line_level else None
    safe_alarm = sum(r["file"] in safe_paths for r in labelled)
    safe_flagged = sum(1 for l in safe if by_file.get(l["path"]))
    n = len(vuln)

    by_pattern = {}
    for pat in sorted({c["pattern"] for c in per_case if c["label"] == "vulnerable"}):
        cs = [c for c in per_case if c["label"] == "vulnerable" and c["pattern"] == pat]
        by_pattern[pat] = {"n": len(cs), "detected": sum(c["detected"] for c in cs),
                           "recall": wilson(sum(c["detected"] for c in cs), len(cs))}
    return {
        "level": "line" if line_level else "file",
        "n_vulnerable": n, "n_safe": len(safe),
        "recall": wilson(detected_line, n),
        "cwe_exact_recall": wilson(agree["exact"], n),
        "cwe_agreement": {k: agree.get(k, 0) for k in ("exact", "related", "incorrect", "missed")},
        "records_total": len(labelled),
        "records_true_positive": tp,
        "records_off_target": off,
        "records_in_safe_files": safe_alarm,
        "record_precision": wilson(tp, len(labelled)) if line_level else None,
        "safe_files_flagged": safe_flagged,
        "file_level": {"detected": detected_file, "recall": wilson(detected_file, n),
                       "precision": wilson(detected_file, detected_file + safe_flagged)},
        "by_pattern": by_pattern,
        "per_case": per_case,
    }
