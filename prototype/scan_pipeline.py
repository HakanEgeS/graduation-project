"""
scan_pipeline.py - Baseline SAST orchestration layer (Report #1 prototype skeleton)

Project: AI-Powered Vulnerability Detection and Secure Code Review System
Purpose: Run two static analysers (Bandit, Semgrep) on a target directory,
normalise their outputs into one finding schema, merge duplicates, and
evaluate detection against a labelled benchmark (labels.csv).

The LLM triage/explanation layer is NOT implemented in this cycle; the
normalised finding schema below is the planned input of that layer.
"""
import argparse
import csv
import json
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class Finding:
    tool: str
    rule_id: str
    file: str
    line: int
    severity: str
    cwe: str
    message: str


def run_bandit(target: Path) -> tuple[list[Finding], float]:
    t0 = time.perf_counter()
    proc = subprocess.run(["bandit", "-r", str(target), "-f", "json", "-q"],
                          capture_output=True, text=True)
    elapsed = time.perf_counter() - t0
    data = json.loads(proc.stdout or "{}")
    out = []
    for r in data.get("results", []):
        cwe = r.get("issue_cwe", {}).get("id")
        out.append(Finding("bandit", r["test_id"], Path(r["filename"]).name,
                           r["line_number"], r["issue_severity"].upper(),
                           f"CWE-{cwe}" if cwe else "-", r["issue_text"]))
    return out, elapsed


def run_semgrep(target: Path, rules: Path) -> tuple[list[Finding], float]:
    t0 = time.perf_counter()
    proc = subprocess.run(["semgrep", "scan", "--config", str(rules), "--json",
                           "--metrics=off", "--quiet", str(target)],
                          capture_output=True, text=True)
    elapsed = time.perf_counter() - t0
    data = json.loads(proc.stdout or "{}")
    out = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        cwe = meta.get("cwe", ["-"])
        cwe = cwe[0] if isinstance(cwe, list) else cwe
        cwe = cwe.split(":")[0].strip()
        out.append(Finding("semgrep", r["check_id"].split(".")[-1],
                           Path(r["path"]).name, r["start"]["line"],
                           r["extra"].get("severity", "INFO").upper(), cwe,
                           r["extra"].get("message", "").strip().split("\n")[0][:160]))
    return out, elapsed


def merge(findings: list[Finding]) -> list[dict]:
    """Merge findings reported by several tools at the same file and line."""
    merged: dict[tuple, dict] = {}
    for f in findings:
        key = (f.file, f.line)
        if key not in merged:
            merged[key] = {**asdict(f), "tools": [f.tool]}
        elif f.tool not in merged[key]["tools"]:
            merged[key]["tools"].append(f.tool)
    return sorted(merged.values(), key=lambda d: (d["file"], d["line"]))


def evaluate(findings: list[Finding], labels: Path, tools: set[str]) -> dict:
    """File-level evaluation: a file is 'flagged' if the tool(s) report any finding."""
    rows = list(csv.DictReader(labels.open()))
    flagged = {f.file for f in findings if f.tool in tools}
    tp = sum(1 for r in rows if r["vulnerable"] == "1" and r["file"] in flagged)
    fn = sum(1 for r in rows if r["vulnerable"] == "1" and r["file"] not in flagged)
    fp = sum(1 for r in rows if r["vulnerable"] == "0" and r["file"] in flagged)
    tn = sum(1 for r in rows if r["vulnerable"] == "0" and r["file"] not in flagged)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    missed = [r["file"] for r in rows if r["vulnerable"] == "1" and r["file"] not in flagged]
    false_alarms = [r["file"] for r in rows if r["vulnerable"] == "0" and r["file"] in flagged]
    return dict(TP=tp, FP=fp, FN=fn, TN=tn, precision=round(prec, 3),
                recall=round(rec, 3), f1=round(f1, 3), missed=missed,
                false_alarms=false_alarms)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", type=Path)
    ap.add_argument("--rules", type=Path, required=True)
    ap.add_argument("--labels", type=Path)
    ap.add_argument("--out", type=Path, default=Path("findings.json"))
    ap.add_argument("--include-non-security", action="store_true",
                    help="keep findings without a CWE mapping (code-quality rules)")
    a = ap.parse_args()

    b, tb = run_bandit(a.target)
    s, ts = run_semgrep(a.target, a.rules)
    if not a.include_non_security:
        dropped = [f for f in b + s if f.cwe == "-"]
        b = [f for f in b if f.cwe != "-"]
        s = [f for f in s if f.cwe != "-"]
        print(f"Filtered {len(dropped)} non-security finding(s) without CWE mapping")
    merged = merge(b + s)
    report = {"target": str(a.target), "runtime_s": {"bandit": round(tb, 2), "semgrep": round(ts, 2)},
              "raw_counts": {"bandit": len(b), "semgrep": len(s)},
              "merged_findings": merged}
    if a.labels:
        report["evaluation"] = {
            "bandit": evaluate(b + s, a.labels, {"bandit"}),
            "semgrep": evaluate(b + s, a.labels, {"semgrep"}),
            "union": evaluate(b + s, a.labels, {"bandit", "semgrep"}),
        }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(report, indent=2))

    print(f"Bandit : {len(b):3d} findings in {tb:.2f}s")
    print(f"Semgrep: {len(s):3d} findings in {ts:.2f}s")
    print(f"Merged : {len(merged):3d} unique findings -> {a.out}\n")
    print(f"{'FILE':26s} {'LINE':>4s}  {'CWE':9s} {'SEV':7s} TOOLS")
    for m in merged:
        print(f"{m['file']:26s} {m['line']:4d}  {m['cwe']:9s} {m['severity']:7s} {'+'.join(m['tools'])}")
    if a.labels:
        print("\nFile-level evaluation on labelled benchmark:")
        print(f"{'TOOL':8s} {'TP':>3s} {'FP':>3s} {'FN':>3s} {'TN':>3s} {'PREC':>6s} {'REC':>6s} {'F1':>6s}")
        for k, e in report["evaluation"].items():
            print(f"{k:8s} {e['TP']:3d} {e['FP']:3d} {e['FN']:3d} {e['TN']:3d} "
                  f"{e['precision']:6.3f} {e['recall']:6.3f} {e['f1']:6.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
