"""Cycle-2 experiment runner. Produces a self-contained evidence folder:

evidence/<run-id>/
  commands.log        every external command with UTC timestamp and exit code
  env.txt             OS, Python, tool versions, repository + rules commits
  console.log         the unedited console output of this run
  raw/                unedited engine outputs (Bandit/Semgrep JSON, CodeQL SARIF)
  results/            normalised findings, unmapped findings, merged findings,
                      metrics per split and engine, SARIF 2.1.0 export, timing
  SHA256SUMS          hashes of every file above and of the benchmark inputs

Usage:
  python -m vulnreview.run --splits dev holdout securityeval --repeat 5 \
      --semgrep-rules rules/semgrep-python-security.yaml \
      --semgrep-full semgrep-rules/python --codeql /path/to/codeql
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from . import __version__
from . import adapters as ad
from .evaluate import evaluate, load_labels
from .merge import merge, split_unmapped
from .sarif import to_sarif, validate

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")   # no network call on start-up
os.environ.setdefault("SEMGREP_SEND_METRICS", "off")
SPLITS = {
    "dev": (ROOT / "bench/dev", ROOT / "bench/dev/labels_dev.csv", "dev"),
    "holdout": (ROOT / "bench/holdout", ROOT / "bench/holdout/labels_holdout.csv", "holdout"),
    "securityeval": (ROOT / "datasets/securityeval/cases", ROOT / "datasets/securityeval/labels_securityeval.csv",
                     "securityeval"),
}
PRIMARY = ("bandit", "semgrep", "codeql")


class Tee:
    def __init__(self, path: Path):
        self.fh = path.open("w")

    def __call__(self, *parts):
        line = " ".join(str(p) for p in parts)
        print(line)
        self.fh.write(line + "\n")
        self.fh.flush()


def sh(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout.strip()
    except Exception as e:  # noqa: BLE001
        return f"unavailable ({e})"


def stats(xs: list[float]) -> dict:
    return {"n": len(xs), "mean": round(statistics.mean(xs), 3),
            "sd": round(statistics.stdev(xs), 3) if len(xs) > 1 else 0.0,
            "min": round(min(xs), 3), "max": round(max(xs), 3), "runs": [round(x, 3) for x in xs]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--splits", nargs="+", default=["dev", "holdout"], choices=list(SPLITS))
    ap.add_argument("--semgrep-rules", type=Path, default=ROOT / "rules/semgrep-python-security.yaml")
    ap.add_argument("--semgrep-full", type=Path, help="full pinned rule folder, for the curation comparison")
    ap.add_argument("--codeql", help="path to the codeql executable (omit to skip CodeQL)")
    ap.add_argument("--repeat", type=int, default=5, help="timed repetitions per engine and split")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()

    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = a.out or ROOT / "evidence" / run_id
    raw, res, work = out / "raw", out / "results", out / "work"
    for d in (raw, res, work):
        d.mkdir(parents=True, exist_ok=True)
    log = Tee(out / "console.log")
    cmdlog = (out / "commands.log").open("w")

    def record(cmd, rc, secs):
        text = " && ".join(cmd) if cmd and isinstance(cmd[0], str) and " " in cmd[0] else " ".join(map(str, cmd))
        cmdlog.write(f"{dt.datetime.now(dt.timezone.utc).isoformat()} rc={rc} t={secs:.3f}s :: {text}\n")
        cmdlog.flush()

    env = {
        "run_id": run_id, "argv": " ".join(sys.argv), "platform": platform.platform(),
        "python": sys.version.split()[0], "vulnreview": __version__,
        "repo_commit": sh(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "repo_dirty": bool(sh(["git", "-C", str(ROOT), "status", "--porcelain", "--", "vulnreview", "bench", "scripts"])),
        "bandit": (sh(["bandit", "--version"]).splitlines() or ["?"])[0],
        "semgrep": sh(["semgrep", "--version"]),
        "semgrep_rules_config": str(a.semgrep_rules),
        "semgrep_rules_commit": sh(["git", "-C", str(a.semgrep_full), "rev-parse", "HEAD"]) if a.semgrep_full else "see rules manifest",
        "codeql": sh([a.codeql, "version", "--format=terse"]) if a.codeql else "not run",
        "codeql_suite": ad.CODEQL_SUITE if a.codeql else "-",
    }
    (out / "env.txt").write_text("\n".join(f"{k}: {v}" for k, v in env.items()) + "\n")
    log(f"vulnreview {__version__} run {run_id}")
    for k in ("repo_commit", "bandit", "semgrep", "codeql"):
        log(f"  {k}: {env[k]}")

    engines = {"bandit": lambda t, p, rd: ad.run_bandit(t, rd, p),
               "semgrep": lambda t, p, rd: ad.run_semgrep(t, a.semgrep_rules, rd, p)}
    if a.semgrep_full:
        engines["semgrep_full"] = lambda t, p, rd: ad.run_semgrep(t, a.semgrep_full, rd, p + "-full")
    if a.codeql:
        engines["codeql"] = lambda t, p, rd: ad.run_codeql(a.codeql, t, rd, work, p)

    # ---- start-up cost: each engine on an empty directory -----------------------
    timing = {"startup": {}, "splits": {}}
    empty = Path(tempfile.mkdtemp(dir=work))
    (empty / "empty.py").write_text("x = 1\n")
    for name, fn in engines.items():
        xs = []
        for i in range(max(1, min(a.repeat, 3))):
            rr = fn(empty, f"startup{i}", work)
            record(rr.command, rr.returncode, rr.seconds)
            xs.append(rr.seconds)
        timing["startup"][name] = stats(xs)
        log(f"startup {name:13s} mean {timing['startup'][name]['mean']:.2f}s sd {timing['startup'][name]['sd']:.2f}")

    all_metrics = {}
    sarif_errors = {}
    for split in a.splits:
        target, labels_path, prefix = SPLITS[split]
        labels = load_labels(labels_path)
        log(f"\n=== split: {split}  ({len(labels)} labelled cases)  target={target.relative_to(ROOT)}")
        per_engine, timing["splits"][split] = {}, {}
        for name, fn in engines.items():
            secs, first, fingerprints = [], None, set()
            for i in range(a.repeat if name != "codeql" else max(1, min(a.repeat, 3))):
                rr = fn(target, prefix, raw if i == 0 else work)
                record(rr.command, rr.returncode, rr.seconds)
                secs.append(rr.seconds)
                fingerprints.add(json.dumps(sorted(asdict(f).__repr__() for f in rr.findings)))
                if first is None:
                    first = rr
            t = stats(secs)
            t["deterministic"] = len(fingerprints) == 1
            st = timing["startup"][name]["mean"]
            t["scan_only_mean"] = round(max(0.0, t["mean"] - st), 3)
            timing["splits"][split][name] = t
            mapped, unmapped = split_unmapped(first.findings)
            per_engine[name] = (mapped, unmapped)
            (res / f"findings-{split}-{name}.json").write_text(json.dumps([asdict(f) for f in mapped], indent=1))
            (res / f"unmapped-{split}-{name}.json").write_text(json.dumps([asdict(f) for f in unmapped], indent=1))
            log(f"{name:13s} {len(first.findings):4d} raw, {len(unmapped):3d} without CWE | "
                f"total {t['mean']:.2f}±{t['sd']:.2f}s (n={t['n']}), scan-only ≈{t['scan_only_mean']:.2f}s, "
                f"deterministic={t['deterministic']}")

        metrics = {}
        for name, (mapped, _) in per_engine.items():
            metrics[name] = evaluate(merge(mapped), labels)
        union_findings = [f for n, (m, _) in per_engine.items() if n in PRIMARY for f in m]
        merged = merge(union_findings)
        union_name = "union(" + "+".join(n for n in per_engine if n in PRIMARY) + ")"
        metrics[union_name] = evaluate(merged, labels)
        (res / f"merged-{split}.json").write_text(json.dumps(merged, indent=1))
        doc = to_sarif(merged, __version__, {k: env.get(k if k != "semgrep_full" else "semgrep", "") for k in per_engine})
        (res / f"merged-{split}.sarif").write_text(json.dumps(doc, indent=1))
        errs = validate(doc, ROOT / "schemas/sarif-schema-2.1.0.json")
        sarif_errors[split] = errs
        all_metrics[split] = metrics

        log(f"\n{'ENGINE':28s} {'RECALL [95% CI]':22s} {'CWE-EXACT':10s} {'E/R/I/M':12s} {'REC-PREC':8s} {'OFF':>4s} {'SAFE':>5s}")
        for name, m in metrics.items():
            r = m["recall"]
            ag = m["cwe_agreement"]
            prec = m["record_precision"][0] if m["record_precision"] else float("nan")
            log(f"{name:28s} {r[0]:.3f} [{r[1]:.2f}-{r[2]:.2f}]     {m['cwe_exact_recall'][0]:.3f}      "
                f"{ag['exact']}/{ag['related']}/{ag['incorrect']}/{ag['missed']:<5} {prec:8.3f} "
                f"{str(m['records_off_target'] if m['records_off_target'] is not None else '-'):>4s} "
                f"{m['safe_files_flagged']:>3d}/{m['n_safe']}")
        log(f"SARIF 2.1.0 schema validation ({split}): {'PASS' if not errs else f'{len(errs)} errors'}")

    (res / "metrics.json").write_text(json.dumps(all_metrics, indent=1))
    (res / "timing.json").write_text(json.dumps(timing, indent=1))
    (res / "sarif_validation.json").write_text(json.dumps(sarif_errors, indent=1))
    cmdlog.close()

    # ---- hashes of outputs and inputs -------------------------------------------
    import shutil
    shutil.rmtree(work, ignore_errors=True)
    inputs = sorted(p for s in a.splits for p in [SPLITS[s][1], *SPLITS[s][0].rglob("*.py")])
    lines = []
    for p in sorted(out.rglob("*")) + inputs:
        if p.is_file() and p.name != "SHA256SUMS":
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            rel = p.relative_to(out) if out in p.parents else Path("REPO") / p.relative_to(ROOT)
            lines.append(f"{h}  {rel.as_posix()}")
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    log(f"\nEvidence written to {out} ({len(lines)} hashed files)")
    return 0


if __name__ == "__main__":
    t0 = time.time()
    rc = main()
    sys.exit(rc)
