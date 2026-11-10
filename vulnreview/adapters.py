"""Engine adapters. Each adapter runs one SAST engine on a target directory,
saves the engine's raw output unchanged, and returns normalised findings."""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import cwe as cwelib


@dataclass
class Finding:
    tool: str
    rule_id: str
    file: str          # path relative to the benchmark root, e.g. "dev/vuln/v01_sqli.py"
    line: int
    severity: str
    cwes: list[str] = field(default_factory=list)
    message: str = ""


@dataclass
class RunResult:
    tool: str
    findings: list[Finding]
    seconds: float
    command: list[str]
    raw_path: Path
    returncode: int


def _rel(path: str, target: Path, prefix: str) -> str:
    p = Path(path)
    try:
        p = p.resolve().relative_to(target.resolve())
    except ValueError:
        pass
    return f"{prefix}/{p.as_posix()}" if prefix else p.as_posix()


def _run(cmd: list[str], cwd: Path | None = None) -> tuple[subprocess.CompletedProcess, float]:
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return proc, time.perf_counter() - t0


# ---------------------------------------------------------------- Bandit
def bandit_cmd(target: Path) -> list[str]:
    return ["bandit", "-r", str(target), "-f", "json", "-q"]


def run_bandit(target: Path, raw_dir: Path, prefix: str) -> RunResult:
    cmd = bandit_cmd(target)
    proc, secs = _run(cmd)
    raw = raw_dir / f"bandit-{prefix or 'scan'}.json"
    raw.write_text(proc.stdout)
    data = json.loads(proc.stdout or "{}")
    out = []
    for r in data.get("results", []):
        cid = (r.get("issue_cwe") or {}).get("id")
        out.append(Finding("bandit", r["test_id"], _rel(r["filename"], target, prefix),
                           r["line_number"], r["issue_severity"].upper(),
                           [cwelib.norm(cid)] if cid else [], r["issue_text"]))
    return RunResult("bandit", out, secs, cmd, raw, proc.returncode)


# ---------------------------------------------------------------- Semgrep
def semgrep_cmd(target: Path, rules: Path) -> list[str]:
    return ["semgrep", "scan", "--config", str(rules), "--json", "--metrics=off",
            "--disable-version-check", "--quiet", str(target)]


def run_semgrep(target: Path, rules: Path, raw_dir: Path, prefix: str) -> RunResult:
    cmd = semgrep_cmd(target, rules)
    proc, secs = _run(cmd)
    raw = raw_dir / f"semgrep-{prefix or 'scan'}.json"
    raw.write_text(proc.stdout)
    data = json.loads(proc.stdout or "{}")
    out = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {}) or {}
        c = meta.get("cwe", [])
        c = c if isinstance(c, list) else [c]
        cwes = sorted({x for x in (cwelib.norm(v) for v in c) if x})
        out.append(Finding("semgrep", r["check_id"].split(".")[-1], _rel(r["path"], target, prefix),
                           r["start"]["line"], (r["extra"].get("severity") or "INFO").upper(), cwes,
                           (r["extra"].get("message") or "").strip().split("\n")[0][:200]))
    return RunResult("semgrep", out, secs, cmd, raw, proc.returncode)


# ---------------------------------------------------------------- CodeQL
CODEQL_SUITE = "codeql/python-queries:codeql-suites/python-security-extended.qls"


def codeql_cmds(codeql: str, target: Path, db: Path, sarif: Path) -> list[list[str]]:
    return [
        [codeql, "database", "create", str(db), "--language=python", f"--source-root={target}",
         "--overwrite", "--quiet"],
        [codeql, "database", "analyze", str(db), CODEQL_SUITE, "--format=sarif-latest",
         f"--output={sarif}", "--quiet", "--threads=0"],
    ]


def run_codeql(codeql: str, target: Path, raw_dir: Path, work_dir: Path, prefix: str) -> RunResult:
    db = work_dir / f"codeql-db-{prefix or 'scan'}"
    sarif = raw_dir / f"codeql-{prefix or 'scan'}.sarif"
    cmds = codeql_cmds(codeql, target, db, sarif)
    secs, rc = 0.0, 0
    for c in cmds:
        proc, s = _run(c)
        secs += s
        rc = rc or proc.returncode
        if proc.returncode != 0:
            raise RuntimeError(f"CodeQL failed: {' '.join(c)}\n{proc.stderr[-2000:]}")
    data = json.loads(sarif.read_text())
    out = []
    for run in data.get("runs", []):
        rules = {}
        for ext in [run["tool"]["driver"]] + run["tool"].get("extensions", []):
            for rule in ext.get("rules", []) or []:
                rules[rule["id"]] = rule
        for res in run.get("results", []):
            rule = rules.get(res.get("ruleId"), {})
            tags = (rule.get("properties") or {}).get("tags", [])
            cwes = sorted({x for x in (cwelib.norm(t) for t in tags if "cwe" in t.lower()) if x})
            loc = res["locations"][0]["physicalLocation"]
            sev = (rule.get("properties") or {}).get("security-severity", "")
            out.append(Finding("codeql", res.get("ruleId", ""),
                               f"{prefix}/{loc['artifactLocation']['uri']}" if prefix else loc["artifactLocation"]["uri"],
                               loc["region"]["startLine"], f"SCORE-{sev}" if sev else res.get("level", "warning").upper(),
                               cwes, res["message"]["text"][:200]))
    shutil.rmtree(db, ignore_errors=True)
    return RunResult("codeql", out, secs, [" ".join(c) for c in cmds], sarif, rc)
