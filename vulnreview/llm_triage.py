"""LLM triage layer (cycle-2 prototype).

For every merged finding the model receives the finding (tools, rules, candidate
CWEs, messages) and the surrounding source lines, and must answer with a JSON
object that matches VERDICT_SCHEMA. Nothing else is sent.

Safeguards
* Privacy: a non-local endpoint is refused unless --allow-hosted is given AND every
  finding resolves inside the synthetic or public data folders (PUBLIC_DIRS).
* Reproducibility: temperature 0 and a fixed seed by default; the exact model name,
  the model digest reported by Ollama (when available), all parameters, the full
  prompt, its SHA-256, the raw response, the parsed verdict and the latency are
  appended to a JSONL log, one line per call.
* Robustness: a response that is not valid JSON or does not match the schema is
  logged as invalid and retried once; it is never silently repaired.

Example (Windows PowerShell, Ollama running locally):
  ollama pull qwen2.5-coder:7b
  python -m vulnreview.llm_triage --findings evidence/<run>/results/merged-dev.json ^
         --root bench --model qwen2.5-coder:7b
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
CONTEXT_LINES = 8

VERDICT_SCHEMA = {
    "type": "object",
    "required": ["verdict", "confidence", "cwe", "explanation", "fix"],
    "additionalProperties": False,
    "properties": {
        "verdict": {"enum": ["true_positive", "false_positive", "uncertain"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "cwe": {"type": "string", "pattern": "^CWE-[0-9]+$"},
        "explanation": {"type": "string", "minLength": 20, "maxLength": 1200},
        "fix": {
            "type": "object",
            "required": ["description", "patched_lines"],
            "additionalProperties": False,
            "properties": {
                "description": {"type": "string"},
                "patched_lines": {"type": "string"},
            },
        },
    },
}

SYSTEM_PROMPT = (
    "You are a secure code reviewer. You receive ONE finding reported by static analysis "
    "tools and the code around it. Decide whether it is a real vulnerability in this code "
    "(true_positive), not a vulnerability (false_positive), or undecidable from the code "
    "shown (uncertain). Use only the code shown; do not assume code that is not there. "
    "Reply with ONE JSON object and nothing else, with keys: verdict, confidence (0-1), "
    "cwe (the single best CWE id, e.g. CWE-89), explanation (2-4 sentences naming the "
    "source and the sink lines), fix {description, patched_lines (replacement code for "
    "the flagged lines only; empty string if no fix is needed)}."
)


def build_prompt(rec: dict, src_root: Path) -> str:
    path = src_root / rec["file"]
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    lo, hi = max(1, rec["line"] - CONTEXT_LINES), min(len(lines), rec["line"] + CONTEXT_LINES)
    snippet = "\n".join(f"{i:4d}{'>' if i == rec['line'] else ' '} {lines[i - 1]}" for i in range(lo, hi + 1))
    return (
        f"File: {rec['file']}\nFlagged line: {rec['line']}\n"
        f"Reported by: {', '.join(rec['tools'])}\nRules: {', '.join(rec['rules'])}\n"
        f"Candidate CWEs from the tools: {', '.join(rec['cwes']) or 'none'}\n"
        f"Tool messages:\n- " + "\n- ".join(rec["messages"]) + "\n\n"
        f"Code (lines {lo}-{hi}, '>' marks the flagged line):\n{snippet}\n"
    )


PUBLIC_DIRS = (ROOT / "bench", ROOT / "datasets" / "securityeval")   # synthetic (own) or public code


def check_privacy(endpoint: str, records: list[dict], allow_hosted: bool, src_root: Path) -> None:
    """Local endpoints are always allowed. A hosted endpoint needs --allow-hosted AND every
    finding's file must resolve inside one of PUBLIC_DIRS (checked on the real path, so a
    folder that merely happens to be called 'dev/' elsewhere does not pass)."""
    host = urlparse(endpoint).hostname or ""
    if host in ("localhost", "127.0.0.1", "::1"):
        return
    if not allow_hosted:
        raise SystemExit(f"Refusing hosted endpoint {host}: pass --allow-hosted (synthetic/public code only).")
    private = []
    for r in records:
        real = (src_root / r["file"]).resolve()
        if not any(real.is_relative_to(d.resolve()) for d in PUBLIC_DIRS):
            private.append(r["file"])
    if private:
        raise SystemExit(f"Refusing to send non-public code to {host}: {private[:3]} ...")


def model_digest(endpoint: str, model: str) -> str:
    """Ollama only: digest of the local model, so the exact weights are recorded."""
    try:
        base = endpoint.split("/v1")[0]
        with urllib.request.urlopen(f"{base}/api/tags", timeout=5) as r:
            for m in json.load(r).get("models", []):
                if m.get("name") == model or m.get("model") == model:
                    return m.get("digest", "")
    except Exception:  # noqa: BLE001
        pass
    return ""


def call_openai_compatible(endpoint: str, model: str, system: str, user: str, params: dict,
                           api_key: str | None) -> tuple[str, float]:
    body = {"model": model, "messages": [{"role": "system", "content": system},
                                          {"role": "user", "content": user}],
            "response_format": {"type": "json_object"}, **params}
    req = urllib.request.Request(endpoint.rstrip("/") + "/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": f"Bearer {api_key}"} if api_key else {})})
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=600) as r:
        data = json.load(r)
    return data["choices"][0]["message"]["content"], time.perf_counter() - t0


def call_mock(rec: dict) -> tuple[str, float]:
    """Deterministic stand-in used by the tests; it is NOT a model."""
    return json.dumps({"verdict": "uncertain", "confidence": 0.0, "cwe": (rec["cwes"] or ["CWE-0"])[0],
                       "explanation": "Mock backend: no model was called for this finding.",
                       "fix": {"description": "", "patched_lines": ""}}), 0.0


def parse(text: str) -> tuple[dict | None, str]:
    import jsonschema
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        return None, f"invalid JSON: {e}"
    errs = [e.message for e in jsonschema.Draft7Validator(VERDICT_SCHEMA).iter_errors(obj)]
    return (obj, "") if not errs else (None, "; ".join(errs[:3]))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", type=Path, required=True, help="merged-<split>.json from an evidence run")
    ap.add_argument("--root", type=Path, default=ROOT / "bench", help="folder the finding paths are relative to")
    ap.add_argument("--backend", choices=["openai", "mock"], default="openai")
    ap.add_argument("--endpoint", default="http://localhost:11434/v1")
    ap.add_argument("--model", default="qwen2.5-coder:7b")
    ap.add_argument("--api-key")
    ap.add_argument("--allow-hosted", action="store_true")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()

    records = json.loads(a.findings.read_text())[: a.limit]
    if a.backend == "openai":
        check_privacy(a.endpoint, records, a.allow_hosted, a.root)
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = a.out or ROOT / "llm_logs" / f"{run_id}-{a.findings.stem}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    params = {"temperature": a.temperature, "seed": a.seed}
    digest = model_digest(a.endpoint, a.model) if a.backend == "openai" else "mock"
    valid = 0
    with out.open("w", encoding="utf-8") as log:
        for i, rec in enumerate(records, 1):
            user = build_prompt(rec, a.root)
            for attempt in (1, 2):
                if a.backend == "mock":
                    text, secs = call_mock(rec)
                else:
                    text, secs = call_openai_compatible(a.endpoint, a.model, SYSTEM_PROMPT, user, params, a.api_key)
                obj, err = parse(text)
                log.write(json.dumps({
                    "ts": dt.datetime.now(dt.timezone.utc).isoformat(), "run_id": run_id, "attempt": attempt,
                    "finding": {k: rec[k] for k in ("file", "line", "cwes", "tools")},
                    "backend": a.backend, "endpoint": a.endpoint if a.backend == "openai" else None,
                    "model": a.model if a.backend == "openai" else "mock", "model_digest": digest,
                    "params": params, "system_prompt": SYSTEM_PROMPT, "user_prompt": user,
                    "prompt_sha256": hashlib.sha256((SYSTEM_PROMPT + user).encode()).hexdigest(),
                    "raw_response": text, "parsed": obj, "valid": obj is not None, "error": err,
                    "latency_s": round(secs, 3)}, ensure_ascii=False) + "\n")
                if obj is not None:
                    valid += 1
                    break
            print(f"[{i}/{len(records)}] {rec['file']}:{rec['line']} -> "
                  f"{obj['verdict'] if obj else 'INVALID'} ({err or 'ok'})")
    print(f"{valid}/{len(records)} valid verdicts; log: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
