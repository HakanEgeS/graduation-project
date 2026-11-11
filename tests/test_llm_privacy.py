"""Tests for the LLM privacy guard and call logging (vulnreview.llm_triage)."""
import json
from pathlib import Path

import pytest

from vulnreview import llm_triage as lt

ROOT = Path(__file__).resolve().parent.parent
REC = {"file": "dev/vuln/v01_sqli.py", "line": 4, "cwes": ["CWE-89"], "tools": ["bandit"],
       "rules": ["bandit:B608"], "messages": ["[bandit] m"]}


def test_local_endpoint_always_allowed(tmp_path):
    rec = dict(REC, file="secret.py")
    lt.check_privacy("http://localhost:11434/v1", [rec], allow_hosted=False, src_root=tmp_path)


def test_hosted_endpoint_refused_without_flag():
    with pytest.raises(SystemExit):
        lt.check_privacy("https://api.example.com/v1", [REC], allow_hosted=False, src_root=ROOT / "bench")


def test_hosted_endpoint_allowed_for_public_benchmark_code():
    lt.check_privacy("https://api.example.com/v1", [REC], allow_hosted=True, src_root=ROOT / "bench")


def test_hosted_endpoint_refused_for_private_code_even_in_a_dev_folder(tmp_path):
    (tmp_path / "dev").mkdir()
    (tmp_path / "dev" / "app.py").write_text("x = 1\n")
    with pytest.raises(SystemExit):
        lt.check_privacy("https://api.example.com/v1", [dict(REC, file="dev/app.py")],
                         allow_hosted=True, src_root=tmp_path)


def test_every_call_is_logged_with_parameters(tmp_path, monkeypatch):
    findings = tmp_path / "merged.json"
    findings.write_text(json.dumps([REC]))
    out = tmp_path / "log.jsonl"
    monkeypatch.setattr("sys.argv", ["llm_triage", "--findings", str(findings), "--root", str(ROOT / "bench"),
                                     "--backend", "mock", "--out", str(out)])
    lt.main()
    entry = json.loads(out.read_text().splitlines()[0])
    for key in ("model", "model_digest", "params", "system_prompt", "user_prompt", "prompt_sha256",
                "raw_response", "parsed", "valid", "latency_s"):
        assert key in entry
    assert entry["params"] == {"temperature": 0.0, "seed": 42} and entry["valid"] is True
