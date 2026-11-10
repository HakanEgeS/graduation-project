"""SARIF 2.1.0 export of merged findings, with validation against the OASIS
JSON schema (schemas/sarif-schema-2.1.0.json)."""
from __future__ import annotations

import json
from pathlib import Path

LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"


def to_sarif(records: list[dict], version: str, engines: dict[str, str]) -> dict:
    rules, results = {}, []
    for r in records:
        rid = "+".join(r["cwes"]) if r["cwes"] else "UNMAPPED"
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "shortDescription": {"text": f"Merged finding mapped to {', '.join(r['cwes']) or 'no CWE'}"},
                "properties": {"tags": ["security"] + [f"external/cwe/{c.lower()}" for c in r["cwes"]]},
            }
        results.append({
            "ruleId": rid,
            "level": LEVEL.get(r["severity"], "warning"),
            "message": {"text": " | ".join(r["messages"])[:1000]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": r["file"], "uriBaseId": "BENCHROOT"},
                "region": {"startLine": r["line"]}}}],
            "partialFingerprints": {"fileLineCwe/v1": f"{r['file']}:{r['line']}:{rid}"},
            "properties": {"tools": r["tools"], "rules": r["rules"], "candidateCwes": r["cwes"]},
        })
    return {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "vulnreview", "version": version,
                                "informationUri": "https://github.com/HakanEgeS/graduation-project",
                                "rules": list(rules.values()),
                                "properties": {"engines": engines}}},
            "originalUriBaseIds": {"BENCHROOT": {"description": {"text": "Benchmark root (bench/)"}}},
            "results": results,
        }],
    }


def validate(doc: dict, schema_path: Path) -> list[str]:
    import jsonschema
    schema = json.loads(schema_path.read_text())
    v = jsonschema.Draft4Validator(schema)
    return [f"{'/'.join(map(str, e.path))}: {e.message}" for e in v.iter_errors(doc)]
