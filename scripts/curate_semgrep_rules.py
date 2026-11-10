"""Build the curated Semgrep rule set used from cycle 2 on.

Procedure (documented in docs/semgrep_rule_curation.md):
  1. Walk every *.yaml / *.yml file under the pinned semgrep-rules/python folder.
  2. Keep a rule only if   metadata.category == "security"
                      AND  "python" is in languages
                      AND  metadata.cwe is present (so every kept finding has a CWE).
  3. Keep rules whose ID repeats in another file, renamed <id>__<folder> so no rule
     is lost and every ID in the combined file is unique.
  4. Write all kept rules into ONE config file and a manifest CSV listing
     rule id, source file, CWE(s), subcategory and confidence.
The rule texts stay under the Semgrep Rules License and are therefore NOT
committed; only this script and the manifest are. Re-run it after cloning
semgrep-rules at the pinned commit.
"""
import argparse
import csv
from pathlib import Path

import yaml


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("rules_dir", type=Path, help="semgrep-rules/python")
    ap.add_argument("--out", type=Path, default=Path("rules/semgrep-python-security.yaml"))
    ap.add_argument("--manifest", type=Path, default=Path("rules/semgrep-python-security.manifest.csv"))
    a = ap.parse_args()

    files = sorted(p for p in a.rules_dir.rglob("*") if p.suffix in (".yaml", ".yml"))
    kept, seen = [], set()
    stats = {"files": len(files), "rules_total": 0, "not_security": 0, "not_python": 0,
             "no_cwe": 0, "duplicate_renamed": 0, "unparsable_files": 0}
    manifest = []
    for f in files:
        try:
            doc = yaml.safe_load(f.read_text())
        except Exception:
            stats["unparsable_files"] += 1
            continue
        if not isinstance(doc, dict) or "rules" not in doc:
            continue
        for rule in doc["rules"] or []:
            stats["rules_total"] += 1
            meta = rule.get("metadata") or {}
            if meta.get("category") != "security":
                stats["not_security"] += 1
                continue
            if "python" not in [str(x).lower() for x in rule.get("languages", [])]:
                stats["not_python"] += 1
                continue
            cwe = meta.get("cwe")
            if not cwe:
                stats["no_cwe"] += 1
                continue
            if rule["id"] in seen:
                stats["duplicate_renamed"] += 1
                rule = dict(rule, id=f'{rule["id"]}__{f.parent.name}')
            seen.add(rule["id"])
            kept.append(rule)
            cwes = cwe if isinstance(cwe, list) else [cwe]
            manifest.append([rule["id"], f.relative_to(a.rules_dir).as_posix(),
                             "; ".join(str(c).split(":")[0] for c in cwes),
                             "; ".join(meta.get("subcategory", []) or []), meta.get("confidence", "")])
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(yaml.safe_dump({"rules": kept}, sort_keys=False, allow_unicode=True))
    with a.manifest.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["rule_id", "source_file", "cwe", "subcategory", "confidence"])
        w.writerows(sorted(manifest))
    stats["kept"] = len(kept)
    print(stats)


if __name__ == "__main__":
    main()
