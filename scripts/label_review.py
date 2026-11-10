"""Independent review of the ground-truth labels.

make  : draws a stratified random sample (fixed seed) from the dev + holdout sets
        and writes, WITHOUT the labels,
          review/label_review_packet.md  - the code of each case with line numbers
          review/label_review_form.csv   - one row per case for the reviewer
score : compares the filled form with the labels and reports raw agreement and
        Cohen's kappa (vulnerable/safe), CWE agreement (exact/related/incorrect,
        cwe.agreement) and sink-line agreement.

  python scripts/label_review.py make  --n-vuln 10 --n-safe 5 --seed 2026
  python scripts/label_review.py score review/label_review_form_filled.csv
"""
import argparse
import csv
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from vulnreview import cwe as cwelib  # noqa: E402

LABELS = [ROOT / "bench/dev/labels_dev.csv", ROOT / "bench/holdout/labels_holdout.csv"]
FORM_COLS = ["review_id", "is_vulnerable (yes/no)", "cwe (e.g. CWE-89, blank if safe)",
             "vulnerable line number(s)", "confidence (1-3)", "comment"]


def all_labels():
    rows = []
    for p in LABELS:
        rows += list(csv.DictReader(p.open(newline="")))
    return rows


def make(a):
    rng = random.Random(a.seed)
    rows = all_labels()
    vul = [r for r in rows if r["label"] == "vulnerable"]
    safe = [r for r in rows if r["label"] == "safe"]
    sample = rng.sample(vul, a.n_vuln) + rng.sample(safe, a.n_safe)
    rng.shuffle(sample)
    out = ROOT / "review"
    out.mkdir(exist_ok=True)
    key = []
    md = ["# Label review packet", "",
          "For each case below, decide independently whether the code contains a security "
          "vulnerability. If yes, give the most specific CWE you can and the line number of the "
          "vulnerable statement (the sink). Fill one row per case in label_review_form.csv. "
          "Please do not look at the project repository, the labels or the tool results while reviewing. "
          "Case numbers are random and file names are hidden on purpose.", ""]
    with (out / "label_review_form.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(FORM_COLS)
        for i, r in enumerate(sample, 1):
            rid = f"R{i:02d}"
            key.append([rid, r["case_id"]])
            w.writerow([rid, "", "", "", "", ""])
            code = (ROOT / "bench" / r["path"]).read_text().splitlines()
            md += [f"## {rid}", "", "```python"]
            md += [f"{n:3d}  {line}" for n, line in enumerate(code, 1)]
            md += ["```", ""]
    (out / "label_review_packet.md").write_text("\n".join(md))
    with (out / "label_review_key.csv").open("w", newline="") as fh:
        csv.writer(fh).writerows([["review_id", "case_id"]] + key)
    print(f"{len(sample)} cases written to review/ (seed {a.seed})")


def kappa(pairs):
    n = len(pairs)
    po = sum(x == y for x, y in pairs) / n
    cats = {c for p in pairs for c in p}
    pe = sum((sum(x == c for x, _ in pairs) / n) * (sum(y == c for _, y in pairs) / n) for c in cats)
    return po, (po - pe) / (1 - pe) if pe < 1 else 1.0


def score(a):
    labels = {r["case_id"]: r for r in all_labels()}
    key = {r["review_id"]: r["case_id"] for r in csv.DictReader((ROOT / "review/label_review_key.csv").open())}
    pairs, cwe_agree, line_agree, n_both_vul = [], {"exact": 0, "related": 0, "incorrect": 0}, 0, 0
    rows = []
    for f in csv.DictReader(Path(a.form).open(newline="", encoding="utf-8-sig")):
        lab = labels[key[f["review_id"]]]
        rv = f[FORM_COLS[1]].strip().lower().startswith("y")
        lv = lab["label"] == "vulnerable"
        pairs.append((lv, rv))
        c, ln = "", ""
        if lv and rv:
            n_both_vul += 1
            c = cwelib.agreement(cwelib.norm(lab["cwe"]), [cwelib.norm(f[FORM_COLS[2]])])
            cwe_agree[c] += 1
            given = {int(x) for x in f[FORM_COLS[3]].replace(",", ";").split(";") if x.strip().isdigit()}
            ln = bool(given & {int(x) for x in lab["sink_lines"].split(";") if x})
            line_agree += ln
        rows.append([f["review_id"], lab["case_id"], lab["label"], "vulnerable" if rv else "safe", c, ln])
    po, k = kappa(pairs)
    print(f"cases: {len(pairs)}  raw agreement: {po:.3f}  Cohen's kappa: {k:.3f}")
    print(f"both vulnerable: {n_both_vul}  CWE {cwe_agree}  sink line agrees: {line_agree}/{n_both_vul}")
    for r in rows:
        print("  ", *r)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make")
    m.add_argument("--n-vuln", type=int, default=10)
    m.add_argument("--n-safe", type=int, default=5)
    m.add_argument("--seed", type=int, default=2026)
    s = sub.add_parser("score")
    s.add_argument("form")
    args = ap.parse_args()
    make(args) if args.cmd == "make" else score(args)
