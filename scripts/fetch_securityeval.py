"""Fetch the SecurityEval dataset (Siddiq & Santos, MSR4P&S 2022) at a pinned
commit and prepare it as the EXTERNAL evaluation set.

* Cases: SecurityEval/Testcases_Insecure_Code/<CWE>/<id>.py (121 files, 69 CWEs).
* Labels: every case is labelled vulnerable by the dataset authors with the CWE of
  its folder (independent of this project). No sink lines are given, so this set is
  evaluated at FILE level only, and it contains no safe files (precision is undefined).
* 'pattern' column = the origin given in the file name (author, codeql, sonar, mitre,
  pearce). Samples taken from CodeQL / Sonar documentation may favour those tools;
  results are therefore also reported per origin.
The repository has no licence file, so the cases are not committed; this script
re-creates them from the pinned commit.
"""
import argparse
import csv
import shutil
import subprocess
from pathlib import Path

REPO = "https://github.com/s2e-lab/SecurityEval.git"
COMMIT = "6f4fb70"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", type=Path, help="existing SecurityEval clone (optional)")
    ap.add_argument("--out", type=Path, default=Path("datasets/securityeval"))
    a = ap.parse_args()
    src = a.src
    if src is None:
        src = a.out / "_clone"
        if not src.exists():
            subprocess.run(["git", "clone", "-q", REPO, str(src)], check=True)
    subprocess.run(["git", "-C", str(src), "checkout", "-q", COMMIT], check=True)
    cases = a.out / "cases"
    shutil.rmtree(cases, ignore_errors=True)
    rows = []
    for f in sorted((src / "Testcases_Insecure_Code").rglob("*.py")):
        cwe_dir = f.parent.name                      # e.g. CWE-089
        dst = cases / cwe_dir / f.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, dst)
        origin = f.stem.split("_")[0]
        rows.append([f"{cwe_dir}_{f.stem}", f"securityeval/{cwe_dir}/{f.name}", "vulnerable",
                     f"CWE-{int(cwe_dir.split('-')[1])}", "", origin])
    with (a.out / "labels_securityeval.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "path", "label", "cwe", "sink_lines", "pattern"])
        w.writerows(rows)
    print(f"{len(rows)} cases, {len({r[3] for r in rows})} CWEs -> {cases}")


if __name__ == "__main__":
    main()
