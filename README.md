# AI-Powered Vulnerability Detection and Secure Code Review System - cycle 1 baseline

Setup:
    pip install bandit==1.9.4 semgrep==1.182.1
    git clone https://github.com/semgrep/semgrep-rules.git && git -C semgrep-rules checkout 16b9e6d

Run (reproduces Figures 2-4 of Report #1):
    python3 prototype/scan_pipeline.py bench --rules semgrep-rules/python --labels bench/labels.csv --out results/findings.json

Unfiltered run (decision D6):
    python3 prototype/scan_pipeline.py bench --rules semgrep-rules/python --labels bench/labels.csv --include-non-security --out results/findings_unfiltered.json
