# Re-check of the Report #1 Semgrep runtime (11.11.2026, 00:12-00:15 UTC)

Report #1 measured 118.88 s for Semgrep with the full pinned Python rule set on the
18-file benchmark. To find out why, the same scan was repeated in the same environment:

| Command | Wall time |
|---|---|
| Report #1 command: `semgrep scan --config semgrep-rules/python --json --metrics=off --quiet bench/dev` | 118.3 s |
| Same, version check off: `SEMGREP_ENABLE_VERSION_CHECK=0 semgrep scan ... --disable-version-check ...` | 22.0 s |

During the first command the session's egress proxy recorded refused connections to
`semgrep.dev:443` (00:12:42, 00:13:14, 00:14:19 UTC). Semgrep waited for its online
version check, which the measurement environment blocks. About 96 s of the Report #1
figure was therefore network waiting, not analysis. Both runs return the same findings
(compare the two JSON files). Since cycle 2 the runner disables the version check.
