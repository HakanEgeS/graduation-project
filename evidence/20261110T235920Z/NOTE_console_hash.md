# Note on console.log and SHA256SUMS (added 11.11.2026)

In runner versions up to commit 0e083ae the final line "Evidence written to ..." (and the
blank line before it) was appended to console.log **after** SHA256SUMS had been computed.
Therefore `sha256sum -c SHA256SUMS` reports a mismatch for console.log only.

* Hash listed in SHA256SUMS (console.log without its last 2 lines): 50d9eaf628b1ff9f0dc572929e1334038085631609b11109f2e610b4648db443
* Recomputed hash of console.log without its last 2 lines:          50d9eaf628b1ff9f0dc572929e1334038085631609b11109f2e610b4648db443
* Hash of the complete console.log as committed:                     05169c1942602d06285774882cdc13044c156f269550fa5e19efe0a52971420c

All other files verify. The runner now closes console.log before hashing.
