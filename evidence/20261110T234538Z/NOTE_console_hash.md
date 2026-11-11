# Note on console.log and SHA256SUMS (added 11.11.2026)

In runner versions up to commit 0e083ae the final line "Evidence written to ..." (and the
blank line before it) was appended to console.log **after** SHA256SUMS had been computed.
Therefore `sha256sum -c SHA256SUMS` reports a mismatch for console.log only.

* Hash listed in SHA256SUMS (console.log without its last 2 lines): 666ec500b4bc49f46f65d26fd90c1628d8a0538aeec8889971b802a0f2d2104f
* Recomputed hash of console.log without its last 2 lines:          666ec500b4bc49f46f65d26fd90c1628d8a0538aeec8889971b802a0f2d2104f
* Hash of the complete console.log as committed:                     b357f307a780d7e6df23fc0a879accf98f0a9314395e99b804a1a21a57df8b98

All other files verify. The runner now closes console.log before hashing.
