# GS Evidence Bundle — check us without trusting us

This directory is the verification bundle for a 12-source healthcare-price serve
(70,046,940,655 bytes of publisher machine-readable files, served losslessly at byte
identity). Everything here exists so that **a stranger holding one row can check it with
bytes we hand them and published roots — without trusting our code, our receipts, or us.**

## The three checks you can run yourself

### A. Inclusion — "is this row really in the release?"

Pick any packet in `packets/`. Each carries one served row, its index, the tree size, an
audit path, and the published root. Verify with the included verifier:

    python gs_merkle_roots.py --verify packets/packet_<source>_<kind>.json

or with ~20 lines of your own code: RFC 6962 §2.1 exactly — leaf hash =
`SHA256(0x00 || row_bytes)`, interior node = `SHA256(0x01 || left || right)`, recombine
along the path (index decides sides), require the walk to consume the whole tree, compare
to `root_sha256`. The verifier here reads ONLY the packet — no file of ours, no network.

All 24 roots (one per source × {partition, rates} — never a combined root) are in
`gs_merkle_roots_receipt.json`.

### B. The witnessed release — "did this release exist, when, says who?"

`gs_release_manifest.json` binds the 12 source identities, every tool, and the serve
closure. Its hash is timestamped by a third party (RFC 3161, FreeTSA):

    openssl ts -verify -digest $(sha256sum gs_release_manifest.json | cut -c1-64) \
      -in witness/gs_epoch1.tsr -CAfile witness/freetsa_cacert.pem \
      -untrusted witness/freetsa_tsa.crt

The token's timestamp is the TSA's clock, not ours. The manifest carries no self-written
clock — the epoch instant IS what the token asserts.

### C. Source bytes — "does any of this trace to the publishers?"

Per source, `closure/` carries the link-1 evidence: the **publisher's own integrity
fact** — zip central-directory CRCs, gzip trailer CRC32+ISIZE written by the publisher's
compressor, an Akamai ETag MD5, or a live re-fetch match. Where the publisher still serves
the identical file (e.g. `hosp-westoahu`), the receipt names the URL: fetch it yourself,
`sha256` it, compare to the `member_sha256` in the manifest.

## Clean-room commissions (`gs-commissions/…`, sibling directory)

Implementations written by **separate clean-room sessions from published specs alone** —
enforced input closure in their own code (every local file open tripwired; HTTP the only
data channel), committed here with their receipts. They exist to kill the "you wrote the
checker" objection: the recovery lands on the same hashes without our code.

## Limits — what this bundle does NOT prove

- **Inclusion is membership, not fidelity.** A perfectly built tree over wrong data
  verifies perfectly. Fidelity evidence is check C (publisher facts) plus the per-lane
  byte-exact capture receipts.
- **The roots are unsigned.** Tamper-evidence against a root you already hold, yes;
  non-repudiation of who published it, no — signing is a separate deliberate step.
- **The serve itself binds 127.0.0.1** — this bundle is the checkable evidence, not a
  public API.
- **Publisher cycles rotate monthly.** A rotated cycle's URL cannot be re-fetched; the
  embedded facts (B/C) remain checkable against the captured bytes' hashes.
- Full per-receipt boundaries live in each receipt's own `does_NOT_prove` field — every
  green in this system is required to name its equivalence level and its limits.

## Inventory

| path | what |
|---|---|
| `gs_release_manifest.json` (+ `.sha256`) | the release identity — sources, tools, serve closure, succession |
| `witness/` | RFC 3161 token(s) + the pinned TSA/CA certs |
| `gs_merkle_roots_receipt.json` | the 24 per-source roots (leaf law stated in-receipt) |
| `gs_merkle_roots.py` | builder + prover + **verifier** (`--verify` is packet-only) |
| `packets/` | 24 ready-to-verify inclusion packets (one per source × artifact) |
| `closure/` | per-source wire-closure recoveries + link-1 outside-fact receipts |
| `../gs-commissions/` | clean-room commission implementations + receipts |
