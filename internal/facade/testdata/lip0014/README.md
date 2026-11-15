# Depth-zero trust-contract fixtures

`depth-zero-vectors.json` is a selected, unmodified-object subset of
`vectors/LIP-0014/contract-vectors.json` from `relux-works/swarma-link-spec`
commit `2012ac9155568af80d610bdf9b7683881a46e5cb` (0.1.48).
The original file's SHA-256 is recorded in `source_sha256`; the subset file's
SHA-256 is `f5fabc272768026abb5e7631921ac4c2d59e4ef5b5901cc69e6a742212fefed2`.
It retains the four valid `/2` contracts with `delegate.depth == 0`:
contract-04 (root with exact scope text and escaped note), contract-06
(child ordinal 1), contract-07 (child ordinal 16), and contract-12 (child
with its own spend budget). The parser checks child syntax; issuance and
offline verification refuse children as `CONTRACT_DEPTH`, since the depth-one
parent and certification path are outside this implementation. No fixture
establishes an on-chain grant or permission to spend.

The exact `scope_text` string is copied from the source vector file. The
contracts, lengths, hashes, v3 scopes/budgets and booking hashes are upstream
goldens, not recomputed expected values from the implementation under test.
Published BIP-340 public keys are test data. Placeholder parent ids identify
no real grant. The subset does not claim all 190 upstream vectors: depth-one
rights, parent comparisons and notary certification are outside this slice.
The task explicitly requires `CONTRACT_FIELD` for unknown/duplicate members
and `CONTRACT_DEPTH` for a nonempty right, which differs from draft refusal
codes as documented in [GRANT.md](../../../../docs/GRANT.md).

`v1-cli-golden.json` captures the exact four newline-terminated `/1` CLI
result envelopes (draft, consent, grant_hash, signed) from a clean archive of
assigned base `eaa8523cafcfff90eec7d3d16066dcfd8f2c8dff`. A task-local test
using the base's existing `newFlow`, `flow.prepare`, `flow.finalRequest` and
published test signer produced the capture. Its SHA-256 is
`dcab4bc07324137a43bf820a90ecaadace050b42d17f19dd3cad87527344b8c6`.
Inputs are regtest, `id/landlord-a`, `id/landlord-a-agent`, all four actions,
repository `https://git.example/a/b`, budget 1000, and the existing
`regtestRequest` window, consent time and seal. Node replies are the existing
loopback fixture; no live node, keyvault or chain was used. The fixture
holds only public signatures and bytes, with no secret key material.

Run the focused checks with the repository's Go toolchain:

```sh
go test ./internal/facade -run '^TestTrustContractV2|^TestTrustContractV1' -count=1 -v
```

On the dev523 host, prefix every Go/gofmt invocation with:
`. /home/agent/Werkstatt/keeper-identity-trust2-dev/.goenv/env.sh &&`.
Test logs and isolated mutation overlays go under `.temp/`.
