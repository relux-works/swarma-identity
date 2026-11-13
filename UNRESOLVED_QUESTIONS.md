# Open product decisions

- Live qualification requires the node custodian to select the endpoint, credential-file path and finite read/scan scope. Unit fixtures establish no live-node permission.
- Supporting other Core versions or non-loopback transports requires separate capability and transport qualification.
- Wallet-visible balance requires a separately provisioned and qualified watch-only wallet; it is not implemented or automatically substituted.
- Node lifecycle, name transactions, Nostr/NIP-05 and Link validation require their own interaction contracts. The current raw-read commands establish none of those interfaces.
- `identity show` reports a v3 value problem as a result `reason` (`VALUE_NOT_V3`, `LANDLORD_NOT_V3`) with exit 0, following the v3 identity design. Whether consumers would rather receive a refusal for an agent whose landlord does not resolve is open.
- The design's register/show refusal names (`NAME_MISSING`) and exit codes (1 refusal, 2 retry) differ from this CLI's existing codes (`NAME_NOT_FOUND`, exit 3 refusal, exit 4 retry). `identity show` keeps the existing CLI codes.
- `grant draft` cannot output the grant signing hash, as the design table suggests: the canonical v3 grant contains the consent signature and `landlord_sig`, so the hash exists only after both. `grant sign` therefore runs twice (stage `grant_hash`, then `signed`), and the landlord signs twice. Whether the leads want one landlord review covering both digests (for example a single keyvault prompt) is a signer-UX question outside this CLI.
- `grant sign` does not read the seal on chain (existence, confirmation, unspent, P2PKH to the grant key); the read fence has no `gettxout`. The design puts this pre-check in `grant sign`; These commands check only the local seal ledger. Whether to add `gettxout` here or leave it to the planned `grant seal` and `grant anchor` commands is open.
- Grant refusals use this CLI's exit codes (3 refusal, 2 bad input, 4 retry), not the design's (1 refusal, 2 retry), as `identity show` does.
- G1-K Keychain grant key: the release store writes to the data protection keychain, the only one with `SecAccessControl` biometry. Whether macOS lets an unsigned (ad-hoc) `go build` binary add an item there is not established. CI run 43322768154 shows only that such a binary's read-only lookup returns `KEY_NOT_FOUND`, not `errSecMissingEntitlement`. If Ivan's dry-run keygen returns `KEYCHAIN_ENTITLEMENT`, the options are:
  1. Sign `swarma-keychain` with Ivan's Apple developer team and a `keychain-access-groups` entitlement.
  2. Use the login file keychain with an in-process Touch ID gate. This is weaker, because macOS would not enforce the gate.

  Choosing one is a decision for Ivan and the leads.
- G1-K `keychain sign` takes a digest only together with the draft it binds to, so the landlord signs twice per grant (`contract_sha256`, then `grant_signing_hash`). Each signature asks for Touch ID separately.
- G1-K signer memory hardening (tracked, not scheduled). The arithmetic temporaries inside the pinned curve library (secp256k1 v4.4.0 `DoubleNonConst`, `AddNonConst`, `ToAffine`, `FieldVal.Inverse` and `ModNScalar` locals) are not cleared. `docs/KEYCHAIN.md` "Residual memory" accepts them for the one-shot `swarma-keychain` process only. The options for closing it are:
  1. Sign through libsecp256k1 via cgo, which clears its own secret intermediates with `secp256k1_memclear`. This adds a C dependency and its build and review.
  2. Sign in the keyvault once it is qualified, so the key never enters this process.

  It becomes required before `internal/keysign` is used in any long-running process. Choosing between the options is a decision for the leads.
