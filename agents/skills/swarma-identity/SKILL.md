---
name: swarma-identity
description: Use the Swarma Identity CLI for Namecoin reads, public-account derivation, bounded UTXO scans, offline Nostr kind-0 preparation or public-signature verification, and two-phase trust-grant issuance (draft, consent, sign) with external signers. Signing keys and publication are separate capabilities.
---

# Swarma Identity

Use the repository-built `swarma-identity` CLI. Read [the CLI contract](../../../docs/CLI.md) for exact schemas and error codes. Build instructions are in [README](../../../README.md).

- Offline derivation: `swarma-identity address derive --request FILE --json`. Supply only a public xpub/tpub, explicit network, relative non-hardened path and finite range. It needs no node, relay or signer.
- Health: `swarma-identity node health --config FILE --json`.
- Raw name: `swarma-identity name show --config FILE --request FILE --json`. Exact value bytes are hex; this establishes no Link or identity authority.
- v3 identity: `swarma-identity identity show --config FILE --request FILE --json`. Gives `role` landlord, agent or none with keys and the agent's resolved landlord. Treat any present `reason` (`VALUE_NOT_V3`, `LANDLORD_NOT_V3`) as "not a usable v3 identity"; it is not a grant check.
- Current UTXOs: `swarma-identity balance watch --mode utxo-scan --config FILE --request FILE --json`. Require the node custodian's authorization to occupy its shared scan resource. Supply exactly branches `[0,1]`, P2WPKH and an explicit range of at most 1000 indices per branch.
- Unsigned profile: `swarma-identity nostr profile-prepare --request FILE --json`. Supply an explicit public x-only key, timestamp, kind0, ordered tags and JSON-object content text under the exact schema and limits in the CLI contract. The result includes canonical bytes as a UTF-8 string and an unsigned event, never a signature.
- Public profile verification: `swarma-identity nostr profile-verify --request FILE --json`. Supply the complete already-signed public event under the verification schema. Success binds its canonical fields, id and BIP-340 signature only; it establishes no relay publication, ownership, freshness, domain or identity authority.

- Trust grant, two-phase (see [the grant contract](../../../docs/GRANT.md)): `grant draft --config FILE --request FILE --seal-ledger ABS_FILE --json` builds the LIP-0013 contract and v3 fields and lists the digests to sign in `to_sign`; the grantee signs `consent_event_id` with its own signer; `grant consent --request FILE --json` verifies that consent; the landlord signs `contract_sha256`; `grant sign --config FILE --request FILE --seal-ledger ABS_FILE --json` without `grant_sig` returns `grant_signing_hash`; the landlord signs it; `grant sign` with `grant_sig` returns `signed_grant`, `grant_id` and `commitment`. Hand each signer the digest together with the exact public bytes it commits to, so the signer can render them and recompute the digest before signing: `consent_template` (NIP-01 serialization, giving `consent_event_id`) to the grantee's signer, `contract_b64` (SHA-256 gives `contract_sha256`) and `grant_b64` (the canonical unsigned grant behind `grant_signing_hash`) to the landlord's. Take back only public signatures. Never give this CLI a private key, a key file or a Keychain item; it has no option for one. The grant is not live until it is anchored and verified by the planned anchor and verify commands.

Both Nostr commands are offline, accept no config or signing flag and select no ambient key or timestamp. Content text and tag order are preserved. Check `EVENT_ID_MISMATCH` and `INVALID_SIGNATURE` as refusals with no partial result, never as `valid:false` successes. Keep public input files explicit; do not supply private keys or obtain a signature through this interface.

Online calls require an explicitly selected loopback Core 28.0 node and an existing owner-only credential file. Never inspect or paste credentials, place them in argv, discover another wallet or replace missing authorization with a test fixture. Keep account-specific request/result files in ignored local custody.

Check `ok` and the process exit code before using a result. A matched UTXO total is confirmed-only for the explicit range, not the entire xpub or a spendable balance; coinbase outputs can be immature. Read the returned coverage and observed tip. Missing/expired names and unavailable/unsynced nodes are refusals, not zero funds or absent identity.

For SCAN_BUSY or SNAPSHOT_CHANGED, report the refusal; the tool does not retry. SCAN_UNCERTAIN means the node may still be scanning: do not claim it stopped or launch a blind retry. Never send abort; this interface has no per-caller ownership token. No wallet import/rescan, transaction signing/broadcast, node lifecycle, Nostr publication or plugin registration interface exists in this slice. Route those requirements to their separately agreed implementations.
