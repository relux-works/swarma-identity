---
name: swarma-identity
description: Use the Swarma Identity CLI for Namecoin reads, public-account derivation, bounded UTXO scans and offline Nostr kind-0 preparation or public-signature verification. Signing and publication are separate capabilities.
---

# Swarma Identity

Use the repository-built `swarma-identity` CLI. Read [the CLI contract](../../../docs/CLI.md) for exact schemas and error codes. Build instructions are in [README](../../../README.md).

- Offline derivation: `swarma-identity address derive --request FILE --json`. Supply only a public xpub/tpub, explicit network, relative non-hardened path and finite range. It needs no node, relay or signer.
- Health: `swarma-identity node health --config FILE --json`.
- Raw name: `swarma-identity name show --config FILE --request FILE --json`. Exact value bytes are hex; this establishes no Link or identity authority.
- Current UTXOs: `swarma-identity balance watch --mode utxo-scan --config FILE --request FILE --json`. Require the node custodian's authorization to occupy its shared scan resource. Supply exactly branches `[0,1]`, P2WPKH and an explicit range of at most 1000 indices per branch.
- Unsigned profile: `swarma-identity nostr profile-prepare --request FILE --json`. Supply an explicit public x-only key, timestamp, kind0, ordered tags and JSON-object content text under the exact schema and limits in the CLI contract. The result includes canonical bytes as a UTF-8 string and an unsigned event, never a signature.
- Public profile verification: `swarma-identity nostr profile-verify --request FILE --json`. Supply the complete already-signed public event under the verification schema. Success binds its canonical fields, id and BIP-340 signature only; it establishes no relay publication, ownership, freshness, domain or identity authority.

Both Nostr commands are offline, accept no config or signing flag and select no ambient key or timestamp. Content text and tag order are preserved. Check `EVENT_ID_MISMATCH` and `INVALID_SIGNATURE` as refusals with no partial result, never as `valid:false` successes. Keep public input files explicit; do not supply private keys or obtain a signature through this interface.

Online calls require an explicitly selected loopback Core 28.0 node and an existing owner-only credential file. Never inspect or paste credentials, place them in argv, discover another wallet or replace missing authorization with a test fixture. Keep account-specific request/result files in ignored local custody.

Check `ok` and the process exit code before using a result. A matched UTXO total is confirmed-only for the explicit range, not the entire xpub or a spendable balance; coinbase outputs can be immature. Read the returned coverage and observed tip. Missing/expired names and unavailable/unsynced nodes are refusals, not zero funds or absent identity.

For SCAN_BUSY or SNAPSHOT_CHANGED, report the refusal; the tool does not retry. SCAN_UNCERTAIN means the node may still be scanning: do not claim it stopped or launch a blind retry. Never send abort; this interface has no per-caller ownership token. No wallet import/rescan, transaction signing/broadcast, node lifecycle, Nostr publication or plugin registration interface exists in this slice. Route those requirements to their separately agreed implementations.
