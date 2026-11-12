# Public-data CLI contract

All commands require `--json`, accept long options once and write exactly one JSON envelope. Input/config files are read-only regular files of at most 64 KiB: one UTF-8 object, no duplicate decoded keys, unknown or case-aliased members, null required values or trailing JSON. Invalid Unicode surrogate escapes are rejected. Additional RPC fields are ignored; consumed RPC fields are validated.

## Configuration

Online commands require an explicit file:

```json
{
  "schema": "swarma-identity/config/1",
  "network": "main",
  "node": {
    "id": "local-node",
    "rpc_url": "http://127.0.0.1:8336",
    "auth_file": "/ABSOLUTE/CUSTODIAN-SELECTED/COOKIE",
    "genesis_hash": "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770",
    "rpc_profile": "namecoin-core-read/1"
  }
}
```

`network` is `main`, `test` or `regtest`; it must agree with the node's chain and explicitly selected genesis. Only Core version 280000 is admitted. A network label alone is not a genesis pin. Only literal loopback IPs or `localhost` are accepted; localhost is dialed at 127.0.0.1. HTTP(S) userinfo, query, fragment and non-root paths are refused. There is no ambient proxy or redirect following.

The auth file contains `username:password` (including the node's cookie format), optionally ending in one newline. It must be owner-only, owned by the executing user, regular, at most 4096 bytes, with no final symlink or additional hard link. Credentials stay out of results and diagnostics. The CLI neither discovers credential files nor grants permission to read an existing one. Optional `watch_wallet:{"name":"example","coverage":"wallet-visible"}` is reserved configuration; it enables no wallet operation in this version.

## Commands and requests

`node health --config FILE --json` returns `node_id,backend_version,genesis_hash,block_hash,blocks,headers,initial_block_download,verification_progress,connections`. An unsynced node is a valid health observation; name and balance operations refuse it.

`name show --config FILE --request FILE --json` accepts exactly `{"name":"d/example"}`. Names are 1..255 UTF-8 bytes and are sent without normalization. The RPC explicitly selects UTF-8 names, hex values and expired-record visibility. Active results contain `name,value_hex,expires_in,expired,txid,vout,height,observed_tip`. Hex values represent at most 520 bytes. Missing and expired names are distinct refusals. This raw read does not establish Link, Nostr, domain or identity authority.

Name reads compare the preflight tip hash with a hash sampled after `name_show`. A changed hash gives `SNAPSHOT_CHANGED`, including a reorganization at the same height. Equal endpoint hashes do not prove an atomic snapshot: the tip could move A → B → A between observations. This interface cannot detect every intermediate change and does not claim that it can. The provider's `expired` flag must equal `expires_in <= 0`; contradictory fields are `PROVIDER_PROTOCOL` before the final tip read.

`identity show --config FILE --request FILE --json` accepts exactly `{"name":"id/example"}` with the `name show` input rules and projects the record through the v3 (LIP-0004) value parsers `ParseLandlordIdentity` and `ParseAgentIdentity` of `github.com/relux-works/swarma-chain-lab/experiments/rental` at pseudo-version `v0.5.1-0.20261112085009-7ea1800ed187` (chain-lab commit `7ea1800`). Those parsers admit only canonical compact JSON of at most 520 bytes with valid x-only keys. The result always contains `name,role,value_hex,txid,vout,height,expires_in,observed_tip`, where `value_hex` is the exact value bytes. `role` and its members:

| `role` | Additional members |
| --- | --- |
| `landlord` | `grant_key`; `social:{key,relays}` when the value carries a `nostr` descriptor. |
| `agent` | `nostr_key`, `landlord` (the pointer), optional `social`; `landlord_resolved:{name,grant_key,social?,value_hex,txid,vout,height,expires_in}` when the pointer names an active v3 landlord, otherwise `reason:"LANDLORD_NOT_V3"`. |
| `none` | `reason:"VALUE_NOT_V3"`: the value is neither v3 shape, for example `{"nostr":{...}}` without a `swarma` member. |

`relays` lists the descriptor's relays for its root key in value order, or `[]`. A present `reason` means the record is not a usable v3 identity, including for `role:"agent"`; it is an observation, not a refusal. For an agent, the landlord is read with a second `name_show` between the same preflight tip and closing tip comparison; a missing, expired or non-landlord pointer target (including another agent or the agent itself) gives `LANDLORD_NOT_V3`. Any other failure of that second read is returned as its own refusal. Only one hop is resolved. Refusals and snapshot semantics are those of `name show`: `NAME_NOT_FOUND`, `NAME_EXPIRED`, `SNAPSHOT_CHANGED` and `PROVIDER_PROTOCOL` (including value hex that is malformed or longer than 520 bytes, for the target or the landlord). The projection establishes no grant, seal, rotation history or pending-mempool state.

`address derive --request FILE --json` works entirely offline:

```json
{
  "schema": "swarma-identity/derive/1",
  "network": "main",
  "xpub": "EXPLICIT_PUBLIC_XPUB",
  "relative_path": [0],
  "start": 0,
  "count": 20,
  "address_type": "p2wpkh"
}
```

Supply a valid public extended key, not the placeholder. Mainnet uses xpub serialization; test/regtest use tpub. BIP-32 public derivation accepts at most eight relative path components, count 1..100, and only exact non-hardened indices below 2^31. Invalid children refuse the request rather than advancing the requested index. No account or coin path is inferred. Results contain `address_type,addresses`; each row is `relative_path,index,public_key_hex,address`, without echoing the xpub. P2WPKH uses Bech32 v0 with a 20-byte program and HRP `nc`, `tn` or `ncrt`. P2PKH is also supported, with version 52 on mainnet and 111 on test/regtest. Private payloads, bad checksums, versions and curve points are refused.

`balance watch --mode utxo-scan --config FILE --request FILE --json` accepts:

```json
{
  "schema": "swarma-identity/scan/1",
  "network": "main",
  "xpub": "EXPLICIT_PUBLIC_XPUB",
  "branches": [0, 1],
  "start": 0,
  "count": 20,
  "address_type": "p2wpkh"
}
```

Mode defaults to `utxo-scan`; no alternate mode is substituted. Branches must be exactly `[0,1]`, count 1..1000 per branch, and the entire range must remain below 2^31. After public derivation and network/genesis/sync checks, exactly one `scantxoutset start` is sent with `wpkh(xpub/0/*)` and `wpkh(xpub/1/*)`, each with the explicit inclusive range. No caller-supplied descriptor or gap limit is accepted.

The result contains `mode,address_type,branches,start,count,matched_utxo_nmc_atoms,utxo_count,coinbase_utxo_count,observed_tip,coverage`. One atom is 10^-8 NMC. Amounts use exact decimal conversion and integer summation, bounded by 21 million NMC. All outpoints must be unique and match derived scripts. Incomplete scans, wrong totals, malformed amounts and changed snapshots emit no balance. A complete empty range returns legitimate zero. The tip object is `{"hash":"BLOCK_HASH","height":123}`.

Coverage is always:

```json
{
  "mode": "utxo-scan",
  "scope": "requested-descriptor-set",
  "confirmed_only": true,
  "complete_for_range": true,
  "entire_xpub": false,
  "history": false,
  "mempool": false,
  "spendability": "unassessed",
  "name_outputs": "excluded"
}
```

This is the matched current UTXO total, including immature coinbase when present. It establishes neither spendability nor funds outside the requested range. Name-prefixed outputs do not match plain P2WPKH scripts; read name state separately.

## Trust-grant issuance

`grant draft`, `grant consent` and `grant sign` issue a Grant v3 with a LIP-0013 `swarma-trust-contract/1` contract in two phases without any private key in the process. Their schemas, the signing flow, the seal ledger and their refusals are in [GRANT.md](GRANT.md). `grant ledger-recover --seal-ledger FILE --json` (offline) merges a seal-ledger temporary file left by an interrupted update back into the ledger; until it runs, draft and sign refuse as `LEDGER_FILE`. Named grant refusals exit 3.

## Offline Nostr profiles

These two commands accept `--request FILE --json` only, without `--config`, `--mode`, relay, signing or output-file options. They read no ambient configuration, key or timestamp and perform no network operations. Their envelope `network` is always `""`; `command` is `nostr profile-prepare` or `nostr profile-verify`.

### Prepare an unsigned event

`nostr profile-prepare --request FILE --json` accepts exactly these six required non-null fields:

```json
{
  "schema": "swarma-identity/nostr-profile-prepare/1",
  "pubkey": "LOWERCASE_64_HEX_PUBLIC_KEY",
  "created_at": 0,
  "kind": 0,
  "tags": [],
  "content": "{}"
}
```

Replace the placeholder with a valid 32-byte BIP-340 x-only curve point encoded as 64 lowercase hex characters. `created_at` is an explicit nonnegative decimal integer from 0 through 9007199254740991. Negative zero, signs, fractions, exponents, strings and booleans are refused. `kind` is a decimal integer from 0 through 65535; otherwise well-formed nonzero kinds give `UNSUPPORTED_CAPABILITY`.

The result has exactly `schema:"swarma-identity/nostr-profile-prepared/1",canonical_utf8,event`. The unsigned `event` has exactly `id,pubkey,created_at,kind,tags,content`, without `sig`. Decoding `canonical_utf8` once yields the exact message bytes hashed for `id`; outer JSON transport escaping does not change those decoded bytes. No signature or publication receipt is created.

### Verify a public signed event

`nostr profile-verify --request FILE --json` accepts exactly `schema:"swarma-identity/nostr-profile-verify/1",event`. The event has exactly seven required non-null fields: `id,pubkey,created_at,kind,tags,content,sig`. The shared fields follow the preparation rules; `id` is 64 lowercase hex characters and `sig` is 128 lowercase hex characters. Unknown event fields are refused.

The command validates all shapes, encodings, curve points and limits before refusing unsupported kinds. It then rebuilds the canonical bytes, compares the supplied id to their SHA-256 digest and verifies the BIP-340 signature against that computed digest and supplied public key. A wrong id gives `EVENT_ID_MISMATCH`, even when the signature is also invalid. A correct id with an invalid signature gives `INVALID_SIGNATURE`. Malformed signature hex is `BAD_INPUT`; correctly sized lowercase hex that fails signature parsing or verification is `INVALID_SIGNATURE`.

Success has exactly `schema:"swarma-identity/nostr-profile-verified/1",valid:true,id,pubkey,created_at,kind:0`. Invalid events have no partial result or `valid:false` success. Verification establishes only the binding of these event bytes, id and public signature. It establishes no publication, ownership, freshness, domain, .bit, NIP-05 or identity authority.

### Exact bytes and supported limits

These are local interface limits, not universal Nostr relay policy:

| Field | Accepted form and limit |
| --- | --- |
| Request file | One UTF-8 object, at most 65536 raw bytes; closed schema, unique decoded member names, no structural nulls or lone surrogate escapes. |
| Content | 2..16384 decoded UTF-8 bytes containing one complete JSON object. Arbitrary member values, including nested objects, arrays and null, are allowed. Duplicate decoded keys at any depth are refused. |
| JSON depth | Request and decoded metadata each use root depth0; each object value or array item adds one. Values beyond depth32 are refused. |
| Tags | Explicit array, at most128 tags; each tag has1..16 strings, each0..1024 decoded UTF-8 bytes; all strings together at most8192 bytes. Order, duplicates and arbitrary names are preserved. Null or non-string items are refused. |
| Tag controls | Of U+0000..U+001F, only BS, TAB, LF, FF and CR are accepted. Other valid Unicode, including DEL, is preserved. |
| Canonical message | At most32768 UTF-8 bytes, independently of the field limits. |

Content is retained byte-for-byte after outer JSON decoding, including its whitespace, member order, number lexemes and escape spelling. It is never trimmed, reserialized, filtered, normalized or dereferenced. A metadata member value `null` is valid; a null content field or root metadata `null` is invalid.

Following the pinned [NIP-01 serialization rule](https://github.com/nostr-protocol/nips/blob/98b57cf3e76f5de64a563350d437328e5d7a8f73/01.md), canonical bytes are compact UTF-8 `[0,pubkey,created_at,0,tags,content]`. Integers use decimal notation. Strings escape exactly LF as `\n`, quote as `\"`, backslash as `\\`, CR as `\r`, TAB as `\t`, BS as `\b` and FF as `\f`. Other admitted characters remain UTF-8, including `/`, `<`, `>`, `&`, non-ASCII, U+2028 and U+2029. There is no Unicode normalization or tag sorting. `id` is lowercase hex SHA-256 of those bytes, not of the outer envelope or reserialized metadata.

## Bounds and refusals

Ordinary operations are bounded by 15 seconds total, five seconds per RPC. A scan has a 300-second total bound: preflight at most ten seconds, one scan RPC at most 285 seconds, and at most five seconds for post-scan observation. Responses are bounded by 4 MiB and 128 sequential RPC calls. No automatic retry, scan status/abort, wallet import/rescan, signing, transaction or lifecycle RPC is available.

Every result has `schema:"swarma-identity/result/1",ok,command,network,result,error`. Success has `error:null`. Failure has `result:null` and `error:{code,message,retryable}`. Messages are fixed, sanitized text. `command` and `network` are empty strings when no valid selection could be established; arbitrary input is never echoed.

| Exit | Codes | Meaning |
| ---: | --- | --- |
| 0 | none | Complete successful observation. |
| 1 | INTERNAL | Internal or output failure. |
| 2 | BAD_INPUT | Invalid command, file, schema, key, range or selection. |
| 3 | WRONG_NETWORK, UNSUPPORTED_CAPABILITY, NODE_UNSYNCED, NAME_NOT_FOUND, NAME_EXPIRED, RPC_REFUSED | Selected operation is refused. |
| 3 | EVENT_ID_MISMATCH | The supplied event id does not match its canonical fields. |
| 3 | INVALID_SIGNATURE | The supplied event signature is not valid for its public key and event id. |
| 4 | RPC_UNAVAILABLE | Read unavailable; caller may try later. |
| 4 | SCAN_BUSY | Another scan owns the resource; caller may try later. No tool retry. |
| 4 | SNAPSHOT_CHANGED | Observations disagree; caller may try later. No scan replay. |
| 4 | SCAN_UNCERTAIN | A submitted scan has no confirmed response and may still be running. `retryable:false`; no abort or retry is sent. |
| 5 | PROVIDER_PROTOCOL | Malformed, oversized or inconsistent provider data; no partial result. |

Before-submission cancellation sends no scan. After submission, transport failure/cancellation is conservatively uncertain. Even after the process exits, the node may continue that scan. The API exposes no reliable caller-owned scan token, so the CLI never aborts it.

All Nostr refusals have `retryable:false` and `result:null`. Messages are fixed and include no raw event, request path or cryptography-library diagnostic.

## Validation limits

Published public BIP84 key/program vectors ground derivation tests; Bech32 family/HRP/case controls check the output instrument. Disposable loopback fixtures cover the RPC method fence, exact descriptors, pruned-node read shape, bytes, money and failure paths. Offline public-account qualification and a custodian-authorized live-node check are separate evidence. A passing fixture does not establish deployment, node custody, service freshness or a successful live scan.

Nostr checks combine frozen canonical byte/hash goldens, public BIP-340 true/false vectors and a pinned already-signed kind-0 fixture through the complete CLI. See [fixture provenance](../internal/facade/testdata/nostr/README.md). Public verification uses `github.com/btcsuite/btcd/btcec/v2/schnorr` at v2.3.5. No local signing round trip supplies expected results.

Reference specifications: [BIP-32 public derivation and vectors](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), [BIP-84 public key/program vectors](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki), [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki), [BIP-350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki), [Namecoin Core nc28.0 chain parameters](https://github.com/namecoin/namecoin-core/blob/nc28.0/src/kernel/chainparams.cpp) and [UTXO scan implementation](https://github.com/namecoin/namecoin-core/blob/nc28.0/src/rpc/blockchain.cpp).
