# Read-only CLI contract

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

## Bounds and refusals

Ordinary operations are bounded by 15 seconds total, five seconds per RPC. A scan has a 300-second total bound: preflight at most ten seconds, one scan RPC at most 285 seconds, and at most five seconds for post-scan observation. Responses are bounded by 4 MiB and 128 sequential RPC calls. No automatic retry, scan status/abort, wallet import/rescan, signing, transaction or lifecycle RPC is available.

Every result has `schema:"swarma-identity/result/1",ok,command,network,result,error`. Success has `error:null`. Failure has `result:null` and `error:{code,message,retryable}`. Messages are fixed, sanitized text. `command` and `network` are empty strings when no valid selection could be established; arbitrary input is never echoed.

| Exit | Codes | Meaning |
| ---: | --- | --- |
| 0 | none | Complete successful observation. |
| 1 | INTERNAL | Internal or output failure. |
| 2 | BAD_INPUT | Invalid command, file, schema, key, range or selection. |
| 3 | WRONG_NETWORK, UNSUPPORTED_CAPABILITY, NODE_UNSYNCED, NAME_NOT_FOUND, NAME_EXPIRED, RPC_REFUSED | Selected operation is refused. |
| 4 | RPC_UNAVAILABLE | Read unavailable; caller may try later. |
| 4 | SCAN_BUSY | Another scan owns the resource; caller may try later. No tool retry. |
| 4 | SNAPSHOT_CHANGED | Observations disagree; caller may try later. No scan replay. |
| 4 | SCAN_UNCERTAIN | A submitted scan has no confirmed response and may still be running. `retryable:false`; no abort or retry is sent. |
| 5 | PROVIDER_PROTOCOL | Malformed, oversized or inconsistent provider data; no partial result. |

Before-submission cancellation sends no scan. After submission, transport failure/cancellation is conservatively uncertain. Even after the process exits, the node may continue that scan. The API exposes no reliable caller-owned scan token, so the CLI never aborts it.

## Validation limits

Published public BIP84 key/program vectors ground derivation tests; Bech32 family/HRP/case controls check the output instrument. Disposable loopback fixtures cover the RPC method fence, exact descriptors, pruned-node read shape, bytes, money and failure paths. Offline public-account qualification and a custodian-authorized live-node check are separate evidence. A passing fixture does not establish deployment, node custody, service freshness or a successful live scan.

Reference specifications: [BIP-32 public derivation and vectors](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), [BIP-84 public key/program vectors](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki), [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki), [BIP-350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki), [Namecoin Core nc28.0 chain parameters](https://github.com/namecoin/namecoin-core/blob/nc28.0/src/kernel/chainparams.cpp) and [UTXO scan implementation](https://github.com/namecoin/namecoin-core/blob/nc28.0/src/rpc/blockchain.cpp).
