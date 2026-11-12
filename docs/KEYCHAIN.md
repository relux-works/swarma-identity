# Keychain grant key (G1-K)

The landlord grant key signs BIP-340 grant digests and the ECDSA P2PKH spend of a grant's seal. It is a secp256k1 key, and the Secure Enclave holds only P-256 keys. On a Mac the key is therefore a software key: a Keychain generic-password item that is read under Touch ID for each signature (decision D2). This document covers the `swarma-keychain` binary that holds that key, and `value build`, which publishes it.

## Binaries and the custody boundary

| Binary | Links a signer | Commands |
| --- | --- | --- |
| `swarma-identity` | no (PR 8 invariant, checked by `TestBinaryHoldsNoSigner` and `TestKeychainBinaryClosure`) | all read/grant commands, `value build`; `keychain *` refuses `UNSUPPORTED_CAPABILITY` |
| `swarma-keychain` | yes: `internal/keysign` over `internal/keychain` | `keychain keygen`, `keychain sign`, `value build` |

`internal/keysign` is the only product code that ever holds the secret. `internal/facade` handles parsing, digest binding, display, confirmation and signature verification, and it never sees the secret. The Keychain code is compiled only for darwin with cgo against Security.framework and LocalAuthentication. On any other platform, `keychain` commands refuse with `UNSUPPORTED_CAPABILITY`.

## Threat model

The setup protects against:
- **Key exfiltration from the Mac by other processes.** The item is stored in the data protection keychain under `SecAccessControl` with `biometryCurrentSet` and `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, and it is not synchronizable. Every read needs a Touch ID match from the fingerprints enrolled when the item was created; enrolling a new finger invalidates the item. The item never leaves this device: it is not in iCloud Keychain or in backups that restore to another device.
- **Signing something other than what was shown.** `keychain sign` re-derives each requested digest from the draft before showing anything:
  - `contract_sha256` must equal the draft's contract hash.
  - `grant_signing_hash` is recomputed from the draft, the grantee's verified consent and the verified `landlord_sig`.
  - The seal spend must spend exactly the draft's seal outpoint from P2PKH(this key).

  A digest that is not bound this way is refused with `DIGEST_BINDING` (or the PR 8 refusal code) before the display, so a modified request cannot borrow an approval.
- **Approving by accident or by script.** The display and the confirmation use the controlling terminal (`/dev/tty`), not stdin or stdout. Only the exact line `SIGN` approves; anything else is `CONFIRMATION_DECLINED`, and no key read happens. Each signature then asks for Touch ID separately: a fresh `LAContext` is used with no reuse window and is invalidated after the read.
- **A swapped or corrupted item.** The public key is stored beside the secret, in `kSecAttrGeneric`. A secret that does not derive that public key is refused (`KEY_ITEM_INVALID`). Every signature is verified against the stored key before output, and the seal-spend input must also execute under the standard script flags (strict DER, low-S).
- **Secret disclosure by the tool.** No flag, environment variable or path makes either command print or write the secret. Output is one JSON envelope with public data and signatures only. Tests scan stdout, stderr, the terminal transcript and the process's file descriptors 1 and 2 for every encoding of the secret, and a control proves the scanner detects a planted secret.

It does not protect against:
- Malware running as Ivan that waits for a legitimate Touch ID approval and races the terminal. The display binds what is signed, not who asked.
- A compromised macOS or a compromised `swarma-keychain` build. Build the tool from a reviewed commit on the Mac itself.
- Loss of the item. There is no export and no backup; see [Recovery](#recovery).

### Secret material in memory

`internal/keysign` does not call the library signers. btcec v2.3.5's `schnorr.Sign` copies the private scalar and its bytes into locals it never clears, and the ECDSA path (`ecdsa.Sign` → RFC 6979 in dcrd secp256k1 v4.4.0) leaves the key in the HMAC input buffer and HMAC state and takes the nonce inverse through `math/big`. The package instead implements BIP-340 signing (with fresh 32-byte `aux_rand` from the OS CSPRNG per signature) and RFC 6979 low-S ECDSA itself, over btcec's `ModNScalar` and `JacobianPoint` primitives, and verifies every result with the library's `schnorr` / `ecdsa` verification before it leaves the package.

Every secret-bearing value of one operation lives in one heap-allocated `scratch`: the 32 key bytes, the scalar and its bytes, `aux`, `t`, `rand`, the RFC 6979 seed and HMAC_DRBG `K`/`V`, the nonce and its inverse, the products that mix the key into `s`, the bytes and running sum of each `k·G` multiplication, the k·G and d·G points, and the SHA-256 and HMAC states that consume secret input. The scalar multiplication by G (double-and-add), the inverse (Fermat, `k^(n-2)`), SHA-256 and HMAC-SHA256 are implemented in the package so that their state is in that struct. The scratch is wiped by a `defer` placed right after it is allocated, so it is cleared on every return path. `TestScratchClearedOnEveryReturn` reads each scratch after the public call returned, on success and on every refusal path, and finds every field zero; it also checks that each field was in use before the wipe. The implementation is pinned to the library by all BIP-340 signing vectors (0..3, 15..18), btcec's RFC 6979 vectors, and a byte-for-byte comparison with `schnorr.Sign`/`ecdsa.Sign` on random inputs.

What this does not reach, stated as limits of Go:
- **Library stack frames and registers.** The field and scalar arithmetic (`ModNScalar.Mul2`/`Square`/`Add`, `FieldVal` operations inside `AddNonConst`, `DoubleNonConst` and `ToAffine`) and the package's own SHA-256 round function work on intermediates in their own stack frames and in CPU registers. Go offers no way to clear another frame or the register file. These are arithmetic intermediates, not a whole copy of the key or the nonce, but they are derived from them and are left until the stack is reused.
- **Stack copying.** When a goroutine's stack grows, the runtime copies it and frees the old one without zeroing it. The scratch is on the heap, so it is not copied; the intermediates above can be.
- **The heap.** Go's collector does not move objects, so the scratch is not duplicated by the GC, and it is zero before it becomes garbage. Freed memory is not zeroed until reused.
- **Timing.** Like the btcec routines it replaces (`…NonConst`), the multiplication by G branches on the scalar's bits. The threat model above does not include a local timing attacker.
- **The Keychain read.** The buffer passed to `SecItemAdd` is wiped when it is freed. The copy that Security.framework returns from a read is released without being overwritten, because the framework owns it; the Go copy made from it is the scratch's key bytes.

## Commands

### `keychain keygen --label NAME [--network main|test|regtest] --json`

`NAME` is 1..63 bytes of `[a-z0-9._-]`, starting with `[a-z0-9]`; the network defaults to `main`. The command first checks that Touch ID is usable (`BIOMETRY_UNAVAILABLE` otherwise) and that no item uses the label (`KEY_EXISTS`); in either case it draws no entropy and creates nothing. It then generates the key from the OS CSPRNG, stores it, re-reads the stored public key, and returns:

```json
{"label":"…","network":"main","xonly_key":"<64 hex>","compressed_pubkey":"<66 hex>","p2pkh_address":"N…/M…"}
```

### `keychain sign --label NAME --request FILE --json`

```json
{
  "schema": "swarma-keychain/sign/1",
  "draft": { "...": "the draft record from grant draft (swarma-trust/draft-record/1)" },
  "to_sign": [ {"signer":"landlord","key":"<x-only>","purpose":"contract_sha256","digest":"…"} ],
  "consent_event": { "...": "required for grant_signing_hash: the event from grant consent" },
  "landlord_sig": "required for grant_signing_hash",
  "seal_spend": {
    "tx_hex": "<unsigned tx, no witness>", "input_index": 0,
    "prevouts": [ {"script_hex":"…","amount_sat":0,"prev_tx_hex":"optional full previous tx"} ]
  }
}
```

- `to_sign` entries are copied from PR 8's output: `grant draft` and `grant consent` give `contract_sha256`, and `grant sign` stage `grant_hash` gives `grant_signing_hash`. Only `signer:"landlord"` entries are accepted, and their key must be this item's key. The draft's `issuer_key` must also be this key, otherwise the request is refused with `KEY_MISMATCH`.
- `seal_spend` is optional and takes exactly one of two forms:
  - `tx_hex` with one prevout per input. A legacy sighash does not commit to amounts, so the display marks those amounts as supplied by the request. A prevout may carry `prev_tx_hex`, the full previous transaction; it must hash to the input's txid, and its output must have exactly the supplied script and amount (`SEAL_SPEND_PREVOUTS` otherwise). The display then marks that amount as read from the previous transaction.
  - `psbt_b64` with no `prevouts`. Every PSBT input must carry its full previous transaction, whose hash must equal the outpoint's txid; the amounts are then verified. A witness UTXO given beside it must agree with that output in amount and script (`SEAL_SPEND_PREVOUTS` otherwise).

  The transaction must be unsigned, must not spend any outpoint twice (`SEAL_SPEND_DUPLICATE_INPUT`, checked before any amount is summed) and must not create value. The input at `input_index` must be the draft's seal outpoint, and its prevout must be P2PKH to this key.
- `to_sign` may be empty only when `seal_spend` is present.

The terminal shows the following before the confirmation prompt:
- the label, the key and its P2PKH address
- the network and genesis
- the landlord, the agent, and the grantee key and name
- the scope and budget
- the window, as unix times and in UTC
- the contract SHA-256, actions, repos and note
- the seal outpoint
- each requested purpose and digest
- for a seal spend, every field the legacy SIGHASH_ALL digest commits to: the transaction version; every input's outpoint and sequence (decimal and hex), with the signed input marked; every prevout's script in hex (the signed input's is its script code) with its amount, its address where standard, and whether the amount was read from a previous transaction; every output's amount, address where standard, and script in hex; the locktime; the sighash type (`SIGHASH_ALL (0x01)`); and the unsigned txid, totals, fee and sighash. `TestSealDisplayCoversEverySighashField` derives these fields from the transaction and finds each in the display.

Free text, such as the contract note, is shown with control and non-ASCII characters escaped.

The result contains only the key's public data, `signatures:[{purpose,digest,signature}]` and, for a spend, `seal_spend:{input_index,sighash_type:"ALL",sighash,signature}`. The spend signature is DER followed by `01`; the input script is `<signature> <compressed_pubkey>`.

Refusal codes:

| Codes | Meaning |
| --- | --- |
| `KEY_NOT_FOUND`, `KEY_ITEM_INVALID` | The item is missing, or it does not hold the stored key. |
| `KEY_MISMATCH`, `DIGEST_BINDING`, PR 8 codes | The request is not bound to this key and draft. |
| `SEAL_OUTPOINT_MISMATCH`, `SEAL_SCRIPT_MISMATCH`, `SEAL_SPEND_*` | The seal spend is not acceptable. |
| `NO_TERMINAL` | There is no controlling terminal. |
| `CONFIRMATION_DECLINED` | The human did not type `SIGN`. |
| `AUTH_CANCELED`, `AUTH_FAILED` | The Touch ID prompt was canceled or failed. |
| `KEYCHAIN_ENTITLEMENT` | See [Open item](#open-item-code-signing-for-the-data-protection-keychain). |
| `SIGNATURE_VERIFY` | A produced signature did not verify. |

### `value build --grant-xonly HEX --social-descriptor FILE --json`

The descriptor file is exactly the `nostr` member of the current landlord value, for example `{"names":{"_":"<social x-only>"},"relays":{"<social x-only>":["wss://…"]}}`. Unknown or duplicate members are refused with `BAD_INPUT`. The grant key must be a lowercase, valid x-only key (`LANDLORD_KEY`). The relay rules follow chain-lab (`NOSTR_KEY`, `NOSTR_RELAYS`, `NOSTR_RELAY_URL`), and the value is limited to 520 bytes (`LANDLORD_VALUE`).

The rendered value is accepted only when all of these agree with the intended key and descriptor:
- the repo's v3 reader (`classifyV3`)
- `rental.ParseLandlordIdentity`
- a strict re-decode and re-encode
- chain-lab's own `CombinedLandlordValue`

Any difference is `VALUE_MISMATCH`. The result is `{value,value_hex,bytes,grant_key,social:{key,relays}}`. `value_hex` is what the lead node passes to `name_update`.

## Ivan's sitting

Nothing below runs before the sitting. Build the tool on Ivan's Mac from the reviewed commit:

```sh
git clone https://github.com/relux-works/swarma-identity && cd swarma-identity
git checkout <reviewed commit>
mkdir -p .temp/bin && go build -o .temp/bin/swarma-keychain ./cmd/swarma-keychain && go build -o .temp/bin/swarma-identity ./cmd/swarma-identity
```

1. **Dry run with a throwaway label, then the real key.** The dry run checks Touch ID and the entitlement path:
   ```sh
   .temp/bin/swarma-keychain keychain keygen --label dryrun-2026-11 --json
   ```
   Expect public data only. Remove the dry-run item afterwards in Keychain Access, under the data protection ("iCloud"/"Local Items") section; search for "Swarma grant key dryrun-2026-11". Then create the real key:
   ```sh
   .temp/bin/swarma-keychain keychain keygen --label ivanopcode-grant-1 --json
   ```
   Record `xonly_key`, `compressed_pubkey` and `p2pkh_address`. Nothing secret is printed.
2. **Build the new landlord value.** Extract the current `nostr` descriptor of `id/ivanopcode` with `.temp/bin/swarma-identity name show` (`value_hex` → bytes → `.nostr`) into `social.json`, then:
   ```sh
   .temp/bin/swarma-keychain value build --grant-xonly <xonly_key> --social-descriptor social.json --json
   ```
   Hand `value_hex` to the lead node. The lead node decodes it, runs `testmempoolaccept` and broadcasts the `name_update` once.
3. **Sign grants with the new key, after the name_update confirms.** Run `grant draft` and `grant consent` as before. Put the draft and the `to_sign` entries into a `swarma-keychain/sign/1` request and run:
   ```sh
   .temp/bin/swarma-keychain keychain sign --label ivanopcode-grant-1 --request req.json --json
   ```
   Read the display, type `SIGN`, and touch the sensor once per signature. `landlord_sig` goes into `grant sign`. The grant stage's `grant_signing_hash` goes into a second sign request with `consent_event` and `landlord_sig`. The seal-spend signature goes into the spend transaction's input script.

## Recovery

There is none. The item is device-bound and biometry-bound: it cannot be exported, it does not sync and it does not survive a Touch ID re-enrollment or a new Mac. If it is lost, deleted, or invalidated by enrolling a new fingerprint, the key is gone. The only remedy is a rotation: create a new key with `keygen`, then run `value build` and a `name_update` of `id/ivanopcode` with the new x-only key, signed by the name's owner wallet. Grants issued under the old key remain verifiable against the chain history, but no new grant can be signed with it.

## Open item: code signing for the data protection keychain

Biometry access control exists only in the data protection keychain. macOS may require a keychain-access-group entitlement there, which an ad-hoc `go build` binary does not have. In that case, writing the item fails with `errSecMissingEntitlement` (-34018), which the tool reports as `KEYCHAIN_ENTITLEMENT`.

Evidence so far, from hosted CI run 43322768154 on macOS 15: an ad-hoc-signed test binary's read-only lookup of a random label in the data protection keychain returned `KEY_NOT_FOUND`, not the entitlement error. Whether `SecItemAdd` with the biometry access control succeeds for an unsigned binary is not established, because CI has no Touch ID and never writes there. The dry run in step 1 settles it. If keygen returns `KEYCHAIN_ENTITLEMENT`, the binary needs to be signed with an entitlement (see `UNRESOLVED_QUESTIONS.md`).

## Tests

| Where | What |
| --- | --- |
| any platform | all BIP-340 signing vectors (0..3, 15..18) and btcec's RFC 6979 vectors through the package's own signers; byte-for-byte agreement with the library signers on random inputs; the wipeable SHA-256/HMAC, k·G and inverse against the standard library and btcec; every scratch field zero after each signer call returns (success and refusal paths); ECDSA low-S against the high-S twin; duplicate inputs refused in both encodings; supplied prevouts that disagree with a full previous transaction refused; every sighash-committed field in the display; the legacy sighash against an independent implementation; keygen refusals; display before key read; refusal on decline; 12 digest-binding refusals; seal-spend refusals and a PSBT positive control; secret scan over all outputs and fds; value build vector and refusals; binary closure |
| macOS CI, tag `keychaintest` | a throwaway file keychain made by `security create-keychain` in the job (never the login keychain): store round trip, duplicate label, path guard; keygen → sign → PR 8 `grant sign` end to end |
| macOS CI, release build | release-store preflight refuses on the runner (no biometry); a read-only lookup of a random label returns no item |
| CI Build step | release `swarma-keychain` and `swarma-identity` binaries do not contain the test keychain selector (positive control: the `keychaintest` build does) |
