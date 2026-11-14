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
- **Public-key substitution.** The compressed 33-byte public key is also stored as the value of a separate generic-password item: service `works.relux.swarma-identity.grant-key.pub`, the same label/account, data protection keychain, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, not synchronizable, with no biometry access control. This public data is read without interaction before the display. The protected secret item's `kSecAttrGeneric` retains the same public key. After confirmation and Touch ID, the signer derives the public key from the authenticated secret and requires it to equal **both** the separate public item and the authenticated `kSecAttrGeneric`. A swap is detected with `KEY_ITEM_INVALID` after Touch ID and before any signature is returned. A missing public item refuses with `KEY_PUBLIC_NOT_FOUND` before the display or Touch ID. The public item is not an authority to sign.
- **Signing something other than what was shown.** `keychain sign` re-derives each requested digest before showing anything, as the SHA-256 of the exact bytes the display then shows:
  - `contract_sha256` is the SHA-256 of the draft's contract bytes.
  - `grant_signing_hash` is the SHA-256 of `swarma-grant-v3` followed by the canonical grant (`rental.Grant.Canonical`), built from the draft, the grantee's verified consent event and the verified `landlord_sig`. rental's own `SigningHash` must give the same value, so a change to the signing construction fails closed.
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

Every secret-bearing value of one operation that this package names is a field of one heap-allocated `scratch`: the 32 key bytes, the scalar and its bytes, `aux`, `t`, `rand`, the RFC 6979 seed and HMAC_DRBG `K`/`V`, the nonce and its inverse, the products that mix the key into `s`, the ECDSA `s`, the bytes and running sum of each `k·G` multiplication, the k·G and d·G points, the SHA-256 and HMAC states that consume secret input, the signature bytes until they have verified, and the verifier's copy of the ECDSA `S`. Each SHA-256 state in the scratch holds the chaining value, the block buffer, the message schedule, the working variables a..h and the round temporaries T1/T2; the HMAC state also holds its padded key. The scalar multiplication by G (double-and-add), the inverse (Fermat, `k^(n-2)`), SHA-256, HMAC-SHA256 and the DER encoding are implemented in the package so that their state is in that struct. The scratch is wiped by a `defer` placed right after it is allocated, so it is cleared on every return path, a panic included.

The package's other named locals are not cleared, and they hold no secret-bearing value:
- public values: the digest being signed, `P.x`, `R.x`, `r` and the BIP-340 challenge `e`; the stored public key; the tag hashes computed at start-up;
- loop indices, the message bit length in `sum`, and the byte count in `write`;
- the 0/1 results of the range checks in `loadKey` and `nextNonce`;
- the DER length counters in `putDER` and `signECDSA`, which carry only the byte lengths of `r` and `s`;
- pointers: the parsed signature returned by the curve library (`sig` in `lowSVerifies`, `parsed` in `SchnorrVerifies`); the values it points to are the library's own copies, listed under [Residual memory](#residual-memory).

A signature is built in the scratch and verified there, and the package copies it out only if it verifies. Verifying it makes two kinds of copies. `lowSVerifies` copies the ECDSA `S` it checks against n/2 into `scratch.vs`, which the wipe clears on every path, refusal included. The library's parse and verification make their own copies, which are not cleared (Residual memory).

The values this tool owns, and where each is cleared:

| Value | Held in | Cleared by |
| --- | --- | --- |
| key bytes read from the Keychain or drawn by keygen | `scratch.secret` (the Keychain read writes straight into it) | `clear` right after `loadKey` in `withKey`; `wipe` after `Create` in `Keygen`; the deferred `wipe` on every path |
| the Keychain read result (`SecItemCopyMatching`'s CFData, our +1 object) | heap, allocated by the framework | `sk_release_read` overwrites its bytes before `CFRelease`, on every return path of `sk_secret` |
| the secret handed to `SecItemAdd` | a malloc block wrapped by a CFData with a wiping allocator | overwritten when the CFData is freed (`sk_wipe_free`) |
| d, bytes(d), aux, t, rand, RFC 6979 seed, K, V, k, k⁻¹, r·d+e / e·d, ECDSA s | `scratch` fields | deferred `wipe` |
| bytes and running sum of each k·G / d·G | `scratch.kb`, `scratch.acc` | at the end of `mulG`, and by `wipe` |
| SHA-256 / HMAC states that absorbed the key, `t`, or K: chaining value, block buffer, message schedule, working variables a..h, round temporaries T1/T2, HMAC padded key | `scratch.h`, `scratch.mac` (`hashState.h/x/w/v/t`, `hmacState.pad`) | deferred `wipe`; the HMAC pad also at the end of `start` |
| the signature before it verifies (returned or refused) | `scratch.out` | deferred `wipe`; the caller receives a copy only after verification |
| the verifier's copy of the ECDSA `S` (returned or refused signature) | `scratch.vs` | deferred `wipe` |

`TestScratchClearedOnEveryReturn` reads each scratch after the public call returned, on success and on every refusal path, and finds every field zero; it also checks that each field was in use before the wipe. `TestOwnedWorkingStateCleared` does the same for each SHA-256 state's schedule, working variables and round temporaries, the HMAC pad and `scratch.vs`, on success, verification refusal (BIP-340 through `SignSchnorr` with a fault injected after the key check; ECDSA through the same `withKey` and `signECDSA` with a foreign key), error returns and a panic after signing; it checks per case that those values were populated before the wipe. `TestHashCodeHasNoSecretLocals` checks at source level that `hashState.block`, `sum`, `write`, `reset`, `tagged`, `hmacState.start`, `finish` and `lowSVerifies` declare no named local other than the public ones listed above. The BIP-340 and RFC 6979 vector tests check that a signature refused for a foreign key was in `scratch.out` (and `scratch.s` and `scratch.vs`) and is zero after the wipe. On macOS CI, `TestTestKeychainRoundTrip` observes the Keychain read result all zero after `sk_release_read` wiped it. The implementation is pinned to the library by all BIP-340 signing vectors (0..3, 15..18), btcec's RFC 6979 vectors, a byte-for-byte comparison with `schnorr.Sign`/`ecdsa.Sign` on random inputs, and the DER encoding against `Signature.Serialize` at every minimal-encoding boundary.

### Residual memory

Temporaries inside the pinned curve library are **not** cleared, by decision. Clearing them would mean forking or reimplementing the field and group arithmetic, which this PR does not do. They are listed here precisely, with the reasoning that makes them an accepted limit, and the planned migration that closes them is recorded in `UNRESOLVED_QUESTIONS.md`.

Go gives no guarantee that any value is erased, and that includes the buffers this tool owns. The compiler may keep copies of a value in registers and spill them to stack slots, and the runtime copies a goroutine's stack when it grows. Source code can neither name nor clear those copies. Every clearing described in this document is therefore best effort: it overwrites the copies the code can reach, and it cannot prove that no other copy exists.

The library is `github.com/decred/dcrd/dcrec/secp256k1/v4` v4.4.0, reached through `btcec/v2` v2.3.5. The functions below receive secret-derived inputs from this package. They hold intermediates in multiword `FieldVal` (10×uint32) locals in their own frames and in registers, and never zero them:

- **`DoubleNonConst`** (`curve.go:623`). It is called 256 times per multiplication in `mulG`, on an accumulator that is the scalar's leading bits times G. It runs `doubleGeneric` (`curve.go:570`; locals `a, b, c, d, e, f` declared at `:596`) or `doubleZ1EqualsOne` (`:516`; the same six locals at `:542`).
- **`AddNonConst`** (`curve.go:473`), on the same accumulator in `mulG`, runs one of:
  - `addZ1AndZ2EqualsOne` (`:174`; `h, i, j, r, v, negJ, neg2V, negX3` at `:213-214`)
  - `addZ1EqualsZ2` (`:241`; `a, b, c, d, e, f, negX1, negY1, negE, negX3` at `:281-282`)
  - `addZ2EqualsOne` (`:313`; `z1z1, u2, s2` at `:338`, `h, hh, i, j, r, rr, v, negX1, negY1, negX3` at `:361-362`)
  - `addGeneric` (`:393`; `z1z1, z2z2, u1, u2, s1, s2` at `:417`, `h, i, j, r, rr, v, negU1, negS1, negX3` at `:443-444`)
- **`JacobianPoint.ToAffine`** (`curve.go:135`; `zInv, tempZ` at `:140`). It is called on d·G and on k·G, whose Jacobian Z depends on the scalar. It calls **`FieldVal.Inverse`** (`field.go:1511`; `a, a2, a3, a6, a9, a11, a22, a44, a88, a176, a220, a223` at `:1553`).
- The `FieldVal` primitives these call (`Mul`, `Mul2` at `field.go:832`, `Square`, `SquareVal`, `Add`, `Negate`, `Normalize`). Their 64-bit limb products (`m`, `t0`…) are held in registers and frame slots.
- **`ModNScalar`** arithmetic on d, k, k⁻¹, r·d+e and s:
  - `SetBytes` (`modnscalar.go:324`), `PutBytes` (`:429`) and `PutBytesUnchecked`
  - `Add` (`:496`), `Mul2` (`:816`), `Mul` (`:977`), `Square` (`:1003`) and `Negate` (`:1052`)
  - `reduce512` (`:653`), whose sixteen 64-bit product words are passed as parameters
- Verification of a signature in `scratch.out`: `schnorr.ParseSignature`/`Signature.Verify`, `ecdsa.ParseDERSignature`/`Signature.Verify`. These copy the signature into library values (the parsed ECDSA signature is heap-allocated). A verified signature is public. A refused one is not released, but these copies of it are not cleared.

Three neighbouring residuals are of the same kind:
- **Registers and spill slots of this package's own functions.** The SHA-256 working variables, round temporaries and schedule are fields of the scratch (above), not locals. The values of expressions on their way into the scratch (a Σ or σ term, a limb, a word loaded from it) are unnamed and live in registers. They may be spilled to the frame, and Go removes stores to dead locals, so source code cannot clear them. Built with Go 1.26.8, `(*hashState).block` has no stack locals on darwin/arm64 (`-gcflags=-S`: `locals=0x0`); on amd64 its 48-byte frame holds the state pointer, a pointer to the working variables and the loop index.
- **Stack copying.** When a goroutine's stack grows, the runtime copies it and frees the old one without zeroing it. The scratch is on the heap and is never copied. The frames above can be. Go's collector does not move heap objects.
- **Security.framework internals.** The framework handles the XPC request and reply buffers from which `SecItemAdd`'s input is encoded and `SecItemCopyMatching`'s result is decoded. This tool never receives a pointer to them.

Why this is accepted:
1. **The temporaries live only in short-lived frames of a one-shot process.** `swarma-keychain` signs inside one command invocation and exits as soon as it has written the single JSON envelope:
   - `run` in `internal/facade/cli.go` writes the envelope with one `Encode` to the unbuffered `os.Stdout`, then returns its exit code.
   - `main` in `cmd/swarma-keychain/main.go` passes that code straight to `os.Exit`. There are no deferred calls, no signal teardown and no further allocation.

   Between the last signature and the exit, the only work is verifying, hex-encoding and writing public data. No reference to a scratch remains after `withKey` returns. The process's memory then goes back to the kernel, which zero-fills pages before handing them to any process.
2. **Clearing them would not change the threat model.** While a signature is being made, the decrypted key is in this process's memory: the key bytes until `loadKey` returns, and the scalar d in the scratch for the whole operation. An attacker who can read this process's memory during signing can therefore read the key itself at that moment, so clearing library stack temporaries would not deny them anything. An attacker who cannot read the process's memory gets nothing from the temporaries either, and after the exit they no longer exist.

This argument depends on the process being one-shot. Any later use of `internal/keysign` in a long-running process (a daemon, an agent, a library linked into a server) invalidates it, and that use must first complete the planned migration below.

**Planned migration (owner decision, 2026-11-13).** Ivan decided to keep the current signer for now. Go gives no guarantee of erasing memory, so signing is planned to move to libsecp256k1 via cgo: `secp256k1_schnorrsig_sign32` and `secp256k1_ecdsa_sign`, which clear their own secret intermediates with `secp256k1_memclear`. The migration is not scheduled yet; the demo scale does not need it. It is recorded here and in `UNRESOLVED_QUESTIONS.md` so that it stays in view. The keyvault, once it is qualified, remains the later custody target (KEY-MAP K5): the key would then never enter this process.

Other limits:
- **Timing.** Like the btcec routines it replaces (`…NonConst`), the multiplication by G branches on the scalar's bits. The threat model above does not include a local timing attacker.

## Commands

### `keychain keygen --label NAME [--network main|test|regtest] --json`

`NAME` is 1..63 bytes of `[a-z0-9._-]`, starting with `[a-z0-9]`; the network defaults to `main`. The command first checks that Touch ID is usable (`BIOMETRY_UNAVAILABLE` otherwise) and that neither the public nor the protected secret item uses the label (`KEY_EXISTS`); in either case it draws no entropy and creates nothing. An existing public item reserves the label; if it is absent, a no-interaction secret query returning `errSecInteractionNotAllowed` (-25308) also means `KEY_EXISTS`, never `KEYCHAIN_ERROR`. It then generates the key from the OS CSPRNG, adds the protected secret and its public metadata, and adds the separate non-ACL public item. If the public add fails, it deletes the just-added secret without authentication and refuses. It re-reads only the separate public item without interaction, checks it against the generated public key, and returns:

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
- each requested purpose and digest, and the bytes the digest is the SHA-256 of: the contract bytes for `contract_sha256`; for `grant_signing_hash`, the domain prefix `swarma-grant-v3` (15 bytes, no terminator) followed by the canonical grant. Each is shown in two forms, both taken from the bytes that are hashed, never from the draft:
  - as committed fields: every value in the bytes, one line per value with its JSON path (`consent.consent_event.created_at = …`), empty arrays and objects included. For the grant this covers the nested consent event (`id`, `pubkey`, `created_at`, `kind`, every tag, `content`, `sig`), `consent.contract_sha256` and `consent.landlord_sig`;
  - verbatim, 64 bytes per line after the decimal offset, starting with the prefix. A byte outside printable ASCII would be shown as `\xNN`; canonical JSON has none.
- for `grant_signing_hash`, the consent time rule below: whether the signed consent's `created_at` equals the draft template's
- for a seal spend, every field the legacy SIGHASH_ALL digest commits to: the transaction version; every input's outpoint and sequence (decimal and hex), with the signed input marked; every prevout's script in hex (the signed input's is its script code) with its amount, its address where standard, and whether the amount was read from a previous transaction; every output's amount, address where standard, and script in hex; the locktime; the sighash type (`SIGHASH_ALL (0x01)`); and the unsigned txid, totals, fee and sighash. `TestSealDisplayCoversEverySighashField` derives these fields from the transaction and finds each in the display.

Free text, such as the contract note, is shown with control and non-ASCII characters escaped.

`TestKeychainDisplayCoversEveryPreimageField` takes PR 8's own output bytes (`contract_b64`, and `grant_b64` from `grant sign` stage `grant_hash`), checks that their SHA-256 (after the prefix) is the requested digest, lists every value in them with an independent JSON decoder, and requires the terminal transcript, captured at the first secret read, to show exactly that set of committed fields and the bytes verbatim. Planted controls that drop the nested consent `sig` from the display, hide the consent time difference, or omit the verbatim bytes each fail it.

**Consent time rule.** The grantee's consent event may carry a `created_at` other than the draft template's: `grant consent` accepts a complete event from a NIP-01 or NIP-07 signer, which stamps its own time ([GRANT.md](GRANT.md)). `keychain sign` accepts it too, because refusing would refuse that documented consent path; the event's id and signature are verified either way, and its time must be from 1 to `not_after` − 1. The time is part of the signed grant, so the display states it explicitly, read from the canonical grant: `consent time : <created_at> (<UTC>) equals the draft template`, or `… DIFFERS from the draft template <template time> (<UTC>)`. A changed `created_at` with the template's id is refused as `CONSENT_ID` before the display.

The result contains only the key's public data, `signatures:[{purpose,digest,signature}]` and, for a spend, `seal_spend:{input_index,sighash_type:"ALL",sighash,signature}`. The spend signature is DER followed by `01`; the input script is `<signature> <compressed_pubkey>`.

Refusal codes:

| Codes | Meaning |
| --- | --- |
| `KEY_NOT_FOUND`, `KEY_PUBLIC_NOT_FOUND`, `KEY_ITEM_INVALID` | The secret is missing, the separate public item is missing (before Touch ID), or either public copy disagrees with the authenticated secret (after Touch ID). |
| `KEY_MISMATCH`, `DIGEST_BINDING`, PR 8 codes | The request is not bound to this key and draft. |
| `SEAL_OUTPOINT_MISMATCH`, `SEAL_SCRIPT_MISMATCH`, `SEAL_SPEND_*` | The seal spend is not acceptable. |
| `NO_TERMINAL` | There is no controlling terminal. |
| `CONFIRMATION_DECLINED` | The human did not type `SIGN`. |
| `AUTH_CANCELED`, `AUTH_FAILED` | The Touch ID prompt was canceled or failed. |
| `KEYCHAIN_ENTITLEMENT` | See [Developer ID signing](#developer-id-signing-for-the-data-protection-keychain). |
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

The acceptance gate is Ivan's dry run on his Mac with a **Developer-ID-signed app bundle**: keygen, sign a fixture request, then delete both dry-run items. Only after that gate passes is the real key created. Build from the reviewed commit:

```sh
git clone https://github.com/relux-works/swarma-identity && cd swarma-identity
git checkout <reviewed commit>
mkdir -p .temp/bin
go build -o .temp/bin/swarma-identity ./cmd/swarma-identity
go run ./cmd/build-keychain-bundle /absolute/path/to/swarma-keychain-DevID.provisionprofile
KEYCHAIN_CLI="$PWD/.temp/SwarmaKeychain.app/Contents/MacOS/swarma-keychain"
```

1. **Dry run with a throwaway label, then the real key.** The dry run checks Touch ID and the entitlement path:
   ```sh
   "$KEYCHAIN_CLI" keychain keygen --label dryrun-2026-11 --json
   ```
   Expect public data only. Prepare a `swarma-keychain/sign/1` fixture request bound to this returned key (the request format above), then:
   ```sh
   "$KEYCHAIN_CLI" keychain sign --label dryrun-2026-11 --request .temp/dryrun-sign.json --json
   ```
   Read the display, type `SIGN`, and authenticate with Touch ID; check that the public signatures verify. Remove **both** dry-run items afterwards in Keychain Access, under the data protection ("iCloud"/"Local Items") section: "Swarma grant key dryrun-2026-11" (service `works.relux.swarma-identity.grant-key`) and "Swarma grant public key dryrun-2026-11" (service `works.relux.swarma-identity.grant-key.pub`). Their account is `dryrun-2026-11`. Deletion does not require reading the protected secret. Confirm both are gone. Then create the real key:
   ```sh
   "$KEYCHAIN_CLI" keychain keygen --label landlord-grant-1 --json
   ```
   Record `xonly_key`, `compressed_pubkey` and `p2pkh_address`. Nothing secret is printed.
2. **Build the new landlord value.** Extract the current `nostr` descriptor of `id/example-landlord` with `.temp/bin/swarma-identity name show` (`value_hex` → bytes → `.nostr`) into `social.json`, then:
   ```sh
   "$KEYCHAIN_CLI" value build --grant-xonly <xonly_key> --social-descriptor social.json --json
   ```
   Hand `value_hex` to the lead node. The lead node decodes it, runs `testmempoolaccept` and broadcasts the `name_update` once.
3. **Sign grants with the new key, after the name_update confirms.** Run `grant draft` and `grant consent` as before. Put the draft and the `to_sign` entries into a `swarma-keychain/sign/1` request and run:
   ```sh
   "$KEYCHAIN_CLI" keychain sign --label landlord-grant-1 --request req.json --json
   ```
   Read the display, type `SIGN`, and touch the sensor once per signature. `landlord_sig` goes into `grant sign`. The grant stage's `grant_signing_hash` goes into a second sign request with `consent_event` and `landlord_sig`. The seal-spend signature goes into the spend transaction's input script.

## Recovery

There is none. The item is device-bound and biometry-bound: it cannot be exported, it does not sync and it does not survive a Touch ID re-enrollment or a new Mac. If it is lost, deleted, or invalidated by enrolling a new fingerprint, the key is gone. The only remedy is a rotation: create a new key with `keygen`, then run `value build` and a `name_update` of `id/example-landlord` with the new x-only key, signed by the name's owner wallet. Grants issued under the old key remain verifiable against the chain history, but no new grant can be signed with it.

## Developer ID signing for the data protection keychain

**Entitlement decision closed, owner evidence 2026-11-13.** The ad-hoc `go build` binary returned `KEYCHAIN_ENTITLEMENT` (`errSecMissingEntitlement`, -34018) on Ivan's Mac (Darwin 27.2, Xcode 27, Go 1.26.8). Ivan chose option 1: sign with the Relux Works Developer ID. The bundle below passed `codesign --verify --strict`, and its `SecItemAdd` of the biometry-protected item succeeded. The subsequent protected public-key re-read failed with LAError -1004 → -25308; that separate product defect is addressed by the two-item layout above. This signing evidence closes the entitlement question, not the revised tool's Mac acceptance gate.

The verified provisioning setup is:

- Explicit macOS App ID `works.relux.swarma-keychain`, no capabilities, team `262RZ595FP`.
- Developer ID profile `swarma-keychain DevID`, `ProvisionsAllDevices`, `keychain-access-groups = 262RZ595FP.*`; Developer ID Application certificate serial `2480D282829042976C97FE6A3CF49F34`, expires 2031-07-06.
- `SwarmaKeychain.app/Contents/Info.plist` declares `CFBundleIdentifier = works.relux.swarma-keychain`, `CFBundleExecutable = swarma-keychain`, and `LSUIElement = true`.
- `Contents/MacOS/swarma-keychain` is the release binary; `Contents/embedded.provisionprofile` is the profile.
- Entitlements: `com.apple.application-identifier = 262RZ595FP.works.relux.swarma-keychain`, `com.apple.developer.team-identifier = 262RZ595FP`, and `keychain-access-groups = [262RZ595FP.works.relux.swarma-keychain]`.

From the repository root on the owner's Mac, with that profile and the installed Developer ID Application identity:

```sh
go run ./cmd/build-keychain-bundle /absolute/path/to/swarma-keychain-DevID.provisionprofile
# Optional second argument selects a new output .app path.
codesign --verify --strict .temp/SwarmaKeychain.app
.temp/SwarmaKeychain.app/Contents/MacOS/swarma-keychain keychain keygen --label dryrun-2026-11 --json
```

The command creates the bundle and entitlement plist under `.temp/` by default, builds without inherited Go test tags, and runs exactly:

```sh
codesign --force --options runtime --entitlements .temp/SwarmaKeychain.entitlements.plist \
  --sign "Developer ID Application: Relux Works, LLC (262RZ595FP)" .temp/SwarmaKeychain.app
codesign --verify --strict .temp/SwarmaKeychain.app
```

The owner/co-lead supplies the profile and signs on the Mac. Neither a signing certificate nor a private signing key is shipped in this repository. A bare ad-hoc build is not the sitting executable.

## Why hosted CI missed the defect

The owner's signed-build log showed a successful secret add, followed by a failed non-interactive attributes read. His attributes/reference-only probe found -25308 with an interaction-forbidden `LAContext`, while `kSecUseAuthenticationUISkip` hid the existing item as -25300. `SecItemDelete` succeeded without authentication. Thus even reading protected attributes or references requires authentication on that Mac; public metadata cannot be read from the protected item before the display.

Hosted macOS CI uses a throwaway **file** keychain with no biometry ACL. It checks the native two-item round trip and result wiping, but cannot establish this data-protection/biometry behaviour. `keychainfake.InteractionRequired` models every unauthenticated protected-item read as interaction-required. The positive test runs keygen then all signing paths in that mode. Five named negatives cover a protected-only duplicate (and a public-only duplicate), missing public item before Touch ID, swapped public item after Touch ID, failed public add with secret rollback, and swapped authenticated `kSecAttrGeneric`. The calibration restores the old protected-item public read and requires the same positive test to fail specifically with interaction-required, not a build error. The owner's signed-bundle dry run remains required.

## Tests

| Where | What |
| --- | --- |
| any platform | all BIP-340 signing vectors (0..3, 15..18) and btcec's RFC 6979 vectors through the package's own signers; byte-for-byte agreement with the library signers on random inputs; the DER encoder against the library's at every minimal-encoding boundary; the wipeable SHA-256/HMAC, k·G and inverse against the standard library and btcec; every scratch field zero after each signer call returns (success and refusal paths); a signature refused for a foreign key held only in the scratch and zero after the wipe; the binary exits with the result's code right after its one envelope; ECDSA low-S against the high-S twin; duplicate inputs refused in both encodings; supplied prevouts that disagree with a full previous transaction refused; every sighash-committed field in the display; every field of each BIP-340 digest's preimage in the pre-key-read display, derived from PR 8's bytes, with a re-stamped consent time shown as differing and three planted display omissions killed; the legacy sighash against an independent implementation; keygen refusals; display before key read; refusal on decline; 12 digest-binding refusals; seal-spend refusals and a PSBT positive control; secret scan over all outputs and fds; value build vector and refusals; binary closure |
| any platform, interaction-required fake | `TestKeychainInteractionRequiredKeygenSign`; five negatives `ExistingItem`, `MissingPublic`, `SwappedPublic`, `PublicAddRollback`, `SwappedGeneric` (each prefixed `TestKeychainInteractionRequired`); `TestKeychainInteractionRequiredCalibration` kills the old protected-public read. |
| macOS CI, tag `keychaintest` | a throwaway file keychain made by `security create-keychain` in the job (never the login keychain): store round trip, duplicate label, path guard; the Keychain read result wiped before release; keygen → sign → PR 8 `grant sign` end to end |
| macOS CI, release build | release-store preflight refuses on the runner (no biometry); a read-only lookup of a random label returns no item |
| CI Build step | release `swarma-keychain` and `swarma-identity` binaries do not contain the test keychain selector (positive control: the `keychaintest` build does) |
