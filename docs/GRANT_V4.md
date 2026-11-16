# Grant v4: octet tooling, not a live issuer

This is a **partial implementation**, pinned to swarma-link-spec 0.1.53,
commit `3bef542fc8c0a5dedeeaaa990bd7f93abe194813`. It implements the document
pipeline of LIP-0020 sections 11–12, offline drafting, review, root contract
assents, external grant-signature assembly, and the defined root/by-key
preparation and anchor frame. It does not admit a grant, reserve a row,
consume a consent, build a funding transaction, or broadcast anything.

**Do not use this as a production issuer.** In particular, `keychain sign-v4`
signs ONLY a root contract assent, not a grant. There is deliberately no
private-key route for signing a v4 grant. Returning `admission_checked: false`
is not permission to omit the issuer's pre-sign duties.

## What is implemented

| Specification | Implementation |
| --- | --- |
| LIP-0020 W1–W6, W9.1–W9.3 | `internal/grantv4/wire.go`, `schema.go`, `grant.go` |
| W11.1–W11.8, including root/child member sets, J12 groups/ranges, J10 classes | `schema.go`, `grant.go` |
| W11.9 and every mandatory point of W11.10, including J9 no-certifier restrictions, stop runs and exact pool arithmetic | `grant.go` |
| W7.1–W7.5, root/by-key octet checks only | `issuance.go` |
| W8, W9.4, root/by-key octet checks and the version-2 anchor frame | `issuance.go` |
| LIP-0010 section 10 | Holders are not copied into the grant; a stated landlord value is displayed as unverified, not treated as a chain read |
| Heights-only window | `Heights`, `WithHeights`, and the optional draft calendar input |

The four proposal-only cases of W11.10 are accepted as well-formed documents:
this reader does **not** judge the proposed witness-key-hash restriction on
range/stop scripts or the proposed stop-placement restrictions. Mandatory
presence, index bounds and distinct stop outputs are always checked. This
choice is expressly permitted by section 12; it is not a grant-admission
policy. Seal scripts returned by this tool use the compressed seal key,
including its parity, to compute the witness key hash.

Refusals follow the specified order: document size and syntax/depth first;
then duplicates, null, numeric form, string form, canonical re-encoding;
then envelope, type, all member names, values, curve points, signature form,
parent/key selection, signature, references, grant shape and delegation
rules. A signature failure in a child is `CHILD_SIGNER`; a bad parent
reference is `WIRE_ID` before any signature check. Bounds apply to the
complete signed form, including when only the payload is being drafted.
An identifier excludes the signature; a content address includes it.

## Public file exchange

Every command requires `--json --request <regular-file>`. Existing v3
commands and their schemas are unchanged. The v4 exchange file is bounded
at 524288 bytes because hex of a maximum-size parent and child does not fit
the v3 64 KiB request limit. Each embedded document still has its own
protocol bound. Hex is lowercase; canonical document octets are not repaired.
Unknown, duplicate, aliased and cross-stage request members refuse.

Grant requests have `schema: "swarma-identity/grant-v4/1"`:

- `grant draft-v4`: `payload_hex`, optional `parent_hex` (a complete signed
  root), optional `calendar`. Returns canonical payload bytes, payload
  identifier, typed digest, signing public key, seal script and
  `admission_checked: false`. A child requires its checked parent.
- `grant consent-v4`: the draft inputs and `created_at` (Unix seconds).
  Returns an unsigned NIP-01 event template and the root issuer's typed
  assent payload/digest. Only root/by-key templates are supported. A
  consent time is never compared with a height.
- `grant sign-v4`: the draft inputs and `signature` from an **external**
  signer. This command verifies and attaches it; it never creates a
  signature. Returns signed bytes, their content address, and the draft
  values. The external signer must independently enforce the issuer's
  duties; this command does not establish that it did so.
- `grant anchor-v4`: `signed_hex`, `assent_hex`, `consent_hex`, explicit
  verifier clock `now`, optional `parent_hex`, `name_output`, `frame_hex`.
  Returns the preparation, its typed commitment, and the 72-byte anchor
  script with `dry_run: true, admission_checked: false`. It checks the
  grant, mode, assent and consent in W9.4 order, then a supplied candidate
  frame before its commitment. Child assent and by-name evidence are
  unsupported. No maximum consent age is applied at this verifier-only
  stage; issuer age and single use are separate duties.

`calendar` has exactly `current_height`, `start_after_seconds`,
`end_after_seconds`, and positive `target_block_seconds`. These are explicit
issuance estimates relative to the supplied current height, not an observed
chain clock. Start rounds up; end rounds down. An empty interval or overflow
refuses as `GRANT_SHAPE`. The resulting payload has only
`not_before_height` and `not_after_height`; no clock, timestamp, duration,
or target interval enters its bytes. Already malformed payloads refuse
before this local conversion.

Keychain requests have `schema: "swarma-keychain/v4/1"`, `payload_hex`,
optional `parent_hex`, and `landlord_value_hex`; commands also require
`--label <label>`:

- `keychain review-v4` checks the label's public key against the root grant
  key or the checked parent's delegation key, **before display**. It shows
  every preimage leaf (empty lists included), exact reconstructible payload
  bytes, typed-hash construction, the stated landlord value as unverified,
  and member-derived scope text last. It requests no confirmation or key
  authentication and creates no signature.
- `keychain sign-v4` accepts a root only. It additionally shows every member
  and byte of the root contract assent, explicitly says that only that
  assent will be signed, requires `SIGN`, asks for one key authentication,
  verifies the returned signature, and releases the signed assent. The
  request cannot supply a digest, free scope prose, purpose or batch.

The display is bounded by the 65536-byte grant, 520-byte stated value, at
most 8192 preimage leaves and 1048576 rendered bytes. Non-printable bytes
and backslashes are escaped. The scope is derived only from immutable
checked members; it assigns no invented meanings to the open action and
limit registries. Stating a landlord value, even one with the right public
key, proves nothing about a name on a chain.

## Unimplemented issuer duties and open points

1. The pin explicitly leaves the key assenting to a child's contract open
   (LIP-0020 section 7.1). The delegation key cannot be substituted: J4.2
   forbids it to sign an assent. Child assent and complete child issuance
   stop at this owner point.
2. A live child signer needs J4.4 own-node parent/row/closure checks and an
   authenticated caller listed for delegation. A supplied boolean or a
   public messaging signature would not provide these checks. None is
   implemented or claimed here.
3. A root grant signer also needs own-node issuer/recipient snapshot checks,
   issuer clock age, and durable consent consumption **before** a grant
   signature (W7.6, W7.8, W7.9). There is no private-key grant signing route
   until that integration is present. The later reservation ledger is not
   implemented. `keychainDeps.signApprovedV4` is the single private-key call
   a later service can wrap; today its only caller signs root assents.
4. A seal script is available in each draft, but a v4 seal/anchor transaction
   builder with live observation and linkage checks is not implemented. No
   v3 funding or seal profile is silently reused.
5. A cross-module consumer's fixture contract must be confirmed before
   claiming junction compatibility. Tests export public root/child bytes
   and verdicts for inspection, not a completed junction run.

## Tests and public fixtures

`internal/grantv4/testdata/grant-v4.json` is an unchanged copy of the pinned
public corpus (SHA-256
`66d4a5b1738b746bd5403e30ed1bbd30be9aac256a2559795d038f3455b2b106`).
Its keys are published test data and belong to nobody. Code and the standard
curve/hash libraries implement the reader; the Python checker is never
invoked by production code. Tests pin the whole corpus and fixed identities
outside it, assert all 112 outcomes (11 valid, 84 invalid, 13 compound,
4 proposal-only), all 19 refusal counts, all derived hashes/scripts, and
exact re-drafting of every valid vector. Replacing the corpus with one
regenerated under another key fails its independent literal pin.

The facade tests use the existing fake keychain, not the native store, and
assert display field counts of 30, 31, 81, 45, 22, 30, 21, 1511, 30, 80 and
293 for the eleven valid grants. They independently reconstruct displayed
payload bytes and verify that no validation refusal reads a private key.

For offline independent checking, set `GRANTV4_OUTPUT` to an output file
when running `TestVectors`. It exports the checker-format corpus with valid
documents independently re-drafted and reassembled. Set
`GRANTV4_ISSUED_DIR` to an existing directory for
`TestV4OfflinePreparation`: it exports an externally test-signed root in
checker format, a preparation and a provisional junction fixture. The
original child signature in that fixture is published vector data, not a
production child-signing claim. Run the pinned specification's
`python3 -I tools/grantv4/grantv4.py check <file>` on checker-format exports.
Tests make no external network requests. Native keychain coverage still
requires macOS; hosted CI cannot be inferred from a local Linux run.
