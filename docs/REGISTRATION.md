# Offline registration files

The `registration` commands build unsigned Namecoin registration plans and
publicly verify completed signing results. They invoke no signer, vault, node
or network endpoint. They never take a private key, seed, device or credential.
A public result verifies transaction signatures and correlations; it does not
authenticate native completion, owner presence, a protected journal, chain
confirmation or permission to release a transaction.

Every option below is required exactly once. Options can occur in any order.
`--json` is bare; inline `--flag=value`, duplicate or unknown flags, positional
arguments and clock/config/signer overrides refuse. Filesystem paths must be
absolute and clean. Source bundle references name the source `bundle.json`
file. A directory or a naked manifest cannot replace it.

```sh
swarma-identity registration account-pin --request "$PWD/.temp/pin-input.json" --out-dir "$PWD/.temp/pin-bundle" --json
swarma-identity registration reserve --request "$PWD/.temp/reserve-input.json" --profile "$PROFILE" --profile-sha256 "$PROFILE_SHA256" --account-pin "$ACCOUNT_PIN" --account-pin-sha256 "$ACCOUNT_PIN_SHA256" --out-dir "$PWD/.temp/reservation" --json
swarma-identity registration request --request "$PWD/.temp/request-A-input.json" --profile "$PROFILE" --profile-sha256 "$PROFILE_SHA256" --account-pin "$ACCOUNT_PIN" --account-pin-sha256 "$ACCOUNT_PIN_SHA256" --out-dir "$PWD/.temp/request-A" --json
swarma-identity registration check-result --request "$PWD/.temp/check-A-input.json" --profile "$PROFILE" --profile-sha256 "$PROFILE_SHA256" --account-pin "$ACCOUNT_PIN" --account-pin-sha256 "$ACCOUNT_PIN_SHA256" --out-dir "$PWD/.temp/checked-A" --json
swarma-identity registration reveal --request "$PWD/.temp/reveal-input.json" --profile "$PROFILE" --profile-sha256 "$PROFILE_SHA256" --account-pin "$ACCOUNT_PIN" --account-pin-sha256 "$ACCOUNT_PIN_SHA256" --out-dir "$PWD/.temp/reveal" --json
```

`PROFILE` and `ACCOUNT_PIN` are independently selected public files. Their
`*_SHA256` variables are their independently retained lowercase SHA-256 file
commitments. Computing a hash of an untrusted supplied file does not establish
that selection. No mainnet policy, funding authority or native item is inferred
from an xpub, matching hash or transaction manifest.

## Input records

All records are recursively closed: required fields cannot be omitted, null,
case-aliased or duplicated, including escaped duplicate keys. UTF-8 and Unicode
escapes must be valid. Arrays described as pairs have exactly two ordered
entries. Decimal amounts are canonical unsigned decimal strings; integer fields
are JSON integers without signs, exponents or floating syntax. Times fit
nonnegative signed Unix seconds; transaction sizes and funding vout fit uint32;
process exit is 0..255. Hashes are 32-byte lowercase hex; request and sitting IDs
are also 32 bytes; openings are 20 bytes. Hex and base64 files have no whitespace.

The closed profile has `schema` =
`swarma-identity/registration-profile/1`, `network`, `genesis`, `policy`.
Supported network/genesis pairs are `namecoin-mainnet` /
`000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770`
and `namecoin-regtest` /
`0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206`.
The policy contains exactly these fields:

```json
{"revision":"example","per_tx_fee_cap_atoms":"100000","total_fee_cap_atoms":"400000","min_fee_rate_atoms_per_kvb":"1","max_fee_rate_atoms_per_kvb":"1000000","dust_relay_fee_atoms_per_kvb":"1000","created_at":0,"release_not_after":86400,"final_confirmations":1,"release_mode":"two-stage"}
```

This expired example illustrates field spelling, not a usable selected policy.
Revision is 1..128 UTF-8 bytes without control characters. Amounts/rates are
positive, at most 2100000000000000 atoms; fee caps are at most 100000 per
transaction and 400000 total, with total at least per-transaction. Minimum rate
cannot exceed maximum. The release interval is positive and at most 86400
seconds; confirmations are positive. Release mode is `two-stage` or
`all-four-before-release`. Fresh operations check the actual clock. There is
no public historical-clock argument, environment fallback or automatic retry.

| Command schema suffix (prefix `swarma-identity/registration-`, suffix `/1`) | Required fields after `schema` |
| --- | --- |
| `account-pin` | `group`, `account`, `account_xpub`, `master_fingerprint`, `account_path` |
| `reserve` | `funding`, `registrations`, `change_paths`, `fees_atoms` |
| `reveal` | `reservation_bundle`, `reservation_bundle_sha256`, `parents`, `reveal_values_pin`, `reveal_values_pin_sha256`, `change_paths`, `fees_atoms` |
| `request` | `plan_bundle`, `plan_bundle_sha256`, `slot`, `valid_for_seconds` |
| `check-result` | `request_bundle`, `request_bundle_sha256`, `result`, `result_sha256`, `stdout`, `stdout_sha256`, `process_exit` |

`account-pin` admits public account xpubs with verified checksum, curve, version,
depth and child index, fingerprint lowercase 4-byte hex, and exact account path
`m/84h/7h/0h`. Group/account use `<label>/recovery@<version>` and
`<label>/namecoin@<version>`: label 1..40 lowercase letters, digits or `-`,
version canonical decimal 1..2147483647. It emits the existing six-field
`keyvault-namecoin-account-pin/1` record, compact JSON without LF. It reports an
empty network; an xpub version does not select a network.

`reserve.funding` has `tx_hex`, `txid`, `vout`, `path`. Here `tx_hex` is a
filename containing exact lowercase full funding-transaction hex, not inline
hex. Registrations are ordered id/ then d/ with the same suffix. Each has
`name`, `name_output_path`, `fixed_value_hex`: empty for pending id/, exact
canonical public root-social or combined social/landlord value for d/.
`change_paths` and `fees_atoms` are pairs. All derivation paths are exact
`m/84h/7h/0h/{0,1}/index`, with non-hardened canonical decimal index < 2^31.
Reserve generates separate OS CSPRNG openings once and retains them in state.

`reveal.parents` is the ordered A/B pair. Each has `request_bundle`,
`request_bundle_sha256`, `result`, `result_sha256`, `stdout`, `stdout_sha256`,
`process_exit`. The source requests must bind the exact same reservation.
The reveal pin is an explicit file under the existing closed
`keyvault-namecoin-reveal-values/1` schema: `reservation_plan_sha256` and two
ordered `registrations` rows with `name_hex`, `value_hex`, `value_sha256`.
Both canonical values are checked; d/ must equal its original fixed bytes.
Source results are publicly verified before deriving parent references.

`request.slot` is A/B for a reservation, C/D for a reveal.
`valid_for_seconds` is an integer 1..600. The actual local clock sets preparation
time and expiry; separate OS CSPRNG request/sitting IDs are generated once.
Fresh requests refuse with `REGISTRATION_POLICY_REFUSED` when the requested lifetime or the release window remaining at the captured preparation time is less than 30 seconds.
The original full request and raw binary review frame are retained.

`check-result.result` and `stdout` are exact files from a normally exited call,
with independently recorded raw-byte hashes and actual exit. Nonzero exit,
malformed or mismatched ACK, invalid signature or receipt correlation refuses.
Supplying exit zero and an ACK never proves native provenance. This CLI makes
no signing call. An authentic retained completed result may verify after expiry;
a fresh request at that time still refuses. Missing original context cannot be
replaced by refreshed IDs, expiry, a manifest or a fabricated historical clock.

## Bundles and custody

Inputs must be current-user 0600 one-link regular files. Ancestors must be real
no-follow directories owned by root/current user with no group/world write or
special bits. Source bundle directories must be current-user 0700. Identity,
mode, links, size, mtime and ancestry are checked around freezing. This is not a
hostile same-user atomicity guarantee.

Output uses a fresh create-only 0700 directory, create-only 0600 files, fsync
and exact readback. `bundle.json` is written and read back last, followed by
directory fsync. Existing outputs and interruption leftovers are preserved;
there is no repair, overwrite, deletion or automatic resume. A crash-left index
must pass all payload, hash and reconstruction checks on later use.

The compact JSON plus LF index has fields, in order, `schema`
(`swarma-identity/registration-bundle/1`), `kind`, `profile_sha256`,
`account_pin_sha256`, `files`. Each ordered file commitment has `name`,
`size_bytes`, `sha256`. `bundle.json` is excluded from its own commitments.
For account-pin only, the profile hash is empty. Required payload order is:

| Kind | Payloads |
| --- | --- |
| `account-pin` | account-pin.json |
| `reservation` | profile.json, account-pin.json, funding.hex, reservation-state.json, reservation-manifest.json, A.psbt, B.psbt, transaction-index.json |
| `reveal` | profile.json, account-pin.json, reveal-state.json, reveal-values-pin.json, reveal-manifest.json, C.psbt, D.psbt, transaction-index.json |
| `request` | profile.json, account-pin.json, request-state.json, request.json, review-frame.bin |
| `checked-result` | profile.json, account-pin.json, verification-state.json, verified-transaction.hex, public-result.json |

New state/index/public-result records are compact JSON plus LF in declared
field order. Profile/pin/manifest/request snapshots are exact original bytes;
PSBTs are canonical base64 without LF, frames raw binary and final transaction
hex lowercase without LF. A bundle hash commits its exact index including LF.
A plan's domain-separated hash is a separate commitment.

Reservation state contains `schema`, `prepared_at`, `funding`, `registrations`,
`change_paths`, `fees_atoms`; `funding.tx_hex` becomes `funding.hex` and each
registration appends `rand_hex`. Reveal state has its request fields in the
same order, with state schema and `prepared_at` appended; pin becomes the local
`reveal-values-pin.json`. Other source references remain absolute.
Request state contains `schema`, `plan_bundle`, `plan_bundle_sha256`, `slot`,
`prepared_at`, `request_id`, `sitting_id`, `expires_at`, `request_sha256`,
`review_sha256`. Verification state has check-result fields with state schema.
The state schema suffixes are `reservation-state/1`, `reveal-state/1`,
`request-state/1`, `verification-state/1`, under the registration prefix.

Transaction index schema is `swarma-identity/registration-transactions/1` with
`transactions`: two ordered rows of `slot`, `txid`, `psbt_file`, `unsigned_vsize`,
`signed_vsize_min`, `signed_vsize_max`. Full plans, PSBTs and metadata are
reconstructed and compared; matching file hashes alone are insufficient.
Public-result schema is `swarma-identity/registration-public-result/1` with
`txid`, `signed_psbt_sha256`, `result_sha256`, `fee_atoms`, `weight`, `vsize`,
`reported_journal_sequence`, `reported_journal_head_sha256`. Reported journal
fields remain unauthenticated.

Only typed references are followed: request → reservation/reveal, reveal →
reservation and A/B request contexts, A/B request → reservation. Cycles and
wrong types/slots refuse; shared completed subgraphs are permitted. No
arbitrary JSON references or directory scans occur. Maximum depth is five
bundle-reference edges per path, with at most 128 distinct admitted files and
128 MiB frozen bytes per invocation, including selected files and construction.

| File | Maximum bytes |
| --- | ---: |
| Construction, state, index | 65536 |
| Selected profile | 4194304 |
| Account/reveal pin JSON | 16384 |
| Plan manifest | 1048576 |
| Funding hex / decoded transaction | 8388608 / 4194304 |
| Local request JSON | 8388608 |
| Local PSBT base64 / decoded PSBT | 8388608 / 4194304 |
| Result | 6291456 |
| Captured signer stdout | 256 |
| Raw review frame | 2097152 |

All limits apply together before output creation. Local storage limits do not
widen a future signing process's separate 2 MiB request / 1 MiB decoded PSBT
transport. Native signing and maximum canonical signed-result measurement
require their own implementation and qualification.

## Result envelope and refusals

The existing six-field JSON envelope is `schema`, `ok`, `command`, `network`,
`result`, `error`, followed by LF. A success result contains exactly
`bundle_sha256`, `files`, using the same ordered commitments as the index.
Success is emitted only after complete commit/readback. Network is empty for
account-pin; otherwise it is the successfully selected profile network, or
empty if profile selection did not complete. Failure has `result:null`,
`retryable:false`, and a fixed message with no paths or input bytes.

| Code | Exit | Fixed message |
| --- | ---: | --- |
| BAD_INPUT | 2 | The input does not satisfy the selected contract. |
| REGISTRATION_POLICY_REFUSED | 3 | The registration policy was refused. |
| REGISTRATION_PARENT_REFUSED | 3 | The registration predecessor context was refused. |
| REGISTRATION_RESULT_REFUSED | 3 | The registration result was refused. |
| REGISTRATION_FILES | 1 | The registration files could not be admitted or committed. |
| INTERNAL | 1 | The operation failed internally. |

Malformed argv, closed records and scalars are BAD_INPUT. Selected profile
hash/static-policy/current-window refusal is POLICY. Unsafe, unavailable,
oversize, hash-mismatched or failed-write/readback files are FILES. A hash-valid
substituted original context is PARENT. After restoration, invalid completed
result/ACK/signature/exit is RESULT. An earlier file-admission failure is not
replaced by a later semantic error. No signer wire errors are added or changed.
If stdout encoding fails, stderr is exactly `Could not write the result.` plus
LF and exit is 1; committed files remain in custody.

Run focused public-file and restoration checks with:

```sh
GOTOOLCHAIN=local go test -p 1 -run 'TestRegistration|TestRestore|TestRetained|TestFixedValue|TestWire' ./internal/facade ./internal/registration
```

The tests use isolated public fixtures, including test-only signatures derived
from published BIP32 vector 1 for random unsigned plans. Existing Core signatures
and eight frozen requests/full frames remain unchanged. They establish no
native, production funding, chain or release qualification.
