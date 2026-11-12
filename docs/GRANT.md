# Trust-grant issuance: `grant draft`, `grant consent`, `grant sign`, `grant ledger-recover`

These commands issue a Grant v3 (LIP-0004) whose contract is a
`swarma-trust-contract/1` document (LIP-0013). They follow the general CLI
rules in [CLI.md](CLI.md): `--json`, long options once, strict closed input
files of at most 64 KiB, and exactly one result envelope.

## Key custody

The CLI never reads, holds or asks for a private key. It produces the exact
bytes and the 32-byte digests that each party signs with its own signer, for
example a Secure Enclave keyvault with a Touch ID review per signature, a Mac
Keychain item or a NIP-07 extension. It then verifies the returned public
BIP-340 signatures and assembles the grant. No request member, option or
result carries a key or a key location. The shipped binary does not link the
test signer, and no product source file uses a signing or private-key API.
`TestBinaryHoldsNoSigner` checks both.

## Flow

| Step | Command or signer | Signs | Message (32 bytes) |
| --- | --- | --- | --- |
| 1 | `grant draft` (online) | nobody | builds the contract, the v3 fields and the consent template |
| 2 | grantee's signer | grantee key | `consent_event_id`: the NIP-01 id of the kind-8181 consent event |
| 3 | `grant consent` (offline) | nobody | verifies the consent and outputs the signed event |
| 4 | landlord's signer | landlord grant key | `contract_sha256`: the raw contract hash, which becomes `landlord_sig` |
| 5 | `grant sign` without `grant_sig` (online) | nobody | returns stage `grant_hash` with the canonical unsigned grant |
| 6 | landlord's signer | landlord grant key | `grant_signing_hash`: SHA-256(`swarma-grant-v3` ‖ canonical grant) |
| 7 | `grant sign` with `grant_sig` (online) | nobody | returns stage `signed`: the signed grant, `grant_id` and the commitment |

The grant signing hash cannot be produced at draft time. The canonical v3
grant contains the consent event with its signature and `landlord_sig`
(`rental.Grant.Consent`), and `Grant.Validate` verifies `landlord_sig` before it
encodes anything. So the hash exists only after steps 2 and 4. Every step lists
the digests it expects next in `to_sign`, as `{signer, key, purpose, digest}`.
`key` is the x-only public key that must sign.

Each command re-checks everything the earlier steps produced. The draft record
is never trusted as given.

## `grant draft --config FILE --request FILE --seal-ledger FILE --json`

```json
{"schema":"swarma-trust/draft/1","network":"regtest","landlord_name":"id/landlord","agent_name":"id/landlord-agent",
 "grantee_key":"<64 hex>","grantee_name":"id/optional","actions":["instruct","review"],"repos":[],"spend_budget":0,
 "not_before":1794528000,"not_after":1797120000,"note":"","seal":{"txid":"<64 hex>","vout":0},"consent_created_at":1794527000}
```

`network` is `main` or `regtest`. It must equal the config network, whose
genesis must be the pinned genesis of that network. `grantee_name` is
optional v3 metadata. `consent_created_at` is the template's `created_at`: at
least 1 and below `not_after`. The command reads no ambient clock. A verifier
refuses consent from its future, so choose a time that has passed by the time
the grant is verified.

Checks, in order:

1. The contract is built from the request and must pass LIP-0013 section 2.3.
   Its code is returned on failure, for example `CONTRACT_ACTIONS`.
2. The seal must be absent from the seal ledger.
3. `identity show` reads the agent and its landlord under one tip observation.
   The agent must be a v3 agent (`AGENT_NOT_V3`) whose landlord pointer is
   `landlord_name` (`AGENT_LANDLORD_MISMATCH`). That landlord must be an active
   v3 landlord (`LANDLORD_NOT_V3`). The landlord's current grant key becomes
   `issuer_key`.

The result is `{draft, contract, to_sign, observed_tip}`. `draft` is the record
for the next steps:
`{schema:"swarma-trust/draft-record/1", network, genesis, landlord_name, agent_name, issuer_key, grantee_key, grantee_name?, contract_b64, contract_sha256, scope, budget, not_before, not_after, seal, consent_template}`.
`contract_b64` is the exact contract bytes. `contract` shows the same contract
as fields, for review. `consent_template` is
`{id, pubkey, created_at, kind:8181, tags, content:""}`, with the four LIP-0013
tags `t`, `contract`, `booking` and `privacy`. `to_sign` lists the grantee's
`consent_event_id` and the landlord's `contract_sha256`. Draft creates no file.

## `grant consent --request FILE --json`

```json
{"schema":"swarma-trust/consent/1","draft":{…},"consent_sig":"<128 hex>"}
{"schema":"swarma-trust/consent/1","draft":{…},"consent_event":{"id","pubkey","created_at","kind","tags","content","sig"}}
```

Give exactly one of the two forms. A bare `consent_sig` is a BIP-340 signature
over the drafted id. A complete event, for example from a NIP-01 or NIP-07
signer, may carry its own `created_at`. The command is offline. It re-checks
the draft record against its contract (below), then the consent:

| Check | Refusal |
| --- | --- |
| The event `pubkey` is the grantee key | `CONSENT_SIGNER` |
| Kind 8181, empty content, exactly the four LIP-0013 tags | `CONSENT_BINDING` |
| `created_at` from 1 to `not_after` − 1 | `CONSENT_TIME` |
| The id is the NIP-01 id of the fields | `CONSENT_ID` |
| A valid BIP-340 signature by the grantee key over the id | `CONSENT_SIGNATURE` |

The result is `{consent_event, contract, to_sign}`. `consent_event` is the
verified signed event that `grant sign` takes. The envelope `network` is the
draft's network.

## `grant sign --config FILE --request FILE --seal-ledger FILE --json`

```json
{"schema":"swarma-trust/sign/1","draft":{…},"consent_event":{…},"landlord_sig":"<128 hex>","grant_sig":"<128 hex, optional>"}
```

Checks, in order: the draft record, the consent, the seal ledger, then a fresh
`identity show` of the agent and landlord.

- The on-chain grant key must equal the draft's `issuer_key`. A draft whose
  key was replaced, or a key rotated on chain after the draft, refuses as
  `LANDLORD_KEY_MISMATCH`.
- `landlord_sig` must be a valid BIP-340 signature by the on-chain key over
  `contract_sha256` (`LANDLORD_SIGNATURE`).
- The grant is built (budget omitted when 0), bound to its contract under
  LIP-0013 section 2.5, and checked with `rental.Grant.Validate`. Its codes
  pass through unchanged.

Without `grant_sig`, the result has stage `grant_hash`:
`{stage, grant_signing_hash, grant_b64, to_sign, contract_b64, observed_tip}`.
`grant_b64` is the canonical unsigned grant.

With `grant_sig`, which must verify against the on-chain key over that hash
(`GRANT_SIGNATURE`), the signed grant is encoded and accepted by
`rental.ParseSignedGrant`. The result has stage `signed`:
`{stage, grant_signing_hash, signed_grant, signed_grant_b64, grant_id, commitment, contract_b64, observed_tip}`.

- `signed_grant_b64` is the exact signed-grant bytes.
- `grant_id` is their SHA-256 (`SignedGrant.ID`).
- `commitment` is `rental.IssuanceCommitment`, the value the issuance
  `OP_RETURN` carries.

The seal is recorded in the ledger before the result is written.

## Seal ledger

`--seal-ledger` names the issuer's local ledger. It must be an absolute, clean
path with no symlink in any component (`LEDGER_FILE` otherwise). On macOS,
`/tmp` and `/var` are symlinks to `/private/tmp` and `/private/var`, so a
ledger there must be named by its resolved `/private/...` path; paths under a
home directory are normally already resolved. Every directory on the path must
be readable by the issuer.

The CLI opens the ledger's directory from `/` one component at a time, each
relative to the directory before it and without following symlinks, and does
every later step relative to that directory handle. The ledger itself must be
an owner-only regular file with one link.

- `grant draft`, and `grant sign` without `grant_sig`, only read the ledger
  and never create anything. A missing ledger reads as empty. They hold a
  shared `flock` on the verified directory handle while they check for
  leftover temporary files and read the ledger, so they wait for a final sign
  in progress (at most the 15-second bound) and never read its intermediate
  state.
- `grant sign` with `grant_sig` holds an exclusive `flock` on the verified
  directory handle itself, from before it reads the ledger until its result
  is written. The lock belongs to the directory inode, so renaming or
  replacing a name in or above the directory cannot move it to another
  writer. No lock file is used; a `<ledger>.lock` left by an earlier version
  is ignored. After taking the lock the command checks that the path still
  names the same directory; otherwise it refuses as `LEDGER_FILE`.
- The lock wait follows the caller. Attempts are non-blocking and repeat
  every 10 ms until the lock is free, the caller's context is done, or the
  15-second total bound of `grant sign` is reached; that bound also covers
  the node reads. A sign that gives up refuses as `LEDGER_FILE` with no
  result and writes nothing.
- A new seal is committed by writing the whole ledger to the writer's own
  temporary file `.<ledger name>.tmp-<16 random lower-case hex digits>`,
  created exclusively and without following symlinks in the same directory,
  syncing it, and then swapping it with the ledger in one atomic exchange
  (`renameat2` with `RENAME_EXCHANGE` on Linux, `renameatx_np` with
  `RENAME_SWAP` on macOS), relative to the locked directory handle. The
  ledger that the exchange displaces stays whole under the temporary name.
  The commit stands only if the ledger name then denotes this writer's file
  (device and inode) and the displaced file is the ledger it read under the
  lock. Otherwise the sign exchanges the two names again, which puts the
  displaced ledger back, checks that the ledger name denotes it again, and
  refuses as `LEDGER_FILE` with no grant released; the committed history and
  every `SEAL_REUSED` refusal stay as they were. The first record, with no
  ledger yet, is renamed onto the ledger name only while that name is free
  (`RENAME_NOREPLACE`, `RENAME_EXCL`), and a file that is not the writer's
  own is renamed back off it, so no ledger is left. After a commit that
  stands, the displaced ledger is removed, the directory is synced and the
  path must still name the locked directory. Until the exchange the committed
  ledger is untouched, so a failed write (for example `ENOSPC`) or an
  interrupted update leaves the previous ledger in force. A writer removes
  only its own temporary file: before the exchange and after a verified undo
  it holds the writer's uncommitted ledger, and after a commit that stands it
  holds the ledger the writer read, every entry of which is in the new
  ledger. A temporary file whose undo was not verified is kept. No command
  other than `grant ledger-recover` removes a temporary file it did not
  create, and no name outside the exact pattern is touched.
- A kernel, platform or file system without the atomic exchange or the
  no-replace rename refuses every final sign as `LEDGER_FILE` (fail closed);
  there is no plain-rename fallback. Linux needs `renameat2` with exchange
  support in the file system (ext4, xfs, btrfs and tmpfs have it; some
  network and FUSE file systems do not). macOS needs a volume with
  `RENAME_SWAP` (APFS and HFS+ have it). Platforms other than Linux and
  macOS have no exchange implementation and refuse.
- The ledger file is created by the first recorded seal. A missing ledger is
  a new ledger. An existing ledger must be a complete ledger document whose
  entries this CLI writes: at least one entry, a lower-case hex `txid` and
  `grant_id` in each, and no seal or `grant_id` recorded twice. An empty or
  truncated file, an empty `grant_id` or any other entry outside that shape
  refuses as `LEDGER_FILE` (fail closed) at every step, never reads as a free
  seal, and nothing is recorded until the owner repairs the ledger.
- Recovery fence. A writer stopped between its exchange and the undo (a
  kill, or an undo defeated by a concurrent change) leaves the previous
  ledger under the temporary name and another file under the ledger name; a
  writer killed after a commit and before removing its temporary file, or in
  the middle of writing it, leaves a temporary file as well. So the ledger
  name alone is not the history while any file matching the exact temporary
  pattern exists. Under the lock and before reading the ledger, `grant
  draft` and both stages of `grant sign` list the directory and, if any such
  file exists, refuse as `LEDGER_FILE` with the fixed message `A
  seal-ledger temporary file left by an interrupted update may hold earlier
  seals; run grant ledger-recover.` They read, write and remove nothing.
  The fence holds until `grant ledger-recover` clears it; there is no manual
  check to remember and no automatic deletion. A directory that cannot be
  listed refuses as `LEDGER_FILE` (fail closed).
- Durability. The temporary file is synced with Go's `File.Sync`, which on
  macOS uses `F_FULLFSYNC`. The directory is synced with plain `fsync`, which
  on macOS does not flush the drive's write cache. A killed process leaves the
  previous or the new ledger under the ledger name, and possibly a temporary
  file, which fences the ledger until recovery; after a power loss on macOS
  the exchange may be lost and the previous ledger come back, forgetting the
  newest seal. Process kills on Linux and passing macOS CI do not establish
  power-loss durability.

The content is `{"schema":"swarma-identity/seal-ledger/1","seals":[{"txid","vout","grant_id"}]}`.
A seal backs at most one grant. Draft, and sign without `grant_sig`, refuse a
recorded seal. Sign with `grant_sig` refuses a seal recorded for another
`grant_id`, and is idempotent for the same one. A refused final sign never
records a seal. The ledger holds public data only.

The ledger is local single-use tracking for one issuer, not a chain-level
guarantee. Anyone who can write to the ledger's directory, or rename a
directory above it, can delete or replace the ledger between runs; keep it in
a directory only the issuer can modify. While a sign runs, such a change can
make that sign refuse, but it cannot give the lock to a second writer of the
same directory or make the sign commit a file other than its own. A file
substituted under the writer's temporary name before the exchange is
refused and the displaced ledger is put back, so the refusal leaves the
committed history in place. Between the exchange and its undo the
substituted file is briefly under the ledger name; every other command waits
for the lock and does not see it. An actor that changes the ledger or
temporary name again inside that window, or a kill in it, can defeat the
undo: the sign still refuses with no grant released and keeps the temporary
name, which may hold the previous ledger. The recovery fence then refuses
every draft and sign until `grant ledger-recover` merges that file back.
Such an actor can replace the ledger directly anyway. The substitution cases
are exercised by an in-process step hook, and the interrupted state by a
fixture built with the real exchange under the real lock, not by a racing
process at a native syscall boundary or a killed process.

## `grant ledger-recover --seal-ledger FILE --json`

Clears the recovery fence. It is offline: no `--config` and no `--request`.
Under the exclusive lock (bounded at 15 seconds like a sign) it reads the
ledger, which must be missing or valid, and every leftover file matching the
exact temporary pattern. Each leftover must be an owner-only regular file
with one link, at most 64 KiB, and one of:

- empty;
- a complete ledger document with valid entries, whose entries are merged;
- a torn write: a proper prefix of the exact bytes the writer serializes for
  the ledger or a leftover ledger extended by at most one entry. Past that
  ledger's own entries the file may stop at any byte of
  `{"txid":"<64 hex>","vout":<decimal>,"grant_id":"<64 hex>"}]}`, with
  lower-case hex, a vout in canonical decimal no larger than 4294967295, and
  a seal and grant id not already in that ledger; any other byte, member,
  value or trailing text is not a torn write. Where the file stops, inside a
  value or after it, it must still be completable to an entry a writer
  records: at least one completion has a seal and a grant id that ledger does
  not hold and keeps the document within 64 KiB. A file that stops right
  after a held seal's txid and a vout of `0`, `4294967295` or `429496730`
  therefore refuses: ending the number there repeats the seal, and no
  canonical uint32 continues it. A writer syncs its whole file before the
  exchange, so such a file was never the ledger, and its extra entry backs no
  released grant.

Anything else refuses as `LEDGER_FILE` and is kept for the owner. The merge
is the union of the ledger's and the leftover ledgers' entries and refuses
as `LEDGER_RECOVERY_CONFLICT` when one seal maps to two grant ids or one
grant id to two seals. A union larger than the ledger is committed through
the same exchange protocol as a sign (or the no-replace rename when no ledger
exists). The ledger is then read back and must hold exactly the union; only
then are the leftovers removed, each only while its name still denotes the
file that was classified, and the directory is synced. A refusal before the
read-back leaves the ledger and every leftover as they were, so the fence
keeps holding; after the read-back the ledger already holds the union. A
recovery interrupted after its commit is completed by running it again.

The result is `{seals, restored, removed}`: the entries in the ledger after
recovery, the entries taken from leftovers, and the leftover files removed.
With no leftover it changes nothing and reports `restored:0, removed:0`.

## Refusals

All named grant refusals exit 3 with `retryable:false`:

- `NETWORK_PIN`
- the LIP-0013 codes: `CONTRACT_ENCODING`, `CONTRACT_PROFILE`, `CONTRACT_FIELD`,
  `CONTRACT_ACTIONS`, `CONTRACT_REPOS`, `CONTRACT_BUDGET`, `CONTRACT_NOTE`,
  `CONTRACT_HASH`, `CONTRACT_MISMATCH`, `SCOPE_MISMATCH`, `BUDGET_MISMATCH`,
  `CONSENT_TAGS`
- `GRANT_FIELD`
- the consent codes: `CONSENT_SIGNER`, `CONSENT_BINDING`, `CONSENT_TIME`,
  `CONSENT_ID`, `CONSENT_SIGNATURE`
- the party codes: `AGENT_NOT_V3`, `AGENT_LANDLORD_MISMATCH`, `LANDLORD_NOT_V3`
- the landlord codes: `LANDLORD_KEY_MISMATCH`, `LANDLORD_SIGNATURE`,
  `GRANT_SIGNATURE`
- the seal codes: `SEAL_REUSED`, `LEDGER_FILE` (the recovery fence uses
  `LEDGER_FILE` with its own fixed message), `LEDGER_RECOVERY_CONFLICT`
- any `rental.Grant.Validate` code

A draft record whose fields disagree with its contract (agent, landlord,
grantee, window, budget or scope mapping) refuses with the LIP-0013 section
2.5 code at every step.

Malformed requests are `BAD_INPUT` (exit 2) before any node read. Node
refusals keep the codes of `identity show` (`NAME_NOT_FOUND`, `NAME_EXPIRED`,
`SNAPSHOT_CHANGED`, `PROVIDER_PROTOCOL` and the others in CLI.md).

## Test signer

`internal/testsigner` exists for tests only. It loads a 32-byte key file that
is 0600, owner-only, single-link, at a clean absolute path with no symlink
component (the macOS `/private/...` rule above applies). The tests resolve
their temporary directories for this reason. It loads only the published secret keys of BIP-340 test vectors 0
to 3 and refuses every other key, so it cannot be used with a real key. It
signs with `aux_rand` of 32 zero bytes, as the LIP-0013 vectors do, and it
reproduces the BIP-340 vectors. It is never the default, and the binary does
not import it.

## Limits

- **Seal not read on chain.** These commands do not check that the seal exists,
  is confirmed, is unspent, or pays P2PKH to the grant key. The read fence has
  no `gettxout`. Creating the seal and signing and broadcasting the issuance
  transaction are planned as `grant seal` and `grant anchor`. `rental.Check`
  verifies the seal on the verifier's node.
- **Fixture node.** "Regtest" in the tests means a regtest-pinned loopback
  fixture node, not a Namecoin Core regtest daemon.
- **Signer adapters.** The keyvault, Keychain and NIP-07 adapters are external.
  This CLI hands them each digest together with the exact public bytes it
  commits to (see Signer display) and takes back only public signatures. It
  never takes a private key.
- **Bare v3 parsing does not bind the contract.** `rental.ParseSignedGrant`
  treats `contract_sha256` as opaque: a re-signed grant whose agent, landlord,
  grantee, window, scope, budget or consent tags disagree with its contract
  still parses. Every step here applies the LIP-0013 section 2.5 binding; a
  verifier must also hash the exact contract bytes and apply that binding.
- **Signer display.** The CLI supplies the exact public bytes beside each
  digest: `consent_template`, whose NIP-01 serialization hashes to
  `consent_event_id`; `contract_b64`, whose SHA-256 is `contract_sha256`; and
  `grant_b64`, the canonical unsigned grant behind `grant_signing_hash`. Pass
  those bytes to the signer with the digest. A signer should render them and
  recompute the digest from them; signing a digest supplied on its own does
  not show the signer what it approves.
- **Wall-clock window.** The window and `created_at` are checked for shape and
  order only. Freshness against the wall clock is the verifier's decision
  (`rental.Check`).
