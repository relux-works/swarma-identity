# Grant seal lifecycle and operator runbook

## Scope and source pin

This is the existing reusable Grant v3 seal: one P2PKH output to the
compressed even-y issuer grant key, with native P2WPKH funding and separate
change. It is not the two-branch single-use seal of LIP-0002, a v4 seal,
a contract seal, an anchor, or a live-grant verifier.

The semantic pin is swarma-link-spec **v0.1.61**, commit
`464c445fd52ce0ec8bdc52c0ead8a866a7b77f56`, specifically LIP-0017 sections
5.7 and 6 and LIP-0020 W11.11. A minimal landed v3 contract still needs no
separate contract seal. Requiring one here would contradict that pin.
The four contract termination-script rows (issuer only, either party,
both together, arbiter) do not define canonical constructions for this
tool to invent. V4/framework contract presentation, scripts and issuance
integration remain outside this v3 interface.

Existing sources are reused, not redefined: Swarma book, Link chapter 4
(`link-book/ru/04-doverennost.md`, section on the seal and pool), LIP-0004,
LIP-0013, the public funding profile in [GRANT.md](GRANT.md), and chain-lab
`experiments/rental/grant_plan.go` and `experiments/grantcheck`.
LIP-0022 section 5 supplies the depth arithmetic, not a universal finality
number. This v3 grant format signs no confirmation minimum; the operator
must explicitly choose the floor in the plan. No field is added to a grant.

Qualification in this change is **regtest fixtures only**. No live wallet,
native authentication, real node, production key or mainnet broadcast is
qualified by these tests. A local signed record is not a live issuance;
the existing grant/anchor confirmation and verification requirements stand.

## Prepare and plan offline

Choose the funding inputs yourself and independently pin the compressed
public key of their native P2WPKH wallet key. The signer label must actually
hold that same key. There is no wallet discovery, coin selection, key import,
private-key request member, wallet RPC, or ambient fee policy. Multiple inputs
must all pay to this one funding key; use a different reviewed workflow for
other funding shapes. The funding key need not be the issuer grant key.

`seal plan` takes a closed `swarma-identity/seal-plan/1` request:

```json
{
  "schema": "swarma-identity/seal-plan/1",
  "network": "regtest",
  "signed_grant_b64": "<exact signed v3 grant bytes, base64>",
  "contract_b64": "<exact bound contract bytes, base64>",
  "amount_sat": 100000,
  "funding": {
    "script_hex": "<native P2WPKH script of funding_pubkey>",
    "inputs": [{"txid": "<parent txid>", "vout": 0, "prev_tx_hex": "<full public parent>"}],
    "fee_rate_sat_vbyte": 2
  },
  "funding_pubkey": "<33-byte compressed public key, lower-case hex>",
  "max_fee_sat": 10000,
  "max_fee_rate_sat_vbyte": 10,
  "min_confirmations": 3
}
```

All members are required. Existing funding bounds apply: at most 16 distinct
inputs, complete parents matching their txids and output indices, native
P2WPKH only, fee rate 1..1000 atoms/vbyte and a 1000-atom change reserve.
The seal floor is the pinned implementation profile minimum, 100000 atoms.
The total fee cap is 1..2100000000000000 atoms; the rate cap is 1..1000
atoms/vbyte; the explicit confirmation floor is 1..10000.

The planner recomputes the grant signature, contract binding, seal script,
funding parent outputs, unsigned transaction and PSBTv0. The seal **must already
name the exact resulting txid and vout 0**. It refuses a different outpoint
rather than changing or reissuing the grant. Native witness funding preserves
this txid when signed. This interface reconstructs one known seal transaction;
it does not rewrite a previously issued grant or reconstruct arbitrary pool
transactions with additional seals.

Choose one durable, owner-controlled journal directory. Use its absolute,
physical path, without symlinks, and the basename `<grant_id>.seal.json`:

```sh
swarma-identity seal plan --request plan.json --journal "$JOURNAL" --json
```

Planning is offline and creates the journal only after validation. A repeated
identical request returns the existing state, including a later signed state;
a changed request refuses `SEAL_JOURNAL_CONFLICT`. Never select another journal
directory to evade an existing record. Journal custody, backups and the
authoritative path are the operator responsibility; local metadata is not
cryptographic proof against its owner editing or rolling back the filesystem.

## Review and sign offline

```sh
swarma-keychain seal sign --journal "$JOURNAL" --label "$FUNDING_LABEL" --json
```

Only the signer binary has the custody seam. `swarma-identity seal sign`
refuses `UNSUPPORTED_CAPABILITY`; Linux/non-native signers keep their existing
unsupported behavior. The reserved static-gate label cannot fund a grant.

The existing controlling-terminal display shows the summary, grant id,
network/genesis, funding public key and label, access policy and native ACL
inspection limits, PSBT, every
input/sequence/amount/parent script, every output/amount/script, exact fee,
caps, version, locktime and SIGHASH_ALL without ANYONECANPAY. The operator must
type the exact line **SIGN** on that terminal. There is no approval flag and
stdin is not approval. Each input then uses the existing per-signature native
authentication policy (Touch ID, or the explicitly selected passcode policy).
No secret is requested before approval. Every resulting strict-DER low-S
ECDSA signature and witness is verified against the funding key and exact
transaction before the signed bytes are committed to the journal.

The actual signed size is also checked against the fee-rate cap; leave
headroom over a requested estimate if necessary. Failed signing exposes no
partial signature result. A repeated sign on an already-signed journal returns
the record without another signature. Signing authorizes no broadcast.

## Preflight and one-attempt broadcast

Provide two explicit configurations with the same network, genesis, node id
and loopback endpoint. Read configuration uses the existing schema/profile
`swarma-identity/config/1` / `namecoin-core-read/1` and RPC user **verifier**.
Broadcast configuration uses the same closed fields but profile
`namecoin-core-broadcast/1` and a separate authorized RPC user and credential
file. Both keep the existing owner-only auth-file and no-proxy/no-redirect
rules. No config path or credential is put in the journal. The node custodian
must grant the read user the documented read methods and the separate write
user only the intended broadcast authority; client-side separation is not a
claim about server-side ACL installation. The normal read-only RPC fence
continues to refuse broadcasting and wallet operations.

```sh
swarma-identity seal broadcast --journal "$JOURNAL" --config read.json --broadcast-config broadcast.json --json
```

The command validates the journal and every signature, checks Core 28.0,
network/genesis and sync, reads every funding input with mempool-inclusive
`gettxout`, decodes the exact signed transaction, compares every decoded output
to the plan, and calls `testmempoolaccept` with the pinned rate cap. Returned
txid, acceptance, base fee and vsize must match the reviewed plan. A final tip
check precedes the attempt. These sequential reads are not an atomic node
snapshot; the node may still refuse a transaction after the preflight.

After acceptance the command durably records `accepted`, then durably records
`broadcast_attempted:true`, **before** its one `sendrawtransaction` call. The
same explicit maxfeerate is sent; Core represents it in coins/kB, so 10
atoms/vbyte is `0.00010`, never a zero/unlimited cap. Only the separate write
credential performs that one call. A matching returned txid records `broadcast`.

Any missing, erroneous or contradictory send response is
`SEAL_BROADCAST_UNCERTAIN`. Even an explicit node refusal consumes the attempt.
Subsequent broadcast invocations do not contact the node: they return the
recorded txid and state. For a still-accepted attempted record,
`needs_reconciliation:true` means **not a successful broadcast receipt**.
A crash after intent but before sending can result in zero sends; at-most-once
is intentional, not a promise of exactly-once delivery. Do not delete/reset a
journal, move to another one, change funding, or construct a different
transaction to make an uncertain operation retry.

## Observe and recover without sending

```sh
swarma-identity seal observe --journal "$JOURNAL" --config read.json --json
```

Observation requires a recorded attempt and uses only the verifier user. It
resolves the exact txid/bytes, reads its block header, checks the active hash
at that height and a stable endpoint tip, then computes `H - h + 1`. At or
above the pinned floor the current state is `confirmed`; below it the state
is `broadcast`. Zero denotes no confirmed depth, not finality. Reorgs can move
the current state back from confirmed to broadcast, while retaining history.
A missing transaction/index, unavailable node or contradictory response is
an error, not evidence of absence, and never authorizes another send. The node
must make the transaction readable (for example through its authorized index).
An idempotent broadcast response is the **last recorded observation**, not a
fresh liveness or confirmation check.

The per-grant owner-only journal records the immutable public request/PSBT,
signed wire bytes, state history and latest observation. Directory locking,
bounded lock deadlines, owner/inode/link checks, fsync, atomic no-replace
creation or exchange, directory fsync and a leftover-temp recovery fence reuse
the seal-ledger storage mechanism. Interrupted saves preserve the last record;
if a temporary file remains, `SEAL_JOURNAL_RECOVERY_REQUIRED` stops operations.
Keep all files intact, reconcile exact signed bytes/txid and every possible
attempt with the node custodian, and obtain a reviewed recovery decision.
`grant ledger-recover` is for the separate issuance ledger, **not this journal**.
No automatic lifecycle-journal recovery/reset or transaction replacement exists.

## Checks and remaining production steps

Run `go test ./internal/facade -run TestSeal`, `go test ./...`, `go vet ./...`
and `go test -race ./internal/facade` with the repository isolation rules.
Logs and scratch remain in `.temp/`. Tests use published-vector keys in the
existing in-memory signer and a loopback regtest protocol fixture, not a node.
Its parameter/response semantics follow upstream Core 28.0 documentation:
[decode](https://bitcoincore.org/en/doc/28.0.0/rpc/rawtransactions/decoderawtransaction/),
[acceptance](https://bitcoincore.org/en/doc/28.0.0/rpc/rawtransactions/testmempoolaccept/),
[send](https://bitcoincore.org/en/doc/28.0.0/rpc/rawtransactions/sendrawtransaction/),
[transaction reads](https://bitcoincore.org/en/doc/28.0.0/rpc/rawtransactions/getrawtransaction/)
and [mempool-inclusive prevouts](https://bitcoincore.org/en/doc/28.0.0/rpc/blockchain/gettxout/).
The fixture enforces method/parameter/credential separation and signed-byte
identity; an independent script engine executes the funding witness.

Production remains lead-owned, **after November 22, 2026**, and this runbook is
not permission to perform it. Before any production step: obtain both required
exact-head reviews, required checks and approved signed-head publication;
qualify the real Core policy/ACLs and native signer/display on the operator
machine; agree the confirmation floor and authoritative journal custody;
independently reconstruct and inspect the named seal, chosen wallet inputs,
change, network and fees; and authorize that exact transaction. Only then use
the approved signer and exact SIGN line, decode, test acceptance, durably fence
one send, reconcile any ambiguity read-only, and observe the required active-chain
depth. Anchor/publication and independent live-grant verification are separate
subsequent gates. Never bypass these gates by hand-submitting journal bytes.
