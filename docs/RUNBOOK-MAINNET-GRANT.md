# Mainnet grant ceremony — blocked at contract selection

**STOP:grant-draft-human-landlord**. Do not sign or broadcast a mainnet
transaction using this document. The requested human-to-human text grant has
no executable route through today's `grant draft` contract. The [L1
rehearsal](LINK-L1-REHEARSAL.md) records the exact boundary and supported prefix.
This document delivers preparation and abort handling, not invented commands
for the missing part of the ceremony.

As of November 20, 2026, [SEAL.md](SEAL.md) additionally reserves production
for the lead **after November 22, 2026**. Passing that date is not approval.
The existing exact-head reviews, checks, signed publication, native signer,
real Core policy/ACL qualification, confirmation policy and journal custody
gates still apply. None was discharged by the regtest prefix.

## Roles and prerequisites

The node operator prepares public requests and performs read-only chain
checks. The grantor's Mac owns the grant key and, only if separately selected,
the funding key. The grantee owns their independent NIP-01 key and consent
signer. Transfer only exact public request/result bytes between them; never
copy credentials, private keys, Keychain items or RPC cookies. Retain public
objects by their hash, not by a mutable filename alone.

Before a later authorized ceremony:

1. Agree the normative profile for two human landlords and the fixed grantor
   name-expiry block. Preserve the complete owner text, including multi-use,
   no extension on renewal, no payments/keys/sub-delegation and target-system
   permission limits. Do not estimate a timestamp from a block height, use
   `/1` note as scope, or silently introduce agent names. Rehearse the accepted
   profile end to end, both directions, including independent `trust`/network
   pins where applicable, revocation and all four requested negatives.
2. Run the approved `SwarmaKeychain.app` on each grantor's Mac with an owner-
   supervised throwaway-key native signer/display test, then the separately
   approved real key procedure in [KEYCHAIN.md](KEYCHAIN.md). Use the signed,
   provisioned app's `Contents/MacOS/swarma-keychain`, not an unsigned loose
   binary. Select the key label and access policy independently. Before any
   Touch ID/passcode prompt verify the displayed key, policy and device-only
   limit. The native hardware run remains outstanding here.
3. Publish the selected grant key through the name owner's separately reviewed
   **`name_update`**, preserving the existing social descriptor and unrelated
   value data. `value build --grant-xonly "$ISSUER_KEY" --social-descriptor
   social.json --json` prepares public value bytes; it does not update a name.
   The external name-wallet transaction workflow must sign, decode, test
   acceptance, publish once and confirm. This CLI has no `name_update` command.
   Re-read `identity show` and pin the name generation, expiry and grant key
   after confirmation. Do not renew a name and silently extend the grant term.
4. Fund the independently selected native P2WPKH funding key with NMC for the
   reviewed seal, issuance and revocation fees. Confirm every ordinary funding
   parent **before** the child; do not mine/accept parent and seal together.
   Select exact full parents, outpoints, change script, maximum absolute fee
   and maximum fee rate. The seal creation profile floor is 100000 atoms, not
   a consensus denomination or a fee estimate. No mainnet fee quote is supplied.

## Read-only freshness sequence: node host

These are existing commands, not permission to contact a node. The custodian
must supply an authorized read-only `READ_CONFIG`, network `main`, pinned
genesis `000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770`
and Core version 280000. Auth remains in an owner-only file, never argv.
Set request files to the independently selected exact names.

```sh
swarma-identity node health --config "$READ_CONFIG" --json > health-before.json
swarma-identity name show --config "$READ_CONFIG" --request grantor-name.json --json > grantor-name.result.json
swarma-identity identity show --config "$READ_CONFIG" --request grantor-name.json --json > grantor-identity.result.json
swarma-identity name show --config "$READ_CONFIG" --request grantee-name.json --json > grantee-name.result.json
swarma-identity identity show --config "$READ_CONFIG" --request grantee-name.json --json > grantee-identity.result.json
swarma-identity node health --config "$READ_CONFIG" --json > health-after.json
```

Require process exit 0 **and** `ok:true` for each result. Check Core version,
main/genesis, non-IBD, headers/blocks agreement, connections and observed tip.
`node health` can succeed on an unsynced node: success is not freshness.
Compare the observed tip/time with an independently approved current chain
reference; the command itself gives no independent best-chain assurance.
Require the agreed freshness bound, active names and expected generation/key.
If the tips changed, preserve both snapshots and repeat the read sequence;
if either differs from the independent view or policy, stop. No universal
freshness allowance is invented here.

## Confirmation floors and journal custody

Before authorizing any transaction the owners must record the actual mainnet
floors in the accepted policy. This PR selects none:

| Object | Existing lower bound | Remaining owner gate |
| --- | --- | --- |
| Ordinary funding parent | integer depth at least 1 before seal broadcast | stricter funding floor and reorg policy |
| Name registration/update | confirmed active generation, not a mempool value | accepted depth and generation/expiry pins |
| Seal | confirmed, unspent, correct P2PKH to even-y grant key | agreed active-chain depth; `seal plan` accepts 1–10000 |
| Grant issuance | confirmed on each verifier's own node | policy-selected issuance floor and freshness |
| Revocation | spent-seal observation, including relevant mempool rules | publication/observation and reorg expectations |

The `min_confirmations:3` example in SEAL.md is not a mandated mainnet floor.
Neither `grant seal` nor `grant anchor` creates the durable lifecycle journal.
Do not confuse the draft/sign seal-reuse ledger with the broadcast journal.
`seal plan` reconstructs the exact seal already named in a signed v3 grant;
it cannot repair the present draft blocker or replace an arbitrary funding
wallet workflow. Once applicable, use one authoritative private physical
journal path, basename `<grant_id>.seal.json`, and preserve all states and
recovery files. Move custody only with an explicit single-authority handoff;
never run independent copies on the Mac and node as separate journals.

## Supported v3 command order — reference only

This is the existing [GRANT.md](GRANT.md) flow, **not** a runnable translation
of the owner text. The named request formats must already be valid for an
accepted contract. Stop before step 0 for the requested mainnet ceremony.

| Step | Where | Existing command or external action |
| --- | --- | --- |
| 0 | node, then external funding wallet | `swarma-identity grant seal --config "$READ_CONFIG" --request seal.json --json`; review, externally sign/publish, confirm exact seal |
| 1 | node | `swarma-identity grant draft --config "$READ_CONFIG" --request draft.json --seal-ledger "$LEDGER" --json`; **requested parties refuse here** |
| 2 | grantee signer | independently check/sign the NIP-01 kind-8181 event; see [RUNBOOK-CONSENT.md](RUNBOOK-CONSENT.md) |
| 3 | offline preparer | `swarma-identity grant consent --request consent.json --json` |
| 4 | grantor Mac | `"$KEYCHAIN_CLI" keychain sign --label "$GRANT_LABEL" --request contract-sign.json --json` for `contract_sha256` |
| 5 | node | `swarma-identity grant sign --config "$READ_CONFIG" --request grant-hash.json --seal-ledger "$LEDGER" --json` without `grant_sig` |
| 6 | grantor Mac | `"$KEYCHAIN_CLI" keychain sign --label "$GRANT_LABEL" --request grant-sign.json --json` for `grant_signing_hash` |
| 7 | node | `swarma-identity grant sign --config "$READ_CONFIG" --request signed.json --seal-ledger "$LEDGER" --json` with both signatures |
| 8 | node, then external funding wallet | `swarma-identity grant anchor --config "$READ_CONFIG" --request anchor.json --json`; externally review/sign/publish and independently verify confirmed issuance |

Before **each** `SIGN`, the grantor checks the app identity, exact label/public
key and access policy, network/genesis, both names and roles, recipient key,
whole canonical contract and its exact SHA-256, actual scope/limitations and
time semantics, consent and its signature, seal outpoint and every requested
purpose/digest/preimage. At step 6 also check the domain `swarma-grant-v3`,
canonical grant bytes and previously verified `landlord_sig`. For a transaction
signature additionally inspect every input/parent/amount, seal and change
output, fee/rate caps, sighash and unsigned txid. If any field is not understood,
decline. Type exact `SIGN` on the controlling terminal only after this review;
authenticate separately for each signature. A Touch ID success is not consent
to bytes that were not reviewed. Never pipe `SIGN` or bypass native approval.

The lifecycle commands, when applicable to a separately qualified v3 seal,
add explicit `--network main --issuer-key "$ISSUER_KEY" --allow-mainnet
--confirm-mainnet MAINNET` to **every** `seal plan`, signer `seal sign`,
`seal broadcast` and `seal observe` call. The two mainnet gates do not replace
`SIGN`. Use separate read and broadcast configs with matching node pins;
broadcast authorization must be independently granted. A repeated broadcast
call reports local state, not a second send. On an ambiguous send, preserve
the journal and use only `seal observe` for reconciliation; never hand-submit
the journal's bytes or reset its attempt fence.

## Abort and unresolved gates

Stop on any refusal, wrong key/network/digest, unconfirmed funding, changed
name/generation/expiry, unavailable native authentication, fee-policy mismatch,
unknown broadcast result, stale node, or missing signed-head qualification.
Do not delete ledger recovery files: `grant ledger-recover --seal-ledger
"$LEDGER" --json` is the supported offline recovery path when GRANT.md names
it. Preserve all public bytes, hashes, errors and receipts; keep sensitive
custody material private. A new head/profile requires fresh review/evidence.

The external funding/anchor signer transport, grantee's actual NIP-01 client,
verifier executable/service and pinned policy for each side, exact mainnet
floors, revocation transaction route and native owner run are **not qualified**
by this PR. Grantcheck is a Go library in the pinned source, not an existing
`swarma-identity grant verify` CLI command. Do not invent such a command or
announce `live` from a local signature, seal plan or transaction acceptance.
The full ceremony remains stopped until the contract and these gates are met.
