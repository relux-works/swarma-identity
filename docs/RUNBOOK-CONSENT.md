# Grantee consent — existing v3 contract and current STOP

**STOP:grant-draft-human-landlord** for the requested human-to-human ceremony.
There is no valid draft for that ceremony to consent to. Do not sign a
replacement agent grant or reword the owner text to make a fixture pass.
The following is the existing v3 consent interface, for use only after a
valid, owner-approved contract and signer route exist. See [the mainnet
gates](RUNBOOK-MAINNET-GRANT.md) and [contract evidence](LINK-L1-REHEARSAL.md).

## What the grantee receives and checks

The preparer sends the exact public `draft` from `grant draft` together with
the complete intended contract bytes, independently pinned grantor identity
and the `to_sign` entries. Preserve the files and hashes; no key, credential
or signer account is transferred. Compare the intended grantee's **own**
NIP-01 public key with `draft.grantee_key`; do not learn that key from an
untrusted draft. `grantee_name` alone does not establish key ownership.

Before approving any signer or Touch ID prompt, independently review:

- Network/genesis, grantor name/current grant key, intended recipient key,
  exact name roles and generation, seal outpoint, and the whole contract.
- Exact `contract_b64` decoded bytes and SHA-256, not a displayed summary.
  `/1` note is not authority; `/2` text must match its separate exact-byte hash.
- Actual actions, repositories, budget, time window and all intended limits.
  In this ceremony a fixed name-expiry block cannot be silently translated to
  the existing Unix window. Stop if the signed contract does not say the terms.
- The consent event: kind **8181**, empty content, own x-only `pubkey`,
  `created_at >= 1` and `< not_after`, not in the verifier's future, and exactly
  the four ordered LIP-0013 template tags (`t`, `contract`, `booking`, `privacy`).
  Preserve the template's literal tag values; do not reconstruct them from prose.

Recompute the event id as SHA-256 of UTF-8 NIP-01 serialization
`[0,pubkey,created_at,kind,tags,content]`. The event id in the draft is the
`consent_event_id` signing purpose; a landlord contract hash is **not** that
message. Consent needs the grantee key, never the grantor key.

## Produce the public event: grantee's signer

Use the grantee's independently selected and qualified NIP-01/NIP-07 signer.
The identity CLI cannot generate or sign this event, and its `nostr
profile-prepare`/`profile-verify` commands support kind 0, not kind 8181.
The grantor's `keychain sign` route accepts landlord purposes, not a generic
grantee key import. No new signer command is introduced by this runbook.

With a qualified NIP-07 client, obtain `window.nostr.getPublicKey()` and compare
it to the independent recipient pin. Give `window.nostr.signEvent(event)` the
reviewed template fields `kind`, `created_at`, `tags`, `content` (the signer
sets `pubkey`, id and signature). These are existing signer API operations,
not a supplied browser application or an installed CLI adapter. Check the
complete returned event again; reject changed tags/content/key. If the signer
chooses a new timestamp, recompute the id from the returned fields and review
that timestamp/window. Do not sign a bare digest without the event preimage.
Do not publish to a relay as a side effect of this procedure.

Export **only** the complete public event
`{id,pubkey,created_at,kind,tags,content,sig}`. Retain it and the reviewed
contract with their exact hashes. No seed/private key, NIP-49 material,
extension backup or unlocked signer session goes to the preparer/node.
Until the owners select and qualify the concrete client/export route,
**STOP:consent-signer-route**; there is no invented command for that gate.

## Check the result offline: grantee and preparer

Create the exact closed request file described by [GRANT.md](GRANT.md):

```json
{"schema":"swarma-trust/consent/1","draft":{"…":"exact draft record"},"consent_event":{"…":"complete signed event"}}
```

The ellipses denote whole objects to copy, not literal admissible fields.
Use exactly one of `consent_event` and the supported bare `consent_sig` form;
the full event form is preferable for review/export. Do not supply keys.

```sh
swarma-identity grant consent --request consent.json --json > consent.result.json
```

Require process exit 0 and `ok:true`. The returned `consent_event` is the
verified public event. The command rechecks the contract/draft binding,
recipient, tag binding, time shape, canonical NIP-01 id and BIP-340 signature;
it does not contact a node or relay and does not prove current chain state,
wall-clock freshness, publication or an authorized machine action.

| Changed input | Required existing refusal |
| --- | --- |
| Event public key is not the draft's recipient | `CONSENT_SIGNER` |
| Kind/content/tags do not bind to this contract | `CONSENT_BINDING` |
| Time outside the admitted shape/window | `CONSENT_TIME` |
| Id is not the canonical event hash | `CONSENT_ID` |
| Invalid signature over the recomputed id | `CONSENT_SIGNATURE` |
| Draft's contract digest does not match its exact bytes | `CONTRACT_HASH` |

A refusal exits 3, with no usable partial result. Preserve it and stop; do not
retry with another key, suppress a tag, or accept any error as proof of the
intended rejection. A future full regtest rehearsal must pair these negatives
with a valid event and assert the exact named checks. This prefix did not run
that consent rehearsal. Once valid, send only the exact verified public event
back to the grantor for the separate contract/grant signing stages.
