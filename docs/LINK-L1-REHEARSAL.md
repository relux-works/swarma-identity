# L1 materialization rehearsal: supported prefix and STOP

**STOP:grant-draft-human-landlord**. This is not an end-to-end qualification.
The script deliberately exits **3**, not zero, after reproducing the blocker.
The opt-in Go test can pass by proving that exact STOP; its passing status must
not be reported as a passing grant ceremony.

## Contract boundary

The requested ceremony grants authority between two people whose names both
carry `swarma.landlord.grant`. Today's `grant draft` instead requires
`agent_name` to resolve to a v3 **agent**, with a pointer to `landlord_name`.
`grantIssuer` in `internal/facade/grant.go` returns `AGENT_NOT_V3` for the
other landlord, in both directions. `TestGrantDraftPartyNegatives` already
documents this behavior against an RPC fixture; this rehearsal exercises it
against the actual Core daemon after creating confirmed seals.

The diagnostic draft uses a one-hour Unix-time window and narrow actions
only to reach that role check. It is **not** an encoding of the owner's text,
is never signed, and creates no grant. In particular, the requested terms are:
multi-use; fixed end at the grantor name's present expiry block, without
extension on renewal; decisions, reviews, admissions and repository landings
subject to the target's own permissions and checks; runner administration
only below critical load (CPU above 90% for more than 10 minutes, macOS memory
pressure "critical", or free memory below 10% is critical); no money, personal
accounts/keys, root key, internal-network access, elevated privileges,
destructive repository actions, or sub-delegation; revocation on publication;
and no automatic machine-effect authority.

Those terms must not be replaced by a technically issuable agent grant.
Profile `/1` has Unix-second `not_before`/`not_after`, not a fixed expiry-block
field; its short ASCII `note` carries no authority. Profile `/2` carries exact
separate scope bytes but keeps the same agent/landlord model and Unix window.
Neither supplies an approved encoding of this ceremony. The v4 commands are
partial offline octet tooling, not a live issuer; see [GRANT_V4.md](GRANT_V4.md).
Converting an expiry block to an estimated timestamp, assigning each human an
agent alias, or treating an explanatory note as the signed scope changes the
contract and is not an acceptable workaround.

## Sources and decisions

Read against swarma-identity base `99d991d3b3caf4cc7b096ca4bc01e2233ede11e6`
and swarma-chain-lab `5d1d02b6f148d441bc9157524c7a7f8c8e215674`:

- **Same:** [GRANT.md](GRANT.md), flow steps 0–8, role checks and `/1`/`/2`
  formats; [SEAL.md](SEAL.md), confirmed funding and qualification gates.
- **Same:** Swarma book `link-book/ru/04-doverennost.md`, sections Document,
  Issuance, Seal and pool, Verification and What the chain says about time;
  `link-book/ru/06-dogovor.md`, contract/digest description. Book revision:
  `bc1132c9d9be60864ef7195efa83215357ad3011` in swarma-docs.
- **Same:** grantcheck's explicit `trust` profile, network/genesis pins and
  LIP-0004/0005/0010/0013/0014 reader, pinned there to spec v0.1.51
  `bd3bc80e5543d8a563343ec05abd1a5f3f67284c`.
- **Owner decision required:** human-to-human text authority and fixed-block
  expiry cannot be forced into the existing trust flow. Select the normative
  contract/profile first; a changed contract needs its spec and implementation
  delivery before a fresh full rehearsal. This PR introduces no protocol rule.

## What the prefix exercises

`scripts/rehearse_link_l1.py` imports the pinned fullnode-trusts harness's RPC,
network check, mining, transaction inspection and checked broadcast functions.
Their source hashes are checked before import. The existing prototype's grant
format is **not** used. The m5-rehearsal Core configuration pattern supplies
the disabled-network loopback configuration and owner-PID cleanup. Only the
fixed `/lab` filesystem budget callback is adapted to a task-owned directory;
the original bubblewrap/cgroup/tmpfs isolation is not claimed by this driver.

The daemon must match the harness's Core 28.0 Linux executable SHA-256
`dc7430676e445af3992430e036f7c1a17bea44f757e9cf25b69205e39625f2f7`.
The driver creates new Core wallets/keys for every run; no key input is
accepted. Names have fresh random suffixes. P2P/DNS/discovery/network activity
are disabled. The sole RPC endpoint is that new regtest daemon, accessed with
its private fixture cookie by the external wallet harness, and a separate
method-restricted read credential by swarma-identity. No installed node or
wallet is discovered. No test private key enters swarma-identity.

For A and B it registers landlord values, confirms native P2WPKH funding,
runs `grant seal`, signs externally with the disposable Core wallet, checks
fee/size/mempool policy through the reused harness, broadcasts and confirms.
The signed seal txid must equal the unsigned plan's outpoint. Each wrong-network
seal request returns `NETWORK_PIN` (exit 3) without changing the mempool;
the adjacent regtest request succeeds (exit 0). Both draft probes then return
`AGENT_NOT_V3` (exit 3), with no ledger or mempool write. Core is stopped by its
own child PID and reaped before the public result is emitted.

No consent event, grant signature, issuance, `live` verdict, revocation,
second verifier node, wrong-grantee check, unconfirmed-issuance check or
tampered-contract check is claimed. Existing fixture tests for some of those
checks are not substitutes for the missing end-to-end run.

## Reproduce

Requirements: Linux, Python 3 standard library, Git, Go 1.26.8, the independently
verified Core 28.0 Linux release, and the pinned chain-lab source obtained over
HTTPS. Verify the release signing key/archive as described by fullnode-trusts;
the executable pin alone is an additional check, not a release-signature claim.

From a clean checkout of this PR, choose `CORE_BIN` yourself. No default searches
wallets or node installations. All commands below run in task scratch. Fetching
source/modules uses HTTPS; every chain operation remains isolated regtest.

```sh
set -eu
REPO=$(pwd -P)
mkdir -p .temp
SCRATCH=$(mktemp -d "$REPO/.temp/link-l1.XXXXXX")
mkdir -p "$SCRATCH/work"
git archive HEAD > "$SCRATCH/source.tar"
tar -xf "$SCRATCH/source.tar" -C "$SCRATCH/work"
git clone https://github.com/relux-works/swarma-chain-lab.git "$SCRATCH/chain-lab"
git -C "$SCRATCH/chain-lab" checkout --detach 5d1d02b6f148d441bc9157524c7a7f8c8e215674
cd "$SCRATCH/work"
ENV_ROOT="$PWD/.temp/env"
mkdir -p "$ENV_ROOT/home" "$ENV_ROOT/config" "$ENV_ROOT/cache" \
  "$ENV_ROOT/go-build" "$ENV_ROOT/go-mod" "$ENV_ROOT/go-path" \
  "$ENV_ROOT/go-tmp" "$ENV_ROOT/tmp"
export HOME="$ENV_ROOT/home" USERPROFILE="$ENV_ROOT/home"
export XDG_CONFIG_HOME="$ENV_ROOT/config" XDG_CACHE_HOME="$ENV_ROOT/cache"
export GOCACHE="$ENV_ROOT/go-build" GOMODCACHE="$ENV_ROOT/go-mod" GOPATH="$ENV_ROOT/go-path"
export GOTMPDIR="$ENV_ROOT/go-tmp" TMPDIR="$ENV_ROOT/tmp" TMP="$ENV_ROOT/tmp" TEMP="$ENV_ROOT/tmp"
export GOTELEMETRY=off GOTOOLCHAIN=local GOWORK=off GOMAXPROCS=2
unset GOTELEMETRYDIR GOFLAGS
export L1_REGTEST=1 L1_CORE_BIN="$CORE_BIN" L1_CHAIN_LAB="$SCRATCH/chain-lab"
export L1_PUBLIC_RESULT="$SCRATCH/public-result.json"
go test -p 1 -parallel 2 -count=1 -v -timeout 5m -run '^TestLinkL1' ./internal/facade
```

`TestLinkL1NetworkGate` rejects main/test/unknown before creating scratch or
opening any tooling. `TestLinkL1RegtestContractStop` is skipped unless explicitly
enabled. Enabled, it builds the real identity binary and checks the child
script's exit 3 and exact named refusals. Its zero exit proves this bounded
STOP witness, not the requested ceremony. The optional `L1_PUBLIC_RESULT`
retains the sanitized JSON after Go removes its temporary private fixtures.
The [recorded public prefix receipt](rehearsals/LINK-L1-PREFIX.json) binds the
script and identity binary by SHA-256 and records each CLI exit code, both
confirmed public seal outpoints, the STOP, unrun stages and Core cleanup.
The bounded fee rate is the reused harness's 200 atoms/vbyte, not a mainnet
quote. Its real-node relay checks are not replaced by an RPC fake.
Do not publish private directories, wallets, cookies or logs. Core PIDs and
public transaction ids in the result are disposable run evidence.

To call the script directly with the same isolated environment:

```sh
go build -p 1 -o "$ENV_ROOT/swarma-identity" ./cmd/swarma-identity
python3 -B scripts/rehearse_link_l1.py --network regtest \
  --core-bin "$CORE_BIN" --chain-lab "$L1_CHAIN_LAB" \
  --identity "$ENV_ROOT/swarma-identity" --root "$PWD/.temp/direct-run"
```

The last command must exit 3 and write `public/result.json` inside its new run
root. Private state is retained there for local diagnosis, not exported.
Never turn its STOP into a success status or proceed to mainnet.
