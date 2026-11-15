# swarma-identity

A Swarma module for an agent-facing facade over Namecoin and Nostr. The current CLI implements seven public-data operations and trust-grant issuance with unsigned transaction planning:

- Node health for an explicitly configured loopback Namecoin Core 28.0 node.
- Active name reads with exact value bytes, returned as hex.
- A v3 (LIP-0004) identity projection of an `id/` name: landlord or agent keys, the agent's resolved landlord, or `VALUE_NOT_V3`.
- Offline BIP-32 public derivation of Namecoin P2WPKH or P2PKH addresses.
- A bounded current-UTXO scan for both branches of a public P2WPKH account.
- Offline preparation of unsigned Nostr kind-0 profile events and their canonical bytes.
- Offline verification of an already-signed public kind-0 event's id and BIP-340 signature.
- Two-phase Grant v3 issuance with a LIP-0013 trust contract: `grant draft` builds the exact bytes and the digests to sign, `grant consent` verifies the grantee's externally signed consent, and `grant sign` verifies the landlord's external signatures against the on-chain grant key and assembles the signed grant, its `grant_id` and its issuance commitment. See [the grant contract](docs/GRANT.md).
- `grant seal` builds one P2PKH seal to the even-y grant key, plus separate funding change. `grant anchor` checks that seal with mempool-inclusive `gettxout` (confirmed, unspent, expected P2PKH/key) and builds the exact LIP-0005 issuance frame for the signed grant. Both return unsigned wire transactions and PSBTv0 with public parents, explicit fees and `dry_run:true`; neither signs nor broadcasts.

Node deployment/lifecycle, name transactions, transaction signing/broadcast, live grant verification, Nostr publication and NIP-05 resolution remain planned. Wallet-visible balance is not implemented. No plugin registration interface is exposed by this version.

The CLI uses no private keys or signer. The grant commands only exchange digests and public BIP-340 signatures with each party's own external signer; the test-only signer in `internal/testsigner` is not linked into the binary and loads only published BIP-340 test keys. Public derivation and both Nostr operations work without a node, wallet or relay. Online commands read only the selected node and never import a wallet, sign, broadcast, restart a service or automatically retry a scan. Validating a Nostr signature establishes no publication, freshness or identity authority.

## Build and use

Targets: macOS (darwin/arm64) and Linux (linux/amd64), Go 1.26.8. Go 1.26 is required by the imported `swarma-chain-lab/experiments/rental` module. From the repository root:

```sh
mkdir -p .temp/bin
GOTOOLCHAIN=local GOMAXPROCS=2 go build -p 1 -o .temp/bin/swarma-identity ./cmd/swarma-identity
.temp/bin/swarma-identity address derive --request .temp/derive.json --json
.temp/bin/swarma-identity node health --config .temp/node.json --json
.temp/bin/swarma-identity name show --config .temp/node.json --request .temp/name.json --json
.temp/bin/swarma-identity identity show --config .temp/node.json --request .temp/name.json --json
.temp/bin/swarma-identity balance watch --mode utxo-scan --config .temp/node.json --request .temp/scan.json --json
.temp/bin/swarma-identity nostr profile-prepare --request .temp/profile-prepare.json --json
.temp/bin/swarma-identity nostr profile-verify --request .temp/profile-verify.json --json
.temp/bin/swarma-identity grant draft --config .temp/node.json --request .temp/draft.json --seal-ledger "$PWD/.temp/seal-ledger.json" --json
.temp/bin/swarma-identity grant consent --request .temp/consent.json --json
.temp/bin/swarma-identity grant sign --config .temp/node.json --request .temp/sign.json --seal-ledger "$PWD/.temp/seal-ledger.json" --json
.temp/bin/swarma-identity grant seal --config .temp/node.json --request .temp/seal.json --json
.temp/bin/swarma-identity grant anchor --config .temp/node.json --request .temp/anchor.json --json
.temp/bin/swarma-identity value build --grant-xonly <x-only> --social-descriptor .temp/social.json --json
```

The Mac-only Keychain grant key (G1-K) is a separate binary, because `swarma-identity` itself never links a signer. See [docs/KEYCHAIN.md](docs/KEYCHAIN.md):

```sh
# On the owner's Mac, using the Developer ID profile and signing identity:
go run ./cmd/build-keychain-bundle /absolute/path/to/swarma-keychain-DevID.provisionprofile
.temp/SwarmaKeychain.app/Contents/MacOS/swarma-keychain keychain keygen --label NAME --access biometry-current-set --json > .temp/grant-key-NAME.public.json
.temp/SwarmaKeychain.app/Contents/MacOS/swarma-keychain keychain sign --label NAME --request .temp/keychain-sign.json --json
```

Keygen defaults to `biometry-current-set` unchanged; `--access biometry-any` survives fingerprint enrollment changes, while `--access biometry-or-passcode` also allows the device passcode/password. Every choice remains this-device-only. The public record and signing display include `access_policy`; changing policy requires a new key and an owner-key-signed `name_update`. See [the trade-offs and native inspection limit](docs/KEYCHAIN.md#access-policy).

The node custodian must authorize online use and select the credential file. A scan occupies the node's shared scan resource. The matched UTXO total covers only the explicit range; it is not an entire-account or spendable balance. Coinbase outputs can be included. Mempool, history and name-encumbered outputs are excluded.

See [the CLI contract](docs/CLI.md) for input schemas, result fields, deadlines and refusals, and [the module skill](agents/skills/swarma-identity/SKILL.md) for agent use. Keep account-specific inputs and qualification evidence in ignored local files. Never put credentials or private keys in command arguments or diagnostics.

## Development

Scratch output goes to `.temp/`, which Git ignores.

### Tools

| Tool | Purpose and exact entry point | Output |
| --- | --- | --- |
| Go 1.26.8 | Build: command above. Test: `GOTOOLCHAIN=local GOMAXPROCS=2 go test -p 1 -parallel 2 ./...`. Static checks: `GOTOOLCHAIN=local GOMAXPROCS=2 go vet -p 1 ./...`. | Binary under `.temp/bin/`; redirect logs to `.temp/`. |
| Go race detector | `go test ./... -race` (same Go 1.26.8 environment). | Redirect complete test logs to `.temp/`. |
| gofmt | Format: `gofmt -w cmd internal`. | Updates those source files. |
| swarma-identity | The commands above and the offline `registration` commands below; every invocation requires `--json`. | One JSON envelope on stdout; fixed bounded diagnostics on stderr. |
| swarma-keychain | darwin/cgo only: `keychain keygen`, `keychain sign`, `value build` ([docs/KEYCHAIN.md](docs/KEYCHAIN.md)). | One JSON envelope on stdout. The signing display and the confirmation use `/dev/tty`. |
| Developer ID bundle (macOS) | `go run ./cmd/build-keychain-bundle PROFILE [OUTPUT.app]` builds the release signer, embeds the owner-supplied provisioning profile, signs with the Relux Works Developer ID Application identity and runs `codesign --verify --strict`. See [the recipe and Mac acceptance gate](docs/KEYCHAIN.md#developer-id-signing-for-the-data-protection-keychain). | Default `.temp/SwarmaKeychain.app` and `.temp/SwarmaKeychain.entitlements.plist`. |
| Keychain tests (macOS) | `security create-keychain -p PW "$RUNNER_TEMP/swarma-test-X.keychain-db"`, unlock it, then `SWARMA_KEYCHAIN_TEST_PATH=<that path> go test -tags keychaintest -p 1 -parallel 2 -run 'TestTestKeychain\|TestKeychainDarwin' ./internal/keychain/ ./internal/facade/`. The `keychaintest` tag is for tests only and never goes into release builds. | Throwaway test keychain only; never the login keychain. |

Tests use published public BIP84 vectors and fake loopback RPC fixtures with disposable credentials. They never discover or contact a live node. A pruned-node fixture establishes that the adapter makes no historical-block calls; it does not establish live-node qualification. CI runs serial tests and static checks on macOS.

Grant tests drive the three grant commands end to end against regtest- and main-pinned loopback fixture nodes with the test-only signer, reuse the pinned LIP-0013 contract, binding and consent-tag vectors ([provenance](internal/facade/testdata/lip0013/README.md)), check that no output carries any encoding of a test secret key, and run planted overlay controls that remove one check at a time. Note that the planted controls and the Nostr observation tests run `go` from `runtime.GOROOT()`, so run the suite without `-trimpath` in `GOFLAGS`.

The six `grant` commands follow the same `--json` envelope rules as the seven above; `grant sign` also writes the seal ledger named by `--seal-ledger`, locking the ledger's directory with `flock` and committing through a temporary `.<ledger>.tmp-<hex>` file beside it by an atomic rename exchange (`renameat2` `RENAME_EXCHANGE` on Linux, `renameatx_np` `RENAME_SWAP` on macOS; without it a final sign refuses). A leftover temporary file from an interrupted update fences draft and sign (`LEDGER_FILE`) until `.temp/bin/swarma-identity grant ledger-recover --seal-ledger "$PWD/.temp/seal-ledger.json" --json` merges it back. Cross-compile check for both targets: `GOTOOLCHAIN=local GOOS=darwin GOARCH=arm64 go build -o .temp/bin/swarma-identity-darwin-arm64 ./cmd/swarma-identity`, and the same with `GOOS=linux GOARCH=amd64`; binaries go to `.temp/bin/`.

Transaction requests use explicitly supplied native P2WPKH funding outpoints,
full public parent transactions and a separate funding/change script pin.
They select no wallet or key. The seal creation floor is 100000 atoms, following
the pinned implementation profile; the LIP specifies no numeric denomination.
There is no broadcast flag. External signing/publication and confirmed observation
remain required. `grant sign` retains its local-ledger checks; the chain seal
pre-check runs in `grant anchor`. See [request schemas and refusal codes](docs/GRANT.md#grant-seal---config-file---request-file---json).

Transaction tests reuse the grant loopback RPC fake, freeze the 72-byte frame,
compare transaction and PSBT bytes, pair state/funding/frame/backend refusals with
valid controls and plant bounded removals of critical checks. The fake's
`gettxout [txid,vout,true]` semantics were checked against nc28.0 source: null
means missing or spent, including mempool spends. These tests do not qualify a
live wallet/node, consensus, relay policy or a broadcast.

Nostr tests use pinned public BIP-340 verification vectors, an already-signed neutral kind-0 event and frozen canonical byte/hash fixtures. No signing or key generation is used. Source revisions and fixture limits are recorded in [the fixture notes](internal/facade/testdata/nostr/README.md).

Use a standalone Go distribution for the full suite. The Nostr observer uses standard-library overlays; Go refuses these when its toolchain itself resides beneath `GOMODCACHE`.

Fresh registration requests enforce the dispatch byte ceilings before creating
their output bundle; see [registration limits](docs/REGISTRATION.md).

The offline Go planner in `internal/registration` constructs PSBTv0 reservation and reveal phases from a fixed public funding transaction, an independently selected account pin and immutable policy. It preserves exact approved value bytes and extracts the social and grant keys through the reveal-building path. Its public Core 28.0 fixtures cover both release modes. Plan construction establishes no chain state, signing, protected receipt provenance or broadcast permission. See [fixture details](internal/registration/testdata/core28/README.md).

The same internal library prepares immutable signing requests and review frames, checks preserved PSBT maps and every public BIP143 signature, and assembles final witnesses. Result checks bind receipts to the request and require a zero exit plus the exact acknowledgement hashing the complete original result file. Reported journal fields remain unauthenticated public metadata; these checks grant no custody, owner-presence or release authority. The CLI exposes the unsigned file interface below; protected signer integration remains separate.

## Offline registration bundles

`registration account-pin`, `registration reserve`, `registration reveal`,
`registration request` and `registration check-result` build unsigned local
bundles or verify public completed results. They use explicit independently
pinned profile/account files and create a new private output directory.
They invoke no vault, signer, node or network. Exact argv, schemas, limits,
retained-context rules and refusal codes are in [the registration file
contract](docs/REGISTRATION.md). Use the existing Go build/test commands above;
keep local inputs, bundles and test captures under `.temp/`.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
