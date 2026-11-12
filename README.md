# swarma-identity

A Swarma module for an agent-facing facade over Namecoin and Nostr. The current CLI implements seven public-data operations and three trust-grant issuance steps:

- Node health for an explicitly configured loopback Namecoin Core 28.0 node.
- Active name reads with exact value bytes, returned as hex.
- A v3 (LIP-0004) identity projection of an `id/` name: landlord or agent keys, the agent's resolved landlord, or `VALUE_NOT_V3`.
- Offline BIP-32 public derivation of Namecoin P2WPKH or P2PKH addresses.
- A bounded current-UTXO scan for both branches of a public P2WPKH account.
- Offline preparation of unsigned Nostr kind-0 profile events and their canonical bytes.
- Offline verification of an already-signed public kind-0 event's id and BIP-340 signature.
- Two-phase Grant v3 issuance with a LIP-0013 trust contract: `grant draft` builds the exact bytes and the digests to sign, `grant consent` verifies the grantee's externally signed consent, and `grant sign` verifies the landlord's external signatures against the on-chain grant key and assembles the signed grant, its `grant_id` and its issuance commitment. See [the grant contract](docs/GRANT.md).

Node deployment/lifecycle, name transactions, seal creation and issuance anchoring, grant verification, Nostr publication and NIP-05 resolution remain planned. Wallet-visible balance is not implemented. No plugin registration interface is exposed by this version.

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
```

The node custodian must authorize online use and select the credential file. A scan occupies the node's shared scan resource. The matched UTXO total covers only the explicit range; it is not an entire-account or spendable balance. Coinbase outputs can be included. Mempool, history and name-encumbered outputs are excluded.

See [the CLI contract](docs/CLI.md) for input schemas, result fields, deadlines and refusals, and [the module skill](agents/skills/swarma-identity/SKILL.md) for agent use. Keep account-specific inputs and qualification evidence in ignored local files. Never put credentials or private keys in command arguments or diagnostics.

## Development

Scratch output goes to `.temp/`, which Git ignores.

### Tools

| Tool | Purpose and exact entry point | Output |
| --- | --- | --- |
| Go 1.26.8 | Build: command above. Test: `GOTOOLCHAIN=local GOMAXPROCS=2 go test -p 1 -parallel 1 ./...`. Static checks: `GOTOOLCHAIN=local GOMAXPROCS=2 go vet -p 1 ./...`. | Binary under `.temp/bin/`; redirect logs to `.temp/`. |
| gofmt | Format: `gofmt -w cmd/swarma-identity internal/facade`. | Updates those source files. |
| swarma-identity | Seven commands above; every invocation requires `--json`. | One JSON envelope on stdout; fixed bounded diagnostics on stderr. |

Tests use published public BIP84 vectors and fake loopback RPC fixtures with disposable credentials. They never discover or contact a live node. A pruned-node fixture establishes that the adapter makes no historical-block calls; it does not establish live-node qualification. CI runs serial tests and static checks on macOS.

Grant tests drive the three grant commands end to end against regtest- and main-pinned loopback fixture nodes with the test-only signer, reuse the pinned LIP-0013 contract, binding and consent-tag vectors ([provenance](internal/facade/testdata/lip0013/README.md)), check that no output carries any encoding of a test secret key, and run planted overlay controls that remove one check at a time. Note that the planted controls and the Nostr observation tests run `go` from `runtime.GOROOT()`, so run the suite without `-trimpath` in `GOFLAGS`.

The three `grant` commands follow the same `--json` envelope rules as the seven above; `grant sign` also writes the seal ledger named by `--seal-ledger`, locking the ledger's directory with `flock` and committing through a temporary `.<ledger>.tmp-<hex>` file beside it by an atomic rename exchange (`renameat2` `RENAME_EXCHANGE` on Linux, `renameatx_np` `RENAME_SWAP` on macOS; without it a final sign refuses). Cross-compile check for both targets: `GOTOOLCHAIN=local GOOS=darwin GOARCH=arm64 go build -o .temp/bin/swarma-identity-darwin-arm64 ./cmd/swarma-identity`, and the same with `GOOS=linux GOARCH=amd64`; binaries go to `.temp/bin/`.

Nostr tests use pinned public BIP-340 verification vectors, an already-signed neutral kind-0 event and frozen canonical byte/hash fixtures. No signing or key generation is used. Source revisions and fixture limits are recorded in [the fixture notes](internal/facade/testdata/nostr/README.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
