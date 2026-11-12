# swarma-identity

A Swarma module for an agent-facing facade over Namecoin and Nostr. The current CLI implements seven public-data operations:

- Node health for an explicitly configured loopback Namecoin Core 28.0 node.
- Active name reads with exact value bytes, returned as hex.
- A v3 (LIP-0004) identity projection of an `id/` name: landlord or agent keys, the agent's resolved landlord, or `VALUE_NOT_V3`.
- Offline BIP-32 public derivation of Namecoin P2WPKH or P2PKH addresses.
- A bounded current-UTXO scan for both branches of a public P2WPKH account.
- Offline preparation of unsigned Nostr kind-0 profile events and their canonical bytes.
- Offline verification of an already-signed public kind-0 event's id and BIP-340 signature.

Node deployment/lifecycle, name transactions, grant validation, Nostr publication and NIP-05 resolution remain planned. Wallet-visible balance is not implemented. No plugin registration interface is exposed by this version.

The CLI uses no private keys or signer. Public derivation and both Nostr operations work without a node, wallet or relay. Online commands read only the selected node and never import a wallet, sign, broadcast, restart a service or automatically retry a scan. Validating a Nostr signature establishes no publication, freshness or identity authority.

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
```

The node custodian must authorize online use and select the credential file. A scan occupies the node's shared scan resource. The matched UTXO total covers only the explicit range; it is not an entire-account or spendable balance. Coinbase outputs can be included. Mempool, history and name-encumbered outputs are excluded.

See [the CLI contract](docs/CLI.md) for input schemas, result fields, deadlines and refusals, and [the module skill](agents/skills/swarma-identity/SKILL.md) for agent use. Keep account-specific inputs and qualification evidence in ignored local files. Never put credentials or private keys in command arguments or diagnostics.

## Development

Scratch output goes to `.temp/`, which Git ignores.

### Tools

| Tool | Purpose and exact entry point | Output |
| --- | --- | --- |
| Go 1.26.8 | Build: command above. Test: `GOTOOLCHAIN=local GOMAXPROCS=2 go test -p 1 -parallel 1 ./...`. Static checks: `GOTOOLCHAIN=local GOMAXPROCS=2 go vet -p 1 ./...`. | Binary under `.temp/bin/`; redirect logs to `.temp/`. |
| gofmt | Format: `gofmt -w cmd/swarma-identity internal/facade internal/registration`. | Updates those source files. |
| swarma-identity | Seven commands above; every invocation requires `--json`. | One JSON envelope on stdout; fixed bounded diagnostics on stderr. |

Tests use published public BIP84 vectors and fake loopback RPC fixtures with disposable credentials. They never discover or contact a live node. A pruned-node fixture establishes that the adapter makes no historical-block calls; it does not establish live-node qualification. CI runs serial tests and static checks on macOS.

Nostr tests use pinned public BIP-340 verification vectors, an already-signed neutral kind-0 event and frozen canonical byte/hash fixtures. No signing or key generation is used. Source revisions and fixture limits are recorded in [the fixture notes](internal/facade/testdata/nostr/README.md).

Use a standalone Go distribution for the full suite. The Nostr observer uses standard-library overlays; Go refuses these when its toolchain itself resides beneath `GOMODCACHE`.

The offline Go planner in `internal/registration` constructs PSBTv0 reservation and reveal phases from a fixed public funding transaction, an independently selected account pin and immutable policy. It preserves exact approved value bytes and extracts the social and grant keys through the reveal-building path. Its public Core 28.0 fixtures cover both release modes. Plan construction establishes no chain state, signing, protected receipt provenance or broadcast permission. See [fixture details](internal/registration/testdata/core28/README.md).

The same internal library prepares immutable signing requests and review frames, checks preserved PSBT maps and every public BIP143 signature, and assembles final witnesses. Result checks bind receipts to the request and require a zero exit plus the exact acknowledgement hashing the complete original result file. Reported journal fields remain unauthenticated public metadata; these checks grant no custody, owner-presence or release authority. Namecoin transaction commands and protected signer integration are not yet exposed by the CLI.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
