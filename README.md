# swarma-identity

A Swarma module for an agent-facing facade over Namecoin and Nostr. The current CLI implements six public-data operations:

- Node health for an explicitly configured loopback Namecoin Core 28.0 node.
- Active name reads with exact value bytes, returned as hex.
- Offline BIP-32 public derivation of Namecoin P2WPKH or P2PKH addresses.
- A bounded current-UTXO scan for both branches of a public P2WPKH account.
- Offline preparation of unsigned Nostr kind-0 profile events and their canonical bytes.
- Offline verification of an already-signed public kind-0 event's id and BIP-340 signature.

Node deployment/lifecycle, name transactions, Link value validation, Nostr publication and NIP-05 resolution remain planned. Wallet-visible balance is not implemented. No plugin registration interface is exposed by this version.

The CLI uses no private keys or signer. Public derivation and both Nostr operations work without a node, wallet or relay. Online commands read only the selected node and never import a wallet, sign, broadcast, restart a service or automatically retry a scan. Validating a Nostr signature establishes no publication, freshness or identity authority.

## Build and use

Target: macOS, Go 1.25.14. From the repository root:

```sh
mkdir -p .temp/bin
GOTOOLCHAIN=local GOMAXPROCS=2 go build -p 1 -o .temp/bin/swarma-identity ./cmd/swarma-identity
.temp/bin/swarma-identity address derive --request .temp/derive.json --json
.temp/bin/swarma-identity node health --config .temp/node.json --json
.temp/bin/swarma-identity name show --config .temp/node.json --request .temp/name.json --json
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
| Go 1.25.14 | Build: command above. Test: `GOTOOLCHAIN=local GOMAXPROCS=2 go test -p 1 -parallel 1 ./...`. Static checks: `GOTOOLCHAIN=local GOMAXPROCS=2 go vet -p 1 ./...`. | Binary under `.temp/bin/`; redirect logs to `.temp/`. |
| gofmt | Format: `gofmt -w cmd/swarma-identity internal/facade`. | Updates those source files. |
| swarma-identity | Six commands above; every invocation requires `--json`. | One JSON envelope on stdout; fixed bounded diagnostics on stderr. |

Tests use published public BIP84 vectors and fake loopback RPC fixtures with disposable credentials. They never discover or contact a live node. A pruned-node fixture establishes that the adapter makes no historical-block calls; it does not establish live-node qualification. CI runs serial tests and static checks on macOS.

Nostr tests use pinned public BIP-340 verification vectors, an already-signed neutral kind-0 event and frozen canonical byte/hash fixtures. No signing or key generation is used. Source revisions and fixture limits are recorded in [the fixture notes](internal/facade/testdata/nostr/README.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
