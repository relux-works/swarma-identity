# swarma-identity

A swarma module: one agent-facing CLI and skill over a Namecoin full node and a Nostr client.

Planned scope (the contract comes first, then a minimal usable version):

- Namecoin node: deploy at user level, configure, start, stop, upgrade, sync and health.
- Names: read (`name_show`), validate values against the Link spec, build unsigned name transactions (PSBT), broadcast, and remind before expiry.
- Nostr: publish a profile, resolve NIP-05 identifiers, including `.bit` names.

The module never holds private keys. Signing goes through a separate signer, such as swarma-keyvault. The node RPC endpoint, relays and the signer are configuration. Without one of them, the other parts still work.

Status: contract in progress; no code yet.

## Development

Scratch output goes to `.temp/`, which Git ignores.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
