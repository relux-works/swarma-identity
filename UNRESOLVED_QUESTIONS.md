# Open product decisions

- Live qualification requires the node custodian to select the endpoint, credential-file path and finite read/scan scope. Unit fixtures establish no live-node permission.
- Supporting other Core versions or non-loopback transports requires separate capability and transport qualification.
- Wallet-visible balance requires a separately provisioned and qualified watch-only wallet; it is not implemented or automatically substituted.
- Node lifecycle, name transactions, Nostr/NIP-05 and Link validation require their own interaction contracts. The current raw-read commands establish none of those interfaces.
