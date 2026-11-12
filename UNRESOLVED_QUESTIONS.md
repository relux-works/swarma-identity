# Open product decisions

- Live qualification requires the node custodian to select the endpoint, credential-file path and finite read/scan scope. Unit fixtures establish no live-node permission.
- Supporting other Core versions or non-loopback transports requires separate capability and transport qualification.
- Wallet-visible balance requires a separately provisioned and qualified watch-only wallet; it is not implemented or automatically substituted.
- Node lifecycle, name transactions, Nostr/NIP-05 and Link validation require their own interaction contracts. The current raw-read commands establish none of those interfaces.
- `identity show` reports a v3 value problem as a result `reason` (`VALUE_NOT_V3`, `LANDLORD_NOT_V3`) with exit 0, following the v3 identity design. Whether consumers would rather receive a refusal for an agent whose landlord does not resolve is open.
- The design's register/show refusal names (`NAME_MISSING`) and exit codes (1 refusal, 2 retry) differ from this CLI's existing codes (`NAME_NOT_FOUND`, exit 3 refusal, exit 4 retry). `identity show` keeps the existing CLI codes.
