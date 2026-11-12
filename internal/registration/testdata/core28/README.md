# Public registration fixtures

Both transaction graphs were constructed and executed with Namecoin Core28.0.0 in isolated regtest, using disposable authority derived from published BIP32 test vector1. The account public key and openings are public test data. No private key, production account, wallet file or RPC credential is included.

`core-graph.json` records actual Core unsigned transaction and PSBT bytes; both modes completed and confirmed exact name values. Phase manifests and reveal-value pins are immutable wire-v2 reference bytes. Parent request/sitting metadata is synthetic format data, with no claim of presence or protected journal provenance. Planner tests compare public construction only; signing, custody, chain membership and broadcast permission require separate checks.

References: [Core nc28.0](https://github.com/namecoin/namecoin-core/tree/nc28.0), [BIP32 test vectors](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors).
