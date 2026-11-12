# LIP-0013 trust-contract vectors

`trust-vectors.json` is copied byte for byte from
[`relux-works/swarma-link-spec`](https://github.com/relux-works/swarma-link-spec)
`vectors/LIP-0013/trust-vectors.json` at commit `8ea31e039881bc8d51a510534b13118490bd9219`
(pull request 19, LIP-0013 accepted, landing pending).

SHA-256 of the file: `9c29cddd739d56c5d15f4663c3cc923c6ea016730fc62634bff4b4214bf27ff8`.
`TestTrustVectorsPinned` checks this digest.

The grant tests use the contract, binding and consent-tag vectors. The
envelope vectors (kind 8185) belong to the planned envelope commands; only one envelope
signature is used, to check the test signer's BIP-340 path. The keys in the
file are the published BIP-340 test keys, never anyone's real keys.
