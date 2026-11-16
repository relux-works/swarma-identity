# `swarma-s7 static-gate/1` example and published vectors

Source of every file here: `relux-works/swarma-keymaker` at commit `a3b9def3133e76d374d158cd0eb3072a739de7d3` (`spec/keymaker-static-gate.md`, `vectors/staticgate/`). The files are copies; that module is not imported.

- `example-statement.ccj`: the exact CCJ-1 bytes of the genuine statement of the published format, 1491 bytes, with no final line feed. It is a byte-for-byte copy of `vectors/staticgate/genuine.ccj`. All values are placeholders, `approver.key` is CSV index 1 of the published BIP-340 test vectors, and the statement is not for signing.
- `example-preimage.sha256`: the SHA-256 of the 1515-byte preimage `ASCII("swarma-s7 static-gate/1") || 0x0a || <the bytes of example-statement.ccj>`, as lowercase hex and one line feed. The value is the one section 9 of the published format states; it was not computed with the code under test. It can be recomputed with:

  ```sh
  { printf 'swarma-s7 static-gate/1\n'; cat example-statement.ccj; } | shasum -a 256
  ```

- `published/vectors.json`: a byte-for-byte copy of `vectors/staticgate/vectors.json` (180 rows: 21 passes and 159 refusals). Verify a copy against a checkout of the source commit with `cmp`.

`TestStaticGateExampleVector` reads the pair and hard-codes neither. `TestStaticGatePublishedGenuine` states the published digest and the published signature literally. `TestStaticGatePublishedVectors` runs every row of `published/vectors.json` through the signer's statement check. The other tests in `keychain_sign_static_gate_test.go` edit named members of the example (and some state its values literally); with another statement, each edit that no longer finds its target fails its test by name instead of passing silently.

Rows of `published/vectors.json` and what the signer is held to:

| Rows | Count | Held here |
| --- | ---: | --- |
| `expect` is `pass` | 21 | the statement check admits the statement |
| `checks` names `size`, `codec`, `canonical`, `depth`, `members`, `fixed` or `shape` | 84 | `STATIC_GATE_FORM` before the display |
| `checks` names `window_width` and none of the above | 6 | `STATIC_GATE_WINDOW` |
| every other row | 69 | out of scope: the refusal comes from a consumer-side input (key pin, digest pin, wire signature, machine-id, clock, operation class, expected section or association bytes) that the signer does not hold |

Among the 84 are nine rows that the reference refuses with another code because its pin checks run first (`key-approver-missing`, `key-member-uppercase`, `key-member-nonhex`, `key-member-nonstring`, `key-approver-unreadable`, `key-approver-key-missing`, `order-pin-before-size`, `order-pin-before-codec`, `order-key-before-form`); the signer has no pin, so the form cause decides. Among the 69, the statements of `signature-key-at-p` and `signature-key-nonliftable` name an `approver.key` that is not a curve point; the signer refuses those with `STATIC_GATE_FORM`, which is stricter than the reference, and admits the other 67 statements.
