# `swarma-s7 static-gate/1` example vector

- `example-statement.ccj`: the exact CCJ-1 bytes of one example statement G, 1355 bytes, with no final line feed. It is the example of revision 2 of the statement format with one placeholder changed: `host.label` is `example`. All values are placeholders, and `approver.key` is not a key anyone holds. It is not for signing.
- `example-preimage.sha256`: the SHA-256 of the 1379-byte preimage `ASCII("swarma-s7 static-gate/1") || 0x0a || <the bytes of example-statement.ccj>`, as lowercase hex and one line feed. It was computed with `shasum`, not with the code under test:

  ```sh
  { printf 'swarma-s7 static-gate/1\n'; cat example-statement.ccj; } | shasum -a 256
  ```

The two files are a pair. `TestStaticGateExampleVector` reads both and hard-codes neither, so the pair can be replaced by another statement of the same format with its own digest. The other tests in `keychain_sign_static_gate_test.go` edit named members of this example (and two of them state its values literally); with another statement, each edit that no longer finds its target fails its test by name instead of passing silently.
