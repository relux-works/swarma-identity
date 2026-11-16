# Pinned public grant vectors

`grant-v4.json` is copied without changes from
[the upstream vector file](https://github.com/relux-works/swarma-link-spec/blob/3bef542fc8c0a5dedeeaaa990bd7f93abe194813/vectors/LIP-0020/grant-v4.json),
version 0.1.53, commit `3bef542fc8c0a5dedeeaaa990bd7f93abe194813`.

SHA-256:
`66d4a5b1738b746bd5403e30ed1bbd30be9aac256a2559795d038f3455b2b106`.
Tests independently pin this value and their expected identities.

`wire-vectors.json` is copied without changes from `vectors/LIP-0020/wire-vectors.json`
at the same revision, with SHA-256
`0d14f471e4a0a39c99455fab663bdce5c05f2c97fe2383ecbe95717721d53ae0`.
Tests pin it independently and run every in-scope group. Issuer-only duties
are excluded; by-name evidence stages explicitly refuse as unsupported.

These external vector files are licensed under
[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).
The upstream [copyright notice and creator credits](https://github.com/relux-works/swarma-link-spec/blob/3bef542fc8c0a5dedeeaaa990bd7f93abe194813/LICENSE.md)
are retained by reference to that exact revision. The repository's Apache-2.0
license does not relicense these fixtures. No endorsement is implied.

All keys and signatures in the file are published test data; none belongs to
anybody. No transaction, name, seal or block existence is established by it.
