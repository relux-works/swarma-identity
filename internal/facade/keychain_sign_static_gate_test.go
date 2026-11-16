package facade

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/relux-works/swarma-identity/internal/keypolicy"
	"github.com/relux-works/swarma-identity/internal/keysign"
)

// The format's constants, written out here and not taken from the
// implementation.
const (
	gateLabel  = "swarma-static-gate-g1"
	gateTag    = "swarma-s7 static-gate/1"
	gateSchema = "swarma-keychain/sign-static-gate/1"
)

// gateExample is the example statement and the pinned SHA-256 of its
// preimage, both read from testdata (see testdata/static-gate/README.md).
func gateExample(t *testing.T) ([]byte, string) {
	t.Helper()
	statement, err := os.ReadFile("testdata/static-gate/example-statement.ccj")
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := os.ReadFile("testdata/static-gate/example-preimage.sha256")
	if err != nil {
		t.Fatal(err)
	}
	return statement, strings.TrimSuffix(string(pinned), "\n")
}

// gateDigest is the ground truth of the digest: SHA-256 over the tag, one
// line feed and the statement bytes, spelled here without the signer's
// preimage function.
func gateDigest(statement []byte) string {
	return sha256Hex(append([]byte(gateTag+"\n"), statement...))
}

// gateStatement is the example with approver.key set to a published BIP-340
// test key, so that a fake store can hold the matching key.
func gateStatement(t *testing.T, key int) []byte {
	t.Helper()
	example, _ := gateExample(t)
	return replaceOnce(t, example, `"key":"`+strings.Repeat("2", 64)+`"`, `"key":"`+testsigner_public(t, key)+`"`)
}

func gateRequest(statement []byte) StaticGateSignRequest {
	return StaticGateSignRequest{Schema: gateSchema, Purpose: "static_gate", StatementB64: base64.StdEncoding.EncodeToString(statement), Digest: gateDigest(statement)}
}

// newGateKC is newKC (the landlord's grant key, published test key 1, under
// the grant label) with a second key from its own keygen under the
// static-gate label: the published test key `key`, with the given policy.
func newGateKC(t *testing.T, answer string, key int, access keypolicy.Policy) *kcHarness {
	t.Helper()
	h := newKC(t, answer)
	if _, err := keysign.NewWithStore(h.store, fixedReader(mustDecode(bip340Secrets[key]))).Keygen(gateLabel, access); err != nil {
		t.Fatal(err)
	}
	h.log = nil
	return h
}

func (h *kcHarness) signAs(label string, request any) (Envelope, int) {
	return h.run("keychain", "sign", "--label", label, "--request", writeInput(h.t, request))
}

// signGate signs one statement with the static-gate key (published test key
// 2) and returns the terminal transcript captured at the first secret read.
func signGate(t *testing.T, statement []byte) (string, StaticGateSignResult) {
	t.Helper()
	h := newGateKC(t, confirmWord, keyOther, keypolicy.CurrentSet)
	r := gateRequest(statement)
	e, code := h.signAs(gateLabel, r)
	mustOK(t, e, code)
	res := resultAs[StaticGateSignResult](t, e)
	if !h.keyRead || res.Digest != r.Digest || !sigValid(testsigner_public(t, keyOther), r.Digest, res.Signature) {
		t.Fatalf("positive control did not sign the requested digest: %v", h.log)
	}
	if len(h.log) < 4 || h.log[0] != "public:"+gateLabel || h.log[1] != "show" || h.log[2] != "confirm" || h.log[3] != "secret:"+gateLabel || h.count("show") != 1 || h.count("secret:") != 1 {
		t.Fatalf("unexpected approval/secret ordering: %v", h.log)
	}
	return h.preKey, res
}

// refusedGate asserts one refusal with its exact code and exit status, and
// that nothing was shown, nothing was confirmed and no secret was read.
func refusedGate(t *testing.T, h *kcHarness, e Envelope, code int, want string, exit int) {
	t.Helper()
	mustRefuse(t, e, code, want)
	if code != exit {
		t.Fatalf("exit %d, want %d", code, exit)
	}
	if h.count("show") != 0 || h.count("confirm") != 0 || h.count("secret:") != 0 {
		t.Fatalf("refused request reached the display or the key: %v", h.log)
	}
}

// padGate appends a member zz_pad so that the preimage has exactly total
// bytes; the result stays canonical (zz_pad sorts after v).
func padGate(t *testing.T, statement []byte, total int) []byte {
	t.Helper()
	n := total - len(gateTag) - 1 - len(statement) - len(`,"zz_pad":""`)
	if n < 0 {
		t.Fatal("fixture: the statement is too long to pad")
	}
	out := replaceOnce(t, statement, `,"v":1}`, `,"v":1,"zz_pad":"`+strings.Repeat("a", n)+`"}`)
	if len(gateTag)+1+len(out) != total {
		t.Fatalf("fixture: padded preimage is %d bytes, want %d", len(gateTag)+1+len(out), total)
	}
	return out
}

func unescapeHex(s string) []byte {
	return hexEscape.ReplaceAllFunc([]byte(s), func(m []byte) []byte {
		b, _ := hex.DecodeString(string(m[2:]))
		return b
	})
}

// Claim: the signer's preimage for the format's example statement is exactly
// ASCII(tag) || 0x0a || statement, with no final line feed and within 8192
// bytes, and its SHA-256 is the digest pinned beside the example, which was
// computed outside this code. The example is canonical CCJ-1, and the
// statement check admits it under that digest and returns that digest.
func TestStaticGateExampleVector(t *testing.T) {
	statement, pinned := gateExample(t)
	if !lowerHex(pinned, 32) || len(statement) == 0 {
		t.Fatal("fixture: the example or its pinned digest is malformed")
	}
	pre := staticGatePreimage(statement)
	if want := append([]byte("swarma-s7 static-gate/1\n"), statement...); !bytes.Equal(pre, want) {
		t.Fatal("the preimage is not tag || 0x0a || statement")
	}
	if pre[len(pre)-1] == '\n' || len(pre) > 8192 || pre[23] != 0x0a || bytes.Count(pre, []byte("\n")) != 1 {
		t.Fatal("the preimage has a final line feed, a second line feed, or is over the limit")
	}
	if got := sha256Hex(pre); got != pinned {
		t.Fatalf("preimage SHA-256 %s, pinned %s", got, pinned)
	}
	if _, ok := ccjCanonical(statement); !ok {
		t.Fatal("the example is not canonical CCJ-1")
	}
	g, f := checkStaticGate(statement, pinned, gateLabel)
	if f != nil || hex.EncodeToString(g.digest) != pinned {
		t.Fatalf("the example is not admitted under its pinned digest: %+v", f)
	}
}

// Claim: for a static-gate statement, the terminal transcript at the first
// secret read shows (a) as "path = value", exactly the values of the
// statement bytes, every one and nothing else, in a block that states their
// number; (b) the bytes that are hashed, verbatim: the tag, the line feed as
// \x0a and the statement; (c) the digest that is signed, which is the
// SHA-256 of those displayed bytes; (d) the request schema, the purpose, the
// label, the policy and the signing key. The ground truth is the example
// file decoded by an independent JSON decoder (committedLines), not the
// signer's reader. The returned signature verifies under approver.key.
func TestStaticGateDisplayCoversEveryPreimageField(t *testing.T) {
	statement := gateStatement(t, keyOther)
	digest := gateDigest(statement)
	shown, res := signGate(t, statement)
	want := committedLines(t, gateTag+"\n", statement, digest)
	for _, l := range want {
		if !strings.Contains(shown, "\n    "+l+"\n") {
			t.Fatalf("pre-key-read display lacks statement value %q", l)
		}
	}
	got := displayBlock(shown, fmt.Sprintf("Statement members  : all %d values of the statement by path, in the order of the signed bytes", len(want)))
	sortedGot, sortedWant := slices.Clone(got), slices.Clone(want)
	slices.Sort(sortedGot)
	slices.Sort(sortedWant)
	if len(want) < 20 || !slices.Equal(sortedGot, sortedWant) {
		t.Fatalf("member block is not exactly the statement's values:\n got %q\nwant %q", got, want)
	}
	// The block follows the order of the signed bytes: each line's value
	// starts later in the statement than the one before.
	last := -1
	for _, l := range got {
		_, value, _ := strings.Cut(l, " = ")
		at := bytes.Index(statement[last+1:], []byte(value))
		if at < 0 {
			t.Fatalf("member line %q is out of the order of the bytes", l)
		}
		last += 1 + at
	}
	var exact []byte
	for i, l := range displayBlock(shown, "  exact bytes      :") {
		off, text, ok := strings.Cut(l, "  ")
		if !ok || off != fmt.Sprintf("%04d", i*64) {
			t.Fatalf("exact-bytes line %d malformed: %q", i, l)
		}
		exact = append(exact, unescapeHex(text)...)
	}
	if string(exact) != gateTag+"\n"+string(statement) {
		t.Fatalf("display does not show the hashed bytes verbatim:\n got %q", exact)
	}
	for _, line := range []string{
		"\n=== SWARMA STATIC-GATE KEY: SIGNING REQUEST ===\n",
		"\nRequest schema     : " + gateSchema + "\n",
		"\nPurpose            : static_gate; this key signs no grant, no consent and no seal spend, and no other key signs this purpose\n",
		"\nKeychain label     : " + gateLabel + "\n",
		"\nAccess policy      : biometry-current-set (this-device-only)\n",
		"\nSigning key x-only : " + testsigner_public(t, keyOther) + " (equals approver.key of the statement)\n",
		"\nSignature 1        : BIP-340, purpose static_gate\n",
		"\n  digest           : " + digest + "\n",
		fmt.Sprintf("\n  SHA-256 of       : the %d bytes below: tag \"%s\" (23 bytes) || \\x0a || canonical statement (%d bytes), no final line feed\n", len(statement)+24, gateTag, len(statement)),
	} {
		if !strings.Contains(shown, line) {
			t.Fatalf("display lacks %q", line)
		}
	}
	if res.Purpose != "static_gate" || res.Label != gateLabel || res.XOnlyKey != testsigner_public(t, keyOther) || res.AccessPolicy != keypolicy.CurrentSet || res.StatementB64 != base64.StdEncoding.EncodeToString(statement) {
		t.Fatalf("result %+v", res)
	}
}

// Claim: the display knows no section. (1) A statement with an extra
// top-level section that no code names, holding nested objects, an array, an
// empty object and a member name with a dot, signs, and every value of that
// section is shown by its path, the dotted name quoted so that it cannot pass
// for a nested path; the section is listed among the sections. (2) The
// source section is shown when present and its absence needs nothing: the
// same statement without it signs and shows no source line. No value is
// shortened: a 6000-byte value is shown in full.
func TestStaticGateDisplayUnknownSection(t *testing.T) {
	base := gateStatement(t, keyOther)
	t.Run("late-section", func(t *testing.T) {
		statement := replaceOnce(t, base, `,"v":1}`, `,"v":1,"zz_late":{"a_list":[1,"two",{}],"nested":{"deep":{"deeper":"x"}},"odd.name":"y"}}`)
		shown, _ := signGate(t, statement)
		for _, l := range []string{`zz_late.a_list[0] = 1`, `zz_late.a_list[1] = "two"`, `zz_late.a_list[2] = {}`, `zz_late.nested.deep.deeper = "x"`, `zz_late["odd.name"] = "y"`} {
			if !strings.Contains(shown, "\n    "+l+"\n") {
				t.Fatalf("display lacks the unknown section's value %q", l)
			}
		}
		plain, _ := signGate(t, base)
		before := displayBlock(plain, "Statement members  : all 29 values of the statement by path, in the order of the signed bytes")
		after := displayBlock(shown, "Statement members  : all 34 values of the statement by path, in the order of the signed bytes")
		if len(before) != 29 || len(after) != 34 || !slices.Equal(after[:29], before) {
			t.Fatalf("the unknown section changed other lines or the count:\n got %q", after)
		}
		if !strings.Contains(shown, "\n  Sections, 15 top-level members, each shown in full below: approver, association, broker_d5, broker_time, dispatcher, gate_id, host, keymaker, kind, milestone, not_after, not_before, source, v, zz_late\n") {
			t.Fatal("the unknown section is not listed among the sections")
		}
	})
	t.Run("source-present-or-absent", func(t *testing.T) {
		with, _ := signGate(t, base)
		for _, l := range []string{`source.config_sha256 = "` + strings.Repeat("a", 64) + `"`, `source.generation = "s-example-1"`, `source.service_uid = 28604`} {
			if !strings.Contains(with, "\n    "+l+"\n") {
				t.Fatalf("display lacks %q", l)
			}
		}
		without, _ := signGate(t, replaceOnce(t, base, `"source":{"config_sha256":"`+strings.Repeat("a", 64)+`","generation":"s-example-1","service_uid":28604},`, ``))
		if strings.Contains(without, "source") || len(displayBlock(without, "Statement members  : all 26 values of the statement by path, in the order of the signed bytes")) != 26 {
			t.Fatal("a statement without the source section is not shown as its own 26 values")
		}
	})
	t.Run("long-value-in-full", func(t *testing.T) {
		long := strings.Repeat("0123456789", 600)
		shown, _ := signGate(t, replaceOnce(t, base, `,"v":1}`, `,"v":1,"zz_long":"`+long+`"}`))
		if !strings.Contains(shown, "\n    zz_long = \""+long+"\"\n") {
			t.Fatal("a long value is not shown in full")
		}
	})
}

// Claim: the scope text has one exact wording and is worded from the
// statement alone: for the example it is the literal text below (the host
// machine-id, the window with its length and the 72 h limit, every value of
// the caller association, the list of sections); a changed association
// member changes exactly its line.
func TestStaticGateScopeText(t *testing.T) {
	base := gateStatement(t, keyOther)
	want := []string{
		"One statement of kind swarma-s7 static-gate/1, version 1.",
		"Host: only the machine whose machine-id has the SHA-256 " + strings.Repeat("1", 64) + ".",
		"Window: not before 2026-11-17T00:00:00Z, not after 2026-11-19T00:00:00Z; length 48h0m0s, the limit is 72h0m0s.",
		"Caller association, 3 value(s), exactly as signed:",
		`  - association.caller_generation = "g-example-1"`,
		`  - association.caller_key = "ed25519:iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg"`,
		"  - association.caller_uid = 28601",
		"Sections, 14 top-level members, each shown in full below: approver, association, broker_d5, broker_time, dispatcher, gate_id, host, keymaker, kind, milestone, not_after, not_before, source, v",
	}
	shown, _ := signGate(t, base)
	if got := linesUnder(shown, "SCOPE TEXT         : ", "  "); !slices.Equal(got, want) {
		t.Fatalf("scope text:\n got %q\nwant %q", got, want)
	}
	if !strings.Contains(shown, "\nSCOPE TEXT         : worded by this signer from the statement bytes only; no wording comes from the request\n") {
		t.Fatal("display does not state where the scope text comes from")
	}
	shown, _ = signGate(t, replaceOnce(t, base, `"caller_uid":28601`, `"caller_uid":28699`))
	want[6] = "  - association.caller_uid = 28699"
	if got := linesUnder(shown, "SCOPE TEXT         : ", "  "); !slices.Equal(got, want) {
		t.Fatalf("scope text after one changed member:\n got %q\nwant %q", got, want)
	}
}

// Claim: the limits are inclusive where the format says "at most". A
// preimage of exactly 8192 bytes, a window of exactly 72 h and a statement
// nested exactly 8 deep each sign. They are the valid controls beside the
// 8193-byte, 72 h + 1 s and depth-9 refusals of TestStaticGateRefusals.
func TestStaticGateBoundaries(t *testing.T) {
	base := gateStatement(t, keyOther)
	for name, statement := range map[string][]byte{
		"preimage-8192-bytes": padGate(t, base, 8192),
		"window-72h":          replaceOnce(t, base, `"not_after":"2026-11-19T00:00:00Z"`, `"not_after":"2026-11-20T00:00:00Z"`),
		"depth-8":             replaceOnce(t, base, `,"v":1}`, `,"v":1,"zz":[[[[[[[1]]]]]]]}`),
	} {
		t.Run(name, func(t *testing.T) { signGate(t, statement) })
	}
}

// Claim: each condition below refuses a static-gate request with its exact
// closed code and exit status, before anything is shown and before any
// secret is read. Each negative changes one thing in the valid request, and
// that unchanged request signs in the same subtest (the valid control). A
// changed statement carries the digest of its own bytes, so the code comes
// from the rule named and not from a stale digest.
func TestStaticGateRefusals(t *testing.T) {
	base := gateStatement(t, keyOther)
	example, _ := gateExample(t)
	bytesOf := func(statement []byte) func(*StaticGateSignRequest) {
		return func(r *StaticGateSignRequest) { *r = gateRequest(statement) }
	}
	swap := func(from, to string) func(*StaticGateSignRequest) {
		return bytesOf(replaceOnce(t, base, from, to))
	}
	digest := func(d string) func(*StaticGateSignRequest) {
		return func(r *StaticGateSignRequest) { r.Digest = d }
	}
	association := `"association":{"caller_generation":"g-example-1","caller_key":"ed25519:iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg","caller_uid":28601},`
	approverKey := `"key":"` + testsigner_public(t, keyOther) + `"`
	cases := []struct {
		name, want string
		exit       int
		edit       func(*StaticGateSignRequest)
	}{
		// Digest binding: the requested digest is not the SHA-256 of
		// tag || 0x0a || statement.
		{"digest-of-another-statement", "DIGEST_BINDING", 3, digest(gateDigest(example))},
		{"digest-without-the-tag", "DIGEST_BINDING", 3, digest(sha256Hex(base))},
		{"digest-under-the-grant-domain", "DIGEST_BINDING", 3, digest(sha256Hex(append([]byte("swarma-grant-v3"), base...)))},
		{"digest-tag-without-line-feed", "DIGEST_BINDING", 3, digest(sha256Hex(append([]byte(gateTag), base...)))},
		{"digest-with-final-line-feed", "DIGEST_BINDING", 3, digest(sha256Hex(append(append([]byte(gateTag+"\n"), base...), '\n')))},
		{"digest-uppercase", "DIGEST_BINDING", 3, digest(strings.ToUpper(gateDigest(base)))},
		{"digest-empty", "DIGEST_BINDING", 3, digest("")},
		// Not canonical CCJ-1: the same statement in another spelling, or
		// a value CCJ-1 does not have.
		{"non-canonical-space", "STATIC_GATE_FORM", 3, swap(`{"approver":`, `{ "approver":`)},
		{"non-canonical-member-order", "STATIC_GATE_FORM", 3, swap(`"kind":"swarma-s7 static-gate/1","milestone":"G1.0",`, `"milestone":"G1.0","kind":"swarma-s7 static-gate/1",`)},
		{"non-canonical-escape", "STATIC_GATE_FORM", 3, swap(`"milestone":"G1.0"`, `"milestone":"\u00471.0"`)},
		{"non-canonical-final-line-feed", "STATIC_GATE_FORM", 3, bytesOf(append(slices.Clone(base), '\n'))},
		{"duplicate-member", "STATIC_GATE_FORM", 3, swap(`,"v":1}`, `,"v":1,"v":1}`)},
		{"non-integer-number", "STATIC_GATE_FORM", 3, swap(`"v":1}`, `"v":1.0}`)},
		{"exponent-number", "STATIC_GATE_FORM", 3, swap(`"caller_uid":28601`, `"caller_uid":2.8601e4`)},
		{"depth-9", "STATIC_GATE_FORM", 3, swap(`,"v":1}`, `,"v":1,"zz":[[[[[[[[1]]]]]]]]}`)},
		{"not-an-object", "STATIC_GATE_FORM", 3, bytesOf([]byte(`[]`))},
		// Size: one byte over the limit.
		{"preimage-8193-bytes", "STATIC_GATE_FORM", 3, bytesOf(padGate(t, base, 8193))},
		// The members the signer itself relies on.
		{"kind", "STATIC_GATE_FORM", 3, swap(`"kind":"swarma-s7 static-gate/1"`, `"kind":"swarma-s7 static-gate/2"`)},
		{"version", "STATIC_GATE_FORM", 3, swap(`,"v":1}`, `,"v":2}`)},
		{"approver-alg", "STATIC_GATE_FORM", 3, swap(`"alg":"bip340"`, `"alg":"ed25519"`)},
		{"approver-key-not-on-the-curve", "STATIC_GATE_FORM", 3, swap(approverKey, `"key":"`+strings.Repeat("5", 64)+`"`)},
		{"association-absent", "STATIC_GATE_FORM", 3, swap(association, ``)},
		{"association-empty", "STATIC_GATE_FORM", 3, swap(association, `"association":{},`)},
		{"machine-id-not-hex", "STATIC_GATE_FORM", 3, swap(`"machine_id_sha256":"1111`, `"machine_id_sha256":"X111`)},
		{"time-with-offset", "STATIC_GATE_FORM", 3, swap(`"not_after":"2026-11-19T00:00:00Z"`, `"not_after":"2026-11-19T00:00:00+00:00"`)},
		{"time-with-fraction", "STATIC_GATE_FORM", 3, swap(`"not_after":"2026-11-19T00:00:00Z"`, `"not_after":"2026-11-19T00:00:00.5Z"`)},
		// approver.label is not the label asked to sign.
		{"approver-label-other", "STATIC_GATE_LABEL", 3, swap(`"label":"swarma-static-gate-g1"`, `"label":"swarma-static-gate-g2"`)},
		{"approver-label-of-the-grant-key", "STATIC_GATE_LABEL", 3, swap(`"label":"swarma-static-gate-g1"`, `"label":"`+kcLabel+`"`)},
		// The window: over 72 h, empty or reversed.
		{"window-72h-and-one-second", "STATIC_GATE_WINDOW", 3, swap(`"not_after":"2026-11-19T00:00:00Z"`, `"not_after":"2026-11-20T00:00:01Z"`)},
		{"window-empty", "STATIC_GATE_WINDOW", 3, swap(`"not_after":"2026-11-19T00:00:00Z"`, `"not_after":"2026-11-17T00:00:00Z"`)},
		{"window-reversed", "STATIC_GATE_WINDOW", 3, swap(`"not_after":"2026-11-19T00:00:00Z"`, `"not_after":"2026-11-16T00:00:00Z"`)},
		// approver.key is not the key held under the label.
		{"approver-key-is-the-grant-key", "KEY_MISMATCH", 3, swap(approverKey, `"key":"`+testsigner_public(t, keyLandlord)+`"`)},
		{"approver-key-is-another-key", "KEY_MISMATCH", 3, swap(approverKey, `"key":"`+testsigner_public(t, keyRotated)+`"`)},
		// The request itself.
		{"purpose-of-a-grant", "BAD_INPUT", 2, func(r *StaticGateSignRequest) { r.Purpose = PurposeGrant }},
		{"purpose-empty", "BAD_INPUT", 2, func(r *StaticGateSignRequest) { r.Purpose = "" }},
		{"statement-base64-not-canonical", "BAD_INPUT", 2, func(r *StaticGateSignRequest) { r.StatementB64 += "\n" }},
		{"statement-empty", "BAD_INPUT", 2, func(r *StaticGateSignRequest) { r.StatementB64 = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			signGate(t, base) // the valid control
			h := newGateKC(t, confirmWord, keyOther, keypolicy.CurrentSet)
			r := gateRequest(base)
			c.edit(&r)
			e, code := h.signAs(gateLabel, r)
			refusedGate(t, h, e, code, c.want, c.exit)
		})
	}
}

// Claim: the two keys refuse each other's purposes, before the display and
// before any Keychain read (the store log stays empty). (1) Under the grant
// key's label a static-gate request is KEY_PURPOSE, also when the statement
// names that label and that key as approver; the same request signs under
// the static-gate label. (2) Under the static-gate label every grant request
// is KEY_PURPOSE: the contract signature and the grant signature under
// sign/1, the same two under sign/2, a seal spend alone, the full request,
// and a consent digest. For (2) the store holds the landlord's own key under
// both labels, so each request is valid for the key and only the label rule
// can refuse it; the same request under the grant label is the control (it
// signs; the consent digest is DIGEST_BINDING there, since no Keychain key
// signs a consent).
func TestStaticGateKeySeparation(t *testing.T) {
	t.Run("grant-key-refuses-static-gate", func(t *testing.T) {
		base := gateStatement(t, keyOther)
		signGate(t, base) // the valid control under the static-gate label
		asGrantKey := replaceOnce(t, gateStatement(t, keyLandlord), `"label":"swarma-static-gate-g1"`, `"label":"`+kcLabel+`"`)
		for name, statement := range map[string][]byte{"statement-of-the-gate-key": base, "statement-naming-the-grant-key": asGrantKey} {
			t.Run(name, func(t *testing.T) {
				h := newGateKC(t, confirmWord, keyOther, keypolicy.CurrentSet)
				e, code := h.signAs(kcLabel, gateRequest(statement))
				refusedGate(t, h, e, code, "KEY_PURPOSE", 3)
				if len(h.log) != 0 {
					t.Fatalf("a refused purpose reached the Keychain: %v", h.log)
				}
			})
		}
	})
	t.Run("static-gate-key-refuses-grant", func(t *testing.T) {
		f := preparedFlow(t)
		x := prepareV2(t, nil, nil)
		v1 := func(edit func(*KeychainSignRequest)) func() KeychainSignRequest {
			return func() KeychainSignRequest {
				r := fullRequest(t, f)
				edit(&r)
				return r
			}
		}
		v2 := func(edit func(*KeychainSignRequest)) func() KeychainSignRequest {
			return func() KeychainSignRequest {
				r := x.request()
				edit(&r)
				return r
			}
		}
		cases := []struct {
			name, control string // control: the refusal under the grant label, "" when it signs
			request       func() KeychainSignRequest
		}{
			{"sign-1-full", "", v1(func(r *KeychainSignRequest) {})},
			{"sign-1-contract", "", v1(func(r *KeychainSignRequest) { r.ToSign, r.SealSpend = r.ToSign[:1], nil })},
			{"sign-1-grant", "", v1(func(r *KeychainSignRequest) { r.ToSign, r.SealSpend = r.ToSign[1:], nil })},
			{"sign-1-seal-spend-only", "", v1(func(r *KeychainSignRequest) { r.ToSign = []SigningDigest{} })},
			{"sign-1-consent-digest", "DIGEST_BINDING", v1(func(r *KeychainSignRequest) {
				r.ToSign, r.SealSpend = []SigningDigest{digestSigner("landlord", r.Draft.IssuerKey, PurposeConsent, r.Draft.ConsentTemplate.ID)}, nil
			})},
			{"sign-2-contract", "", v2(func(r *KeychainSignRequest) { r.ToSign = r.ToSign[:1] })},
			{"sign-2-grant", "", v2(func(r *KeychainSignRequest) { r.ToSign = r.ToSign[1:] })},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				control := newGateKC(t, confirmWord, keyLandlord, keypolicy.CurrentSet)
				e, code := control.signAs(kcLabel, c.request())
				if c.control == "" {
					mustOK(t, e, code)
					if control.count("show") != 1 || control.count("secret:") == 0 {
						t.Fatalf("valid control did not sign: %v", control.log)
					}
				} else {
					mustRefuse(t, e, code, c.control)
				}
				h := newGateKC(t, confirmWord, keyLandlord, keypolicy.CurrentSet)
				e, code = h.signAs(gateLabel, c.request())
				refusedGate(t, h, e, code, "KEY_PURPOSE", 3)
				if len(h.log) != 0 {
					t.Fatalf("a refused purpose reached the Keychain: %v", h.log)
				}
			})
		}
	})
}

// Claim: the request schema alone selects the path, and the shapes do not
// mix. A static-gate request carrying a member of the grant schemas, a grant
// request carrying the static-gate members, the static-gate members under a
// grant schema, an unknown static-gate version, and a schema member spelled
// in another case are all BAD_INPUT before any Keychain read, under either
// label, beside the unchanged static-gate request, which signs.
func TestStaticGateCrossSchema(t *testing.T) {
	base := gateStatement(t, keyOther)
	signGate(t, base) // the valid control
	members := func(v any) map[string]any {
		b, err := json.Marshal(v)
		var m map[string]any
		if err != nil || json.Unmarshal(b, &m) != nil {
			t.Fatal("fixture: request does not marshal")
		}
		return m
	}
	with := func(m map[string]any, name string, value any) map[string]any {
		m[name] = value
		return m
	}
	gate := func() map[string]any { return members(gateRequest(base)) }
	f := preparedFlow(t)
	grant := func() map[string]any {
		r := fullRequest(t, f)
		r.SealSpend = nil
		return members(r)
	}
	relabel := func(m map[string]any) map[string]any {
		m["Schema"] = m["schema"]
		delete(m, "schema")
		return m
	}
	cases := map[string]map[string]any{
		"gate-request-with-draft":         with(gate(), "draft", grant()["draft"]),
		"gate-request-with-to-sign":       with(gate(), "to_sign", []any{}),
		"gate-request-with-seal-spend":    with(gate(), "seal_spend", map[string]any{"tx_hex": "00", "input_index": 0}),
		"gate-request-with-unknown":       with(gate(), "note", "x"),
		"gate-request-without-digest":     func() map[string]any { m := gate(); delete(m, "digest"); return m }(),
		"grant-request-with-statement":    with(grant(), "statement_b64", gate()["statement_b64"]),
		"grant-request-with-purpose":      with(grant(), "purpose", "static_gate"),
		"gate-members-under-sign-1":       with(gate(), "schema", KeychainSignSchema),
		"gate-members-under-sign-2":       with(gate(), "schema", KeychainSignV2Schema),
		"gate-schema-unknown-version":     with(gate(), "schema", "swarma-keychain/sign-static-gate/2"),
		"gate-schema-empty":               with(gate(), "schema", ""),
		"gate-schema-not-a-string":        with(gate(), "schema", 1),
		"gate-schema-member-in-uppercase": relabel(gate()),
	}
	for name, request := range cases {
		for _, label := range []string{gateLabel, kcLabel} {
			t.Run(name+"/"+label, func(t *testing.T) {
				h := newGateKC(t, confirmWord, keyOther, keypolicy.CurrentSet)
				e, code := h.signAs(label, request)
				refusedGate(t, h, e, code, "BAD_INPUT", 2)
				if len(h.log) != 0 {
					t.Fatalf("a mixed-schema request reached the Keychain: %v", h.log)
				}
			})
		}
	}
}

// Claim: the static-gate key is a biometry-current-set key. (1) keygen under
// the reserved label with any other policy is STATIC_GATE_KEY_ACCESS before
// any store call or entropy draw, beside keygen with the default and with the
// explicit biometry-current-set, which create the key; another label keeps
// every policy. (2) A key that sits under the reserved label with another
// recorded policy does not sign: STATIC_GATE_KEY_ACCESS before the display,
// beside the same request with a biometry-current-set key, which signs.
func TestStaticGateKeyAccessPolicy(t *testing.T) {
	for _, access := range []string{"biometry-any", "biometry-or-passcode"} {
		h := newKC(t, confirmWord)
		e, code := h.run("keychain", "keygen", "--label", gateLabel, "--access", access)
		refusedGate(t, h, e, code, "STATIC_GATE_KEY_ACCESS", 3)
		if len(h.log) != 0 {
			t.Fatalf("refused keygen reached the store: %v", h.log)
		}
		e, code = h.run("keychain", "keygen", "--label", "another-label", "--access", access)
		mustOK(t, e, code)
	}
	for _, args := range [][]string{nil, {"--access", "biometry-current-set"}} {
		h := newKC(t, confirmWord)
		e, code := h.run(append([]string{"keychain", "keygen", "--label", gateLabel}, args...)...)
		mustOK(t, e, code)
		if pub := resultAs[KeychainPublic](t, e); pub.Label != gateLabel || pub.AccessPolicy != keypolicy.CurrentSet {
			t.Fatalf("keygen %+v", pub)
		}
	}
	base := gateStatement(t, keyOther)
	signGate(t, base) // the valid control
	for _, access := range []keypolicy.Policy{keypolicy.Any, keypolicy.OrPasscode} {
		h := newGateKC(t, confirmWord, keyOther, access)
		e, code := h.signAs(gateLabel, gateRequest(base))
		refusedGate(t, h, e, code, "STATIC_GATE_KEY_ACCESS", 3)
	}
}

// Claim: the approval is the exact line SIGN and nothing else; any other
// answer declines after the display with no secret read. The result and
// every output carry public data only: the envelope has no network, the
// result has exactly its seven members, the authentication prompt names the
// purpose, and no encoding of a test secret appears in any output. The
// public-data binary, which links no signer, refuses the same request.
func TestStaticGateConfirmationAndOutputs(t *testing.T) {
	base := gateStatement(t, keyOther)
	for _, answer := range []string{"", "no", "sign", "SIGN ", "yes"} {
		h := newGateKC(t, answer, keyOther, keypolicy.CurrentSet)
		e, code := h.signAs(gateLabel, gateRequest(base))
		mustRefuse(t, e, code, "CONFIRMATION_DECLINED")
		if h.count("show") != 1 || h.count("confirm") != 1 || h.count("secret:") != 0 {
			t.Fatalf("answer %q: %v", answer, h.log)
		}
	}
	h := newGateKC(t, confirmWord, keyOther, keypolicy.CurrentSet)
	e, code := h.signAs(gateLabel, gateRequest(base))
	mustOK(t, e, code)
	var members map[string]any
	b, _ := json.Marshal(e.Result)
	if json.Unmarshal(b, &members) != nil || len(members) != 7 || e.Network != "" {
		t.Fatalf("result members %v, network %q", members, e.Network)
	}
	if len(h.store.Reasons) != 1 || !strings.Contains(h.store.Reasons[0], "static_gate") || !strings.Contains(h.store.Reasons[0], "biometry-current-set") {
		t.Fatalf("auth reasons = %v", h.store.Reasons)
	}
	assertNoSecrets(t, h.blobs)
	var out, diag bytes.Buffer
	if code := Run(context.Background(), []string{"keychain", "sign", "--label", gateLabel, "--request", writeInput(t, gateRequest(base)), "--json"}, &out, &diag); code != 3 || !strings.Contains(out.String(), "UNSUPPORTED_CAPABILITY") {
		t.Fatalf("swarma-identity static-gate sign: %d %s", code, out.String())
	}
}

// Claim: ccjCanonical admits exactly the canonical spelling. Each admitted
// document stands beside refused spellings of the same or a neighbouring
// value: whitespace, member order (by Unicode scalar, which differs from
// UTF-16 order above the BMP), duplicate names, non-integers, non-shortest
// integers, integers beyond 64 bits, escapes other than the prescribed ones,
// trailing content, invalid UTF-8, and more than 8 nested containers.
func TestCCJ1Canonical(t *testing.T) {
	for _, good := range []string{
		`{}`,
		`[]`,
		`{"a":1,"b":[true,false,null,-5,0],"c":{"d":"x"}}`,
		`{"A":1,"a":2}`,
		"{\"a\":\"\u00e9\\\"\\\\\\b\\f\\n\\r\\t\\u0001\\u001f\u007f/\"}",
		"{\"a\":1,\"\u00e9\":2,\"\uff5e\":3,\"\U00010000\":4}",
		`{"a":9223372036854775807,"b":-9223372036854775808}`,
		`[[[[[[[[1]]]]]]]]`,
	} {
		if _, ok := ccjCanonical([]byte(good)); !ok {
			t.Fatalf("canonical document refused: %q", good)
		}
	}
	for _, bad := range []string{
		``, ` {}`, `{} `, "{}\n", `{"a": 1}`, `{"a":1 ,"b":2}`,
		`{"b":1,"a":2}`,
		"{\"\U00010000\":1,\"\uff5e\":2}",
		`{"a":1,"a":1}`, `{"a":1,"a":2}`,
		`{"a":1.0}`, `{"a":1e3}`, `{"a":1.5}`, `{"a":-0}`, `{"a":01}`, `{"a":+1}`,
		`{"a":9223372036854775808}`,
		`{"a":"\u0041"}`, `{"a":"\/"}`, `{"a":"\u000a"}`, `{"a":"\u001F"}`, `{"a":"\u00e9"}`, `{"a":"\u007f"}`, `{"a":"\ud800"}`,
		"{\"a\":\"\x01\"}", "{\"a\":\"\xff\"}",
		`{"a":1}{}`, `{"a":1}1`, `{"a":1,}`, `{"a"}`, `{a:1}`,
		`[[[[[[[[[1]]]]]]]]]`,
	} {
		if _, ok := ccjCanonical([]byte(bad)); ok {
			t.Fatalf("non-canonical document admitted: %q", bad)
		}
	}
}

// Claim: ccjLeaves lists every value once, by an unambiguous path, with no
// knowledge of any name: a member whose name is not [a-z0-9_]+ is quoted in
// brackets, so the member "a.b" and the member b of a differ on the display,
// and empty containers are values of their own.
func TestCCJ1Leaves(t *testing.T) {
	v, ok := ccjCanonical([]byte(`{"":3,"a":{"b":2},"a.b":1,"x y":[{},[],"z"],"y = 1":null,"z":true}`))
	if !ok {
		t.Fatal("control: the document is not canonical")
	}
	want := []string{`[""] = 3`, `a.b = 2`, `["a.b"] = 1`, `["x y"][0] = {}`, `["x y"][1] = []`, `["x y"][2] = "z"`, `["y = 1"] = null`, `z = true`}
	if got := ccjLeaves("", v, nil); !slices.Equal(got, want) {
		t.Fatalf("leaves:\n got %q\nwant %q", got, want)
	}
}
