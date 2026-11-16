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

// The published genuine statement of the format (the example file is its
// byte-for-byte copy): the label and key it names, the SHA-256 of its
// preimage and its wire signature, written out from the published format and
// its vector files. The key is CSV index 1 of the published BIP-340 test
// vectors; all four are public test data.
const (
	publishedLabel       = "static-gate-example"
	publishedApproverKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
	publishedDigest      = "a9112c6bc3bfbf86661f0a637c7ad820ecaff1f777be6cc48d2a23b3e27dda41"
	publishedSignature   = "14c37808857bbab112bfa70710d9c35c4ede88a74f6760efbd52054590644984776b1e6a2ade454548d42b2681e77e722dab37f06bb4393c95786fa322154dbb"
	gateCallerKey        = "ed25519:iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg"
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

// gateStatement is the example with approver.label set to the reserved label
// and approver.key set to a published BIP-340 test key, so that a fake store
// can hold the matching key under that label.
func gateStatement(t *testing.T, key int) []byte {
	t.Helper()
	example, _ := gateExample(t)
	named := replaceOnce(t, example, `"label":"`+publishedLabel+`"`, `"label":"`+gateLabel+`"`)
	return replaceOnce(t, named, `"key":"`+publishedApproverKey+`"`, `"key":"`+testsigner_public(t, key)+`"`)
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
	// The whole trace, exactly: the public and access reads that bind
	// approver.key and the policy, the display, the confirmation, and only
	// then the signing step, which reads the public key again and then the
	// secret, as under sign/1 and sign/2.
	wantOrder := []string{"public:" + gateLabel, "access:" + gateLabel, "show", "confirm", "public:" + gateLabel, "secret:" + gateLabel}
	if !slices.Equal(h.log, wantOrder) {
		t.Fatalf("unexpected approval/secret ordering: %v", h.log)
	}
	return h.preKey, res
}

// refusedGate asserts one refusal with its exact code and exit status, and
// that nothing was shown, nothing was confirmed, no secret was read and no
// public key or access policy was read: the refusal came from validation,
// which runs before any of them.
func refusedGate(t *testing.T, h *kcHarness, e Envelope, code int, want string, exit int) {
	t.Helper()
	gateRefusal(t, h, e, code, want, exit, true)
}

// refusedGateAfterKeyRead is refusedGate for the refusals defined by the
// stored key itself (KEY_MISMATCH and, at signing, STATIC_GATE_KEY_ACCESS):
// the public and access reads that decide them run after validation, still
// before anything is shown and before any secret is read.
func refusedGateAfterKeyRead(t *testing.T, h *kcHarness, e Envelope, code int, want string, exit int) {
	t.Helper()
	gateRefusal(t, h, e, code, want, exit, false)
}

func gateRefusal(t *testing.T, h *kcHarness, e Envelope, code int, want string, exit int, beforeKey bool) {
	t.Helper()
	mustRefuse(t, e, code, want)
	if code != exit {
		t.Fatalf("exit %d, want %d", code, exit)
	}
	if h.count("show") != 0 || h.count("confirm") != 0 || h.count("secret:") != 0 {
		t.Fatalf("refused request reached the display or the key: %v", h.log)
	}
	if beforeKey && (h.count("public:") != 0 || h.count("access:") != 0) {
		t.Fatalf("refused request read the public key or access policy before validation: %v", h.log)
	}
}

// padGate appends a member zz_pad to the broker_time section, which the
// signer does not interpret, so that the preimage has exactly total bytes;
// the result stays canonical (zz_pad sorts after example_in_flight).
func padGate(t *testing.T, statement []byte, total int) []byte {
	t.Helper()
	n := total - len(gateTag) - 1 - len(statement) - len(`,"zz_pad":""`)
	if n < 0 {
		t.Fatal("fixture: the statement is too long to pad")
	}
	out := replaceOnce(t, statement, `"example_in_flight":1}`, `"example_in_flight":1,"zz_pad":"`+strings.Repeat("a", n)+`"}`)
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
	g, f := checkStaticGate(statement, pinned, publishedLabel)
	if f != nil || hex.EncodeToString(g.digest) != pinned {
		t.Fatalf("the example is not admitted under its pinned digest: %+v", f)
	}
}

// Claim: the example file is the published genuine statement and this signer
// derives for it the digest the published format states: 1491 bytes, a
// 1515-byte preimage, the literal SHA-256 above, under which the published
// signature verifies with the published approver key. Beside it, a statement
// with another gate_id is DIGEST_BINDING under the published digest, and the
// published signature does not verify over that statement's own digest.
// Limit: this proves equality for this one statement, not for every input.
func TestStaticGatePublishedGenuine(t *testing.T) {
	statement, _ := gateExample(t)
	if len(statement) != 1491 || len(staticGatePreimage(statement)) != 1515 {
		t.Fatalf("the example is %d bytes with a %d-byte preimage, want 1491 and 1515", len(statement), len(staticGatePreimage(statement)))
	}
	g, f := checkStaticGate(statement, publishedDigest, publishedLabel)
	if f != nil {
		t.Fatalf("the published statement is not admitted under the published digest: %+v", f)
	}
	if got := hex.EncodeToString(g.digest); got != publishedDigest || g.approverKey != publishedApproverKey {
		t.Fatalf("digest %s, approver key %s", got, g.approverKey)
	}
	if !sigValid(publishedApproverKey, hex.EncodeToString(g.digest), publishedSignature) {
		t.Fatal("the published signature does not verify over the digest this signer derives")
	}
	other := replaceOnce(t, statement, `"gate_id":"00112233445566778899aabbccddeeff"`, `"gate_id":"ffeeddccbbaa99887766554433221100"`)
	if _, f := checkStaticGate(other, publishedDigest, publishedLabel); f == nil || f.Code != "DIGEST_BINDING" {
		t.Fatalf("another statement under the published digest: %+v, want DIGEST_BINDING", f)
	}
	g, f = checkStaticGate(other, gateDigest(other), publishedLabel)
	if f != nil {
		t.Fatalf("control: the neighbouring statement is not admitted under its own digest: %+v", f)
	}
	if sigValid(publishedApproverKey, hex.EncodeToString(g.digest), publishedSignature) {
		t.Fatal("the published signature verifies over another statement")
	}
}

// Claim: the example shows the values the published examples show: the caller
// and worker generations are the two literal strings of exactly 32 lowercase
// hex digits, and its five UIDs are the literals 38600..38604, inside
// 30000..59999. The two predicates are held against known violations (the
// earlier example's "g-example-1" and 28601, uppercase hex, 29999, 60000)
// beside the bounds 30000 and 59999. source.generation stays "s-example-1" in
// the published example and is not held to the hex shape. Read with an
// independent JSON decoder, not the signer's reader.
func TestStaticGateExampleValues(t *testing.T) {
	example, _ := gateExample(t)
	var doc struct {
		Association struct {
			CallerGeneration string `json:"caller_generation"`
			CallerUID        int64  `json:"caller_uid"`
		} `json:"association"`
		Dispatcher struct {
			ServiceUID int64 `json:"service_uid"`
			Worker     struct {
				Generation string `json:"generation"`
				UID        int64  `json:"uid"`
			} `json:"worker"`
		} `json:"dispatcher"`
		Keymaker struct {
			ServiceUID int64 `json:"service_uid"`
		} `json:"keymaker"`
		Source struct {
			ServiceUID int64 `json:"service_uid"`
		} `json:"source"`
	}
	if err := json.Unmarshal(example, &doc); err != nil {
		t.Fatal(err)
	}
	generation := func(s string) bool { return len(s) == 32 && strings.Trim(s, "0123456789abcdef") == "" }
	managed := func(uid int64) bool { return uid >= 30000 && uid <= 59999 }
	if generation("g-example-1") || generation("0123456789ABCDEF0123456789ABCDEF") || generation("0123456789abcdef0123456789abcde") || managed(28601) || managed(29999) || managed(60000) || !managed(30000) || !managed(59999) {
		t.Fatal("control: a predicate admits a known violation or refuses a bound")
	}
	generations := []string{doc.Association.CallerGeneration, doc.Dispatcher.Worker.Generation}
	if !slices.Equal(generations, []string{"0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"}) {
		t.Fatalf("example generations %q", generations)
	}
	for _, s := range generations {
		if !generation(s) {
			t.Fatalf("example generation %q is not 32 lowercase hex digits", s)
		}
	}
	uids := []int64{doc.Keymaker.ServiceUID, doc.Association.CallerUID, doc.Dispatcher.ServiceUID, doc.Dispatcher.Worker.UID, doc.Source.ServiceUID}
	if !slices.Equal(uids, []int64{38600, 38601, 38602, 38603, 38604}) {
		t.Fatalf("example UIDs %v", uids)
	}
	for _, uid := range uids {
		if !managed(uid) {
			t.Fatalf("example UID %d is outside 30000..59999", uid)
		}
	}
}

// Claim: every row of the published vector file gets from this signer's
// statement check the verdict its row class requires. (1) Each of the 21
// passing rows is admitted and yields the digest the row states. (2) Each of
// the 84 rows whose published checks name an encoding or form cause (size,
// codec, canonical, depth, members, fixed, shape) is STATIC_GATE_FORM, also
// through the whole command, before anything is shown and before any secret
// is read. (3) Each of the 6 rows refused only for the window width is
// STATIC_GATE_WINDOW. (4) The other 69 rows are refused by the reference for
// a consumer-side input the signer does not hold (key pin, digest pin, wire
// signature, machine-id, clock, class, expected section or association
// bytes): out of scope; their statements are admitted, except the two that
// name an approver.key off the curve, which this signer refuses as
// STATIC_GATE_FORM. The class comes from the row's own expect and checks
// members; the counts are the literals below. Each statement is checked under
// the digest of its own bytes and the approver label it names, so neither the
// digest binding nor the reserved-label rule decides a verdict.
func TestStaticGatePublishedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/static-gate/published/vectors.json")
	if err != nil {
		t.Fatalf("the published vector file is not vendored: %v", err)
	}
	var rows []struct {
		ID           string   `json:"id"`
		Expect       string   `json:"expect"`
		Checks       []string `json:"checks"`
		StatementHex string   `json:"statement_hex"`
		Inputs       struct {
			StatementDigest string `json:"statement_digest"`
		} `json:"inputs"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	formCauses := []string{"size", "codec", "canonical", "depth", "members", "fixed", "shape"}
	offCurve := []string{"signature-key-at-p", "signature-key-nonliftable"}
	example, _ := gateExample(t)
	counts := map[string]int{}
	genuine := false
	for _, row := range rows {
		statement, err := hex.DecodeString(row.StatementHex)
		if err != nil {
			t.Fatalf("%s: statement_hex: %v", row.ID, err)
		}
		class, want := "consumer-side", ""
		switch {
		case row.Expect == "pass":
			class = "pass"
		case slices.ContainsFunc(row.Checks, func(c string) bool { return slices.Contains(formCauses, c) }):
			class, want = "form", "STATIC_GATE_FORM"
		case slices.Contains(row.Checks, "window_width"):
			class, want = "window", "STATIC_GATE_WINDOW"
		case slices.Contains(offCurve, row.ID):
			want = "STATIC_GATE_FORM"
		}
		counts[class]++
		if row.ID == "genuine-keymaker" {
			genuine = bytes.Equal(statement, example) && row.Inputs.StatementDigest == publishedDigest
		}
		t.Run(row.ID, func(t *testing.T) {
			label := publishedLabel
			var named struct {
				Approver struct {
					Label string `json:"label"`
				} `json:"approver"`
			}
			if json.Unmarshal(statement, &named) == nil && named.Approver.Label != "" {
				label = named.Approver.Label
			}
			g, f := checkStaticGate(statement, gateDigest(statement), label)
			got := ""
			if f != nil {
				got = f.Code
			}
			if got != want {
				t.Fatalf("%s row: verdict %q, want %q (the reference: %s, checks %v)", class, got, want, row.Expect, row.Checks)
			}
			if class == "pass" && hex.EncodeToString(g.digest) != row.Inputs.StatementDigest {
				t.Fatalf("digest %x, the row states %s", g.digest, row.Inputs.StatementDigest)
			}
			if class == "form" {
				h := newGateKC(t, confirmWord, keyOther, keypolicy.CurrentSet)
				e, code := h.signAs(gateLabel, gateRequest(statement))
				refusedGate(t, h, e, code, "STATIC_GATE_FORM", 3)
			}
		})
	}
	if len(rows) != 180 || counts["pass"] != 21 || counts["form"] != 84 || counts["window"] != 6 || counts["consumer-side"] != 69 {
		t.Fatalf("%d rows by class %v, want 180: pass 21, form 84, window 6, consumer-side 69", len(rows), counts)
	}
	if !genuine {
		t.Fatal("the row genuine-keymaker is not the example statement under the published digest")
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

// Claim: the display knows no section content. (1) A section whose members no
// code names, holding nested objects, an array, an empty object and a member
// name with a dot, signs, and every value of it is shown by its path, the
// dotted name quoted so that it cannot pass for a nested path; the lines of
// every other member are unchanged and the top-level members are the 14 of
// the format. (2) The source section is shown value by value. (3) No value is
// shortened: a 6000-byte value inside a section is shown in full. The
// top-level member set itself is closed: TestStaticGateRefusals holds the
// unknown, missing and duplicate top-level members.
func TestStaticGateDisplayUnknownSection(t *testing.T) {
	base := gateStatement(t, keyOther)
	t.Run("unnamed-section-content", func(t *testing.T) {
		statement := replaceOnce(t, base, `"broker_time":{"example_hold_seconds":30,"example_in_flight":1}`, `"broker_time":{"a_list":[1,"two",{}],"nested":{"deep":{"deeper":"x"}},"odd.name":"y"}`)
		shown, _ := signGate(t, statement)
		for _, l := range []string{`broker_time.a_list[0] = 1`, `broker_time.a_list[1] = "two"`, `broker_time.a_list[2] = {}`, `broker_time.nested.deep.deeper = "x"`, `broker_time["odd.name"] = "y"`} {
			if !strings.Contains(shown, "\n    "+l+"\n") {
				t.Fatalf("display lacks the section's value %q", l)
			}
		}
		plain, _ := signGate(t, base)
		before := displayBlock(plain, "Statement members  : all 30 values of the statement by path, in the order of the signed bytes")
		after := displayBlock(shown, "Statement members  : all 33 values of the statement by path, in the order of the signed bytes")
		outside := func(lines []string) []string {
			return slices.DeleteFunc(slices.Clone(lines), func(l string) bool { return strings.HasPrefix(l, "broker_time") })
		}
		if len(before) != 30 || len(after) != 33 || len(outside(before)) != 28 || !slices.Equal(outside(after), outside(before)) {
			t.Fatalf("the section content changed other lines or the count:\n got %q", after)
		}
		if !strings.Contains(shown, "\n  Sections, 14 top-level members, each shown in full below: approver, association, broker_d5, broker_time, dispatcher, gate_id, host, keymaker, kind, milestone, not_after, not_before, source, v\n") {
			t.Fatal("the top-level members are not listed")
		}
	})
	t.Run("source-shown", func(t *testing.T) {
		shown, _ := signGate(t, base)
		for _, l := range []string{`source.config_sha256 = "` + strings.Repeat("a", 64) + `"`, `source.generation = "s-example-1"`, `source.service_uid = 38604`} {
			if !strings.Contains(shown, "\n    "+l+"\n") {
				t.Fatalf("display lacks %q", l)
			}
		}
	})
	t.Run("long-value-in-full", func(t *testing.T) {
		long := strings.Repeat("0123456789", 600)
		shown, _ := signGate(t, replaceOnce(t, base, `"example_in_flight":1}`, `"example_in_flight":1,"zz_long":"`+long+`"}`))
		if !strings.Contains(shown, "\n    broker_time.zz_long = \""+long+"\"\n") {
			t.Fatal("a long value is not shown in full")
		}
	})
}

// Claim: a non-ASCII or control character in a displayed value or member name reaches the terminal only escaped, beside a plain ASCII value shown as itself.
func TestStaticGateDisplayEscaping(t *testing.T) {
	base := gateStatement(t, keyOther)
	statement := replaceOnce(t, base, `"broker_time":{"example_hold_seconds":30,"example_in_flight":1}`, `"broker_time":{"example_hold_seconds":30,"example_in_flight":1,"zz_note":"café\u0001end","zz_oddé\u0001name":"y","zz_plain":"plain"}`)
	shown, _ := signGate(t, statement)
	for _, l := range []string{`broker_time.zz_note = "caf\u00e9\x01end"`, `broker_time["zz_odd\u00e9\x01name"] = "y"`, `broker_time.zz_plain = "plain"`} {
		if !strings.Contains(shown, "\n    "+l+"\n") {
			t.Fatalf("display lacks the escaped line %q", l)
		}
	}
	if strings.Contains(shown, "é") || strings.Contains(shown, "\x01") {
		t.Fatal("display carries a raw non-ASCII or control character")
	}
	var exact strings.Builder
	for _, l := range displayBlock(shown, "  exact bytes      :") {
		_, text, ok := strings.Cut(l, "  ")
		if !ok {
			t.Fatalf("exact-bytes line malformed: %q", l)
		}
		exact.WriteString(text)
	}
	if !strings.Contains(exact.String(), `\xc3\xa9`) {
		t.Fatal("exact bytes do not show the non-ASCII bytes in \\xNN form")
	}
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
		"Host: only the machine whose machine-id has the SHA-256 6ed6653dba3d6aee8110c6e23de37f15c609b8a6e29aa164d1acace604e5cb7e.",
		"Window: not before 2026-11-17T00:00:00Z, not after 2026-11-19T00:00:00Z; length 48h0m0s, the limit is 72h0m0s.",
		"Caller association, 3 value(s), exactly as signed:",
		`  - association.caller_generation = "0123456789abcdef0123456789abcdef"`,
		`  - association.caller_key = "ed25519:iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg"`,
		"  - association.caller_uid = 38601",
		"Sections, 14 top-level members, each shown in full below: approver, association, broker_d5, broker_time, dispatcher, gate_id, host, keymaker, kind, milestone, not_after, not_before, source, v",
	}
	shown, _ := signGate(t, base)
	if got := linesUnder(shown, "SCOPE TEXT         : ", "  "); !slices.Equal(got, want) {
		t.Fatalf("scope text:\n got %q\nwant %q", got, want)
	}
	if !strings.Contains(shown, "\nSCOPE TEXT         : worded by this signer from the statement bytes only; no wording comes from the request\n") {
		t.Fatal("display does not state where the scope text comes from")
	}
	shown, _ = signGate(t, replaceOnce(t, base, `"caller_uid":38601`, `"caller_uid":38699`))
	want[6] = "  - association.caller_uid = 38699"
	if got := linesUnder(shown, "SCOPE TEXT         : ", "  "); !slices.Equal(got, want) {
		t.Fatalf("scope text after one changed member:\n got %q\nwant %q", got, want)
	}
}

// Claim: the limits are inclusive where the format says "at most". A
// preimage of exactly 8192 bytes, a window of exactly 72 h, a statement
// nested exactly 8 deep, the integers 2^53-1 and -(2^53-1) inside a section,
// and the caller UIDs 0 and 4294967295 each sign. They are the valid controls
// beside the 8193-byte, 72 h + 1 s, depth-9, 2^53, -(2^53), -1 and 2^32
// refusals of TestStaticGateRefusals.
func TestStaticGateBoundaries(t *testing.T) {
	base := gateStatement(t, keyOther)
	for name, statement := range map[string][]byte{
		"preimage-8192-bytes":  padGate(t, base, 8192),
		"window-72h":           replaceOnce(t, base, `"not_after":"2026-11-19T00:00:00Z"`, `"not_after":"2026-11-20T00:00:00Z"`),
		"depth-8":              replaceOnce(t, base, `"example_in_flight":1}`, `"example_in_flight":[[[[[[1]]]]]]}`),
		"integer-2^53-1":       replaceOnce(t, base, `"example_in_flight":1}`, `"example_in_flight":9007199254740991}`),
		"integer-minus-2^53-1": replaceOnce(t, base, `"example_in_flight":1}`, `"example_in_flight":-9007199254740991}`),
		"caller-uid-0":         replaceOnce(t, base, `"caller_uid":38601`, `"caller_uid":0`),
		"caller-uid-2^32-1":    replaceOnce(t, base, `"caller_uid":38601`, `"caller_uid":4294967295`),
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
	association := `"association":{"caller_generation":"0123456789abcdef0123456789abcdef","caller_key":"` + gateCallerKey + `","caller_uid":38601},`
	approverKey := `"key":"` + testsigner_public(t, keyOther) + `"`
	brokerD5 := `"broker_d5":{"example_acknowledged_head":"` + strings.Repeat("8", 64) + `"}`
	source := `"source":{"config_sha256":"` + strings.Repeat("a", 64) + `","generation":"s-example-1","service_uid":38604},`
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
		{"exponent-number", "STATIC_GATE_FORM", 3, swap(`"caller_uid":38601`, `"caller_uid":3.8601e4`)},
		{"depth-9", "STATIC_GATE_FORM", 3, swap(`"example_in_flight":1}`, `"example_in_flight":[[[[[[[1]]]]]]]}`)},
		{"not-an-object", "STATIC_GATE_FORM", 3, bytesOf([]byte(`[]`))},
		// An integer one past either end of -(2^53-1)..2^53-1 is not CCJ-1.
		// The ends themselves sign in TestStaticGateBoundaries.
		{"integer-2^53", "STATIC_GATE_FORM", 3, swap(`"example_in_flight":1}`, `"example_in_flight":9007199254740992}`)},
		{"integer-minus-2^53", "STATIC_GATE_FORM", 3, swap(`"example_in_flight":1}`, `"example_in_flight":-9007199254740992}`)},
		// The closed top-level member set: an unknown member, a missing
		// member, one member under another name. The duplicate top-level
		// member is duplicate-member above.
		{"unknown-top-level-member", "STATIC_GATE_FORM", 3, swap(`,"v":1}`, `,"v":1,"zz_late":{"a":1}}`)},
		{"missing-top-level-member-source", "STATIC_GATE_FORM", 3, swap(source, ``)},
		{"missing-top-level-member-gate-id", "STATIC_GATE_FORM", 3, swap(`"gate_id":"00112233445566778899aabbccddeeff",`, ``)},
		{"missing-top-level-member-milestone", "STATIC_GATE_FORM", 3, swap(`"milestone":"G1.0",`, ``)},
		{"renamed-top-level-member", "STATIC_GATE_FORM", 3, swap(`"source":{`, `"sourcf":{`)},
		// The fixed values and shapes of the members the format owns.
		{"milestone-other", "STATIC_GATE_FORM", 3, swap(`"milestone":"G1.0"`, `"milestone":"G1.1"`)},
		{"gate-id-uppercase", "STATIC_GATE_FORM", 3, swap(`"gate_id":"00112233445566778899aabbccddeeff"`, `"gate_id":"00112233445566778899AABBCCDDEEFF"`)},
		{"gate-id-31-digits", "STATIC_GATE_FORM", 3, swap(`"gate_id":"00112233445566778899aabbccddeeff"`, `"gate_id":"00112233445566778899aabbccddeef"`)},
		{"host-unknown-member", "STATIC_GATE_FORM", 3, swap(`"host":{"label":"host-a",`, `"host":{"extra":1,"label":"host-a",`)},
		{"host-label-empty", "STATIC_GATE_FORM", 3, swap(`"label":"host-a"`, `"label":""`)},
		{"approver-unknown-member", "STATIC_GATE_FORM", 3, swap(`"approver":{"alg":"bip340",`, `"approver":{"alg":"bip340","extra":1,`)},
		{"approver-label-empty", "STATIC_GATE_FORM", 3, swap(`"label":"swarma-static-gate-g1"`, `"label":""`)},
		{"association-unknown-member", "STATIC_GATE_FORM", 3, swap(`"caller_uid":38601}`, `"caller_uid":38601,"registration":1}`)},
		{"association-without-caller-key", "STATIC_GATE_FORM", 3, swap(`"caller_key":"`+gateCallerKey+`",`, ``)},
		{"caller-generation-empty", "STATIC_GATE_FORM", 3, swap(`"caller_generation":"0123456789abcdef0123456789abcdef"`, `"caller_generation":""`)},
		{"caller-key-without-prefix", "STATIC_GATE_FORM", 3, swap(`"caller_key":"ed25519:`, `"caller_key":"`)},
		{"caller-key-padded", "STATIC_GATE_FORM", 3, swap(`"caller_key":"`+gateCallerKey+`"`, `"caller_key":"`+gateCallerKey+`="`)},
		{"caller-uid-negative", "STATIC_GATE_FORM", 3, swap(`"caller_uid":38601`, `"caller_uid":-1`)},
		{"caller-uid-2^32", "STATIC_GATE_FORM", 3, swap(`"caller_uid":38601`, `"caller_uid":4294967296`)},
		{"caller-uid-string", "STATIC_GATE_FORM", 3, swap(`"caller_uid":38601`, `"caller_uid":"38601"`)},
		{"section-not-an-object", "STATIC_GATE_FORM", 3, swap(brokerD5, `"broker_d5":"8888"`)},
		{"section-empty", "STATIC_GATE_FORM", 3, swap(brokerD5, `"broker_d5":{}`)},
		// Size: one byte over the limit.
		{"preimage-8193-bytes", "STATIC_GATE_FORM", 3, bytesOf(padGate(t, base, 8193))},
		// The members the signer itself relies on.
		{"kind", "STATIC_GATE_FORM", 3, swap(`"kind":"swarma-s7 static-gate/1"`, `"kind":"swarma-s7 static-gate/2"`)},
		{"version", "STATIC_GATE_FORM", 3, swap(`,"v":1}`, `,"v":2}`)},
		{"approver-alg", "STATIC_GATE_FORM", 3, swap(`"alg":"bip340"`, `"alg":"ed25519"`)},
		{"approver-key-not-on-the-curve", "STATIC_GATE_FORM", 3, swap(approverKey, `"key":"`+strings.Repeat("5", 64)+`"`)},
		{"association-absent", "STATIC_GATE_FORM", 3, swap(association, ``)},
		{"association-empty", "STATIC_GATE_FORM", 3, swap(association, `"association":{},`)},
		{"machine-id-not-hex", "STATIC_GATE_FORM", 3, swap(`"machine_id_sha256":"6ed6`, `"machine_id_sha256":"Xed6`)},
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
			if c.want == "KEY_MISMATCH" {
				refusedGateAfterKeyRead(t, h, e, code, c.want, c.exit)
			} else {
				refusedGate(t, h, e, code, c.want, c.exit)
			}
		})
	}
}

// Claim: an all-zero host.machine_id_sha256 refuses with STATIC_GATE_FORM before the display and before any public, access or secret read, beside the unchanged statement, which signs.
func TestStaticGateZeroMachineID(t *testing.T) {
	base := gateStatement(t, keyOther)
	signGate(t, base) // the valid control
	zero := replaceOnce(t, base, `"machine_id_sha256":"6ed6653dba3d6aee8110c6e23de37f15c609b8a6e29aa164d1acace604e5cb7e"`, `"machine_id_sha256":"`+strings.Repeat("0", 64)+`"`)
	h := newGateKC(t, confirmWord, keyOther, keypolicy.CurrentSet)
	before := len(h.store.Events)
	e, code := h.signAs(gateLabel, gateRequest(zero))
	refusedGate(t, h, e, code, "STATIC_GATE_FORM", 3)
	if len(h.log) != 0 || len(h.store.Events) != before {
		t.Fatalf("zero machine-id reached the store or the terminal: %v", h.log)
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
		refusedGateAfterKeyRead(t, h, e, code, "STATIC_GATE_KEY_ACCESS", 3)
	}
}

// Claim: when the access policy cannot be inspected, the display says so before the secret read and the statement still signs, beside the inspectable control, whose display has no such line.
func TestStaticGateAccessInspectionDisclosure(t *testing.T) {
	base := gateStatement(t, keyOther)
	shown, _ := signGate(t, base) // the inspectable valid control
	if strings.Contains(shown, "Native ACL flags") {
		t.Fatal("inspectable control claims native ACL flags are unavailable")
	}
	h := newGateKC(t, confirmWord, keyOther, keypolicy.CurrentSet)
	h.store.HideAccessInspection = true
	e, code := h.signAs(gateLabel, gateRequest(base))
	mustOK(t, e, code)
	if !h.keyRead || !strings.Contains(h.preKey, "\nNative ACL flags   : unavailable through public Security APIs; authenticated policy metadata is checked before signing.\n") {
		t.Fatal("uninspectable access policy was not disclosed before the secret read")
	}
	if !strings.Contains(h.preKey, "\nAccess policy      : biometry-current-set (this-device-only)\n") {
		t.Fatal("access policy line missing beside the disclosure")
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
// integers, integers outside -(2^53-1)..2^53-1 (the two ends are admitted;
// one past either end, the 64-bit ends and one past them are refused),
// escapes other than the prescribed ones, trailing content, invalid UTF-8,
// and more than 8 nested containers.
func TestCCJ1Canonical(t *testing.T) {
	for _, good := range []string{
		`{}`,
		`[]`,
		`{"a":1,"b":[true,false,null,-5,0],"c":{"d":"x"}}`,
		`{"A":1,"a":2}`,
		"{\"a\":\"\u00e9\\\"\\\\\\b\\f\\n\\r\\t\\u0001\\u001f\u007f/\"}",
		"{\"a\":1,\"\u00e9\":2,\"\uff5e\":3,\"\U00010000\":4}",
		`{"a":9007199254740991,"b":-9007199254740991}`,
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
		`{"a":9007199254740992}`, `{"a":-9007199254740992}`,
		`{"a":9223372036854775807}`, `{"a":-9223372036854775808}`, `{"a":9223372036854775808}`,
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
