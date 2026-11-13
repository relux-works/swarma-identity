package facade

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// committedLines derives, without the signer's renderer, every value a digest
// commits to. It requires SHA-256(prefix || body) to be the digest, decodes
// body as one JSON document into a generic tree and lists each leaf (and each
// empty object or array) as "path = value". Map order is irrelevant: the
// caller compares sets.
func committedLines(t *testing.T, prefix string, body []byte, digest string) []string {
	t.Helper()
	if sum := sha256.Sum256(append([]byte(prefix), body...)); hex.EncodeToString(sum[:]) != digest {
		t.Fatal("ground truth: SHA-256(prefix || body) is not the requested digest")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var doc any
	if err := d.Decode(&doc); err != nil || d.More() {
		t.Fatal("ground truth: body is not one JSON document")
	}
	var out []string
	var walk func(path string, v any)
	join := func(path, key string) string {
		if path == "" {
			return key
		}
		return path + "." + key
	}
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			if len(x) == 0 {
				out = append(out, path+" = {}")
			}
			for k, e := range x {
				walk(join(path, k), e)
			}
		case []any:
			if len(x) == 0 {
				out = append(out, path+" = []")
			}
			for i, e := range x {
				walk(fmt.Sprintf("%s[%d]", path, i), e)
			}
		case string:
			out = append(out, path+" = "+strconv.QuoteToASCII(x))
		case json.Number:
			out = append(out, path+" = "+x.String())
		case bool:
			out = append(out, path+" = "+strconv.FormatBool(x))
		case nil:
			out = append(out, path+" = null")
		default:
			t.Fatalf("ground truth: unexpected JSON value %T", v)
		}
	}
	walk("", doc)
	return out
}

// displayBlock returns the lines of the transcript between the first line
// equal to start and the next line that does not begin with four spaces.
func displayBlock(shown, start string) []string {
	_, rest, ok := strings.Cut(shown, "\n"+start+"\n")
	if !ok {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(l, "    ") {
			break
		}
		lines = append(lines, l[4:])
	}
	return lines
}

// checkPreimageShown asserts that the pre-key-read transcript shows every
// committed value of prefix || body and nothing else as a committed field,
// and those bytes verbatim, 64 per line after their offset.
func checkPreimageShown(t *testing.T, shown, prefix string, body []byte, digest string) {
	t.Helper()
	want := committedLines(t, prefix, body, digest)
	for _, l := range want {
		if !strings.Contains(shown, "\n    "+l+"\n") {
			t.Fatalf("pre-key-read display lacks committed field %q", l)
		}
	}
	got := displayBlock(shown, "  committed fields :")
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("committed-field block is not exactly the preimage's fields:\n got %q\nwant %q", got, want)
	}
	var exact []byte
	for i, l := range displayBlock(shown, "  exact bytes      :") {
		off, text, ok := strings.Cut(l, "  ")
		if !ok || off != fmt.Sprintf("%04d", i*64) {
			t.Fatalf("exact-bytes line %d malformed: %q", i, l)
		}
		exact = append(exact, text...)
	}
	if string(exact) != prefix+string(body) {
		t.Fatalf("display does not show the hashed bytes verbatim:\n got %s\nwant %s%s", exact, prefix, body)
	}
}

// restampedConsent has the grantee sign a complete consent event whose
// created_at differs from the draft template, as a NIP-07 signer may, passes
// it through grant consent, and returns it with the grant_b64 and
// grant_signing_hash that PR 8's grant sign derives for it.
func restampedConsent(t *testing.T, f *flow, delta int64) (rental.Event, []byte, string) {
	t.Helper()
	tpl := f.draft.Draft.ConsentTemplate
	ev := rental.Event{Pubkey: tpl.Pubkey, CreatedAt: tpl.CreatedAt + delta, Kind: tpl.Kind, Tags: tpl.Tags, Content: tpl.Content}
	ev.ID = consentEventID(ev.Pubkey, ev.CreatedAt, ev.Kind, ev.Tags, ev.Content)
	ev.Sig = sign(t, f.grantee, ev.ID)
	e, code := f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: f.draft.Draft, ConsentEvent: &ev})
	mustOK(t, e, code)
	ev = resultAs[GrantConsentResult](t, e).ConsentEvent
	e, code = f.signCmd(GrantSignRequest{Schema: GrantSignSchema, Draft: f.draft.Draft, ConsentEvent: ev, LandlordSig: f.landlordSig})
	mustOK(t, e, code)
	stage := resultAs[GrantSignResult](t, e)
	raw, err := base64.StdEncoding.DecodeString(stage.GrantB64)
	if err != nil {
		t.Fatal(err)
	}
	return ev, raw, stage.GrantSigningHash
}

// Claim: for each BIP-340 purpose keychain sign supports, the terminal
// transcript at the first secret read contains, as "path = value", exactly
// the leaves of the bytes the digest is the SHA-256 of, and those bytes
// verbatim: the trust contract for contract_sha256, and "swarma-grant-v3" ||
// canonical grant for grant_signing_hash, with the nested consent event (id,
// pubkey, created_at, kind, tags, content, sig) and landlord_sig. The ground
// truth is PR 8's own output bytes (contract_b64, grant_b64), not the
// signer's, and each returned signature verifies over their hash. Cases: a
// consent signed over the drafted id (the display states the times are
// equal); a complete event whose signer chose another created_at (the display
// states both times and does not show the template's as the signed one).
// Limit: the seal spend's display is TestSealDisplayCoversEverySighashField.
func TestKeychainDisplayCoversEveryPreimageField(t *testing.T) {
	f := preparedFlow(t)
	tpl := f.draft.Draft.ConsentTemplate
	signOne := func(t *testing.T, r KeychainSignRequest) string {
		t.Helper()
		h := newKC(t, confirmWord)
		e, code := h.sign(r)
		mustOK(t, e, code)
		res := resultAs[KeychainSignResult](t, e)
		if !h.keyRead || len(res.Signatures) != 1 || !sigValid(r.Draft.IssuerKey, r.ToSign[0].Digest, res.Signatures[0].Signature) {
			t.Fatalf("positive control did not sign: %v", h.log)
		}
		return h.preKey
	}
	t.Run("contract", func(t *testing.T) {
		r := fullRequest(t, f)
		r.ToSign, r.SealSpend = r.ToSign[:1], nil
		contract, err := base64.StdEncoding.DecodeString(r.Draft.ContractB64)
		if err != nil {
			t.Fatal(err)
		}
		checkPreimageShown(t, signOne(t, r), "", contract, r.Draft.ContractSHA256)
	})
	t.Run("grant-drafted-consent", func(t *testing.T) {
		r := fullRequest(t, f)
		r.ToSign, r.SealSpend = r.ToSign[1:], nil
		grant, err := base64.StdEncoding.DecodeString(f.stage1.GrantB64)
		if err != nil {
			t.Fatal(err)
		}
		shown := signOne(t, r)
		checkPreimageShown(t, shown, "swarma-grant-v3", grant, f.stage1.GrantSigningHash)
		if !strings.Contains(shown, fmt.Sprintf("consent time     : %d (%s) equals the draft template\n", tpl.CreatedAt, utc(tpl.CreatedAt))) {
			t.Fatal("display does not state that the consent time equals the template")
		}
	})
	t.Run("grant-restamped-consent", func(t *testing.T) {
		ev, grant, hash := restampedConsent(t, f, -3600)
		r := fullRequest(t, f)
		r.ConsentEvent, r.ToSign, r.SealSpend = &ev, []SigningDigest{digestSigner("landlord", r.Draft.IssuerKey, PurposeGrant, hash)}, nil
		shown := signOne(t, r)
		checkPreimageShown(t, shown, "swarma-grant-v3", grant, hash)
		if !strings.Contains(shown, fmt.Sprintf("consent time     : %d (%s) DIFFERS from the draft template %d (%s)", ev.CreatedAt, utc(ev.CreatedAt), tpl.CreatedAt, utc(tpl.CreatedAt))) {
			t.Fatal("display does not state the consent time difference")
		}
		if strings.Contains(shown, fmt.Sprintf("consent.consent_event.created_at = %d\n", tpl.CreatedAt)) || strings.Contains(shown, "consent.consent_event.id = \""+tpl.ID+"\"") {
			t.Fatal("display shows the draft template's consent instead of the signed one")
		}
	})
}

// Claim: an accepted, independently verified grant signs nested consent fields
// that the complete pre-key-read approval display must expose. This fixture uses
// only published test keys and the in-memory store; no native Keychain is called.
// (Owner-side reproducer from review 5885669716, kept as written.)
func TestOwnerReviewConsentDisplayContract(t *testing.T) {
	f := preparedFlow(t)
	r := fullRequest(t, f)
	r.ToSign = r.ToSign[1:]
	r.SealSpend = nil
	raw, err := base64.StdEncoding.DecodeString(f.stage1.GrantB64)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append([]byte("swarma-grant-v3"), raw...))
	if fmt.Sprintf("%x", digest) != r.ToSign[0].Digest {
		t.Fatal("independent canonical grant digest mismatch")
	}
	fields := []struct{ name, text string }{
		{"consent.created_at", fmt.Sprint(r.ConsentEvent.CreatedAt)},
		{"consent.id", r.ConsentEvent.ID},
		{"consent.sig", r.ConsentEvent.Sig},
		{"landlord_sig", r.LandlordSig},
	}
	for _, f := range fields {
		if f.text == "" || !bytes.Contains(raw, []byte(f.text)) {
			t.Fatalf("canonical grant does not contain %s", f.name)
		}
	}
	h := newKC(t, confirmWord)
	e, code := h.sign(r)
	mustOK(t, e, code)
	res := resultAs[KeychainSignResult](t, e)
	if len(res.Signatures) != 1 || !sigValid(r.Draft.IssuerKey, r.ToSign[0].Digest, res.Signatures[0].Signature) {
		t.Fatal("valid positive control did not issue matching grant signature")
	}
	if h.count("secret:") != 1 || len(h.log) != 5 || h.log[1] != "show" || h.log[2] != "confirm" {
		t.Fatalf("unexpected approval/secret ordering: %v", h.log)
	}
	shown := h.term.shown.String()
	if !strings.Contains(shown, r.Draft.AgentName) || !strings.Contains(shown, r.ToSign[0].Digest) {
		t.Fatal("ordinary displayed fields missing")
	}
	t.Run("tampered-consent-is-refused-before-approval", func(t *testing.T) {
		bad := r
		ev := *r.ConsentEvent
		ev.CreatedAt++
		bad.ConsentEvent = &ev
		negative := newKC(t, confirmWord)
		e, code := negative.sign(bad)
		mustRefuse(t, e, code, "CONSENT_ID")
		if negative.count("show") != 0 || negative.count("secret:") != 0 {
			t.Fatal("invalid consent reached approval or secret")
		}
	})
	t.Run("all-committed-consent-fields-are-visible", func(t *testing.T) {
		for _, f := range fields {
			if !strings.Contains(shown, f.text) {
				t.Errorf("valid grant was signed while approval omitted %s", f.name)
			}
		}
	})
}

// Claim: jsonLeaves lists every value of exactly one JSON document, empty
// containers and every scalar kind included, and refuses trailing or broken
// input, so a malformed body can never reach the display as a partial list.
func TestJSONLeaves(t *testing.T) {
	got, ok := jsonLeaves([]byte(`{"a":{"b":[1,"xé",[],{}]},"c":true,"d":null,"e":-0.5e3}`))
	want := []string{`a.b[0] = 1`, "a.b[1] = \"x\\u00e9\"", `a.b[2] = []`, `a.b[3] = {}`, `c = true`, `d = null`, `e = -0.5e3`}
	if !ok || !slices.Equal(got, want) {
		t.Fatalf("leaves %q", got)
	}
	for _, bad := range []string{`{"a":1}{}`, `{"a":1`, `{"a":1} x`, ``, `{1:2}`} {
		if _, ok := jsonLeaves([]byte(bad)); ok {
			t.Fatalf("admitted %q", bad)
		}
	}
}
