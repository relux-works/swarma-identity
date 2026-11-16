package facade

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/relux-works/swarma-identity/internal/grantv4"
	"github.com/relux-works/swarma-identity/internal/keychain/keychainfake"
)

func v4TestDigest(tag string, raw []byte) string {
	t := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(t[:])
	h.Write(t[:])
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func v4TestAssent(t *testing.T, contract, party string, signer int) string {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"type": "swarma-contract-assent/1", "contract": contract, "genesis": "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770", "party": party})
	sig := sign(t, testSigner(t, signer), v4TestDigest("swarma-contract-assent/1", raw))
	signed, _ := json.Marshal(struct {
		Payload   json.RawMessage `json:"payload"`
		Signature string          `json:"signature"`
	}{raw, sig})
	return hex.EncodeToString(signed)
}
func v4TestEventHex(t *testing.T, event grantv4.Event) string {
	t.Helper()
	pre, _ := json.Marshal([]any{0, event.Pubkey, event.CreatedAt, event.Kind, event.Tags, event.Content})
	sum := sha256.Sum256(pre)
	event.ID = hex.EncodeToString(sum[:])
	raw, e := json.Marshal(event)
	if e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(raw)
}
func v4PreparationControl(t *testing.T) (GrantV4Request, grantv4.Event) {
	t.Helper()
	g, _ := v4Grant(t, "grant-v-01")
	event, e := grantv4.ConsentTemplate(g, 1700000000)
	if e != nil {
		t.Fatal(e)
	}
	event.Sig = sign(t, testSigner(t, keyLandlord), event.ID)
	return GrantV4Request{Schema: GrantV4RequestSchema, SignedHex: hex.EncodeToString(g.Signed()), AssentHex: v4TestAssent(t, g.Contract(), v4IssuerKey, keyGrantee), ConsentHex: v4TestEventHex(t, event), Now: 1700000001}, event
}

// TestV4PreparationRefusals proves assent and consent closed codes follow W9.4/W7.4 precedence, with a fully valid root preparation beside each negative.
func TestV4PreparationRefusals(t *testing.T) {
	cases := []struct {
		name, code string
		change     func(*GrantV4Request, grantv4.Event)
	}{
		{"assent-binding", "ASSENT_BINDING", func(r *GrantV4Request, _ grantv4.Event) {
			r.AssentHex = v4TestAssent(t, strings.Repeat("0", 64), v4IssuerKey, keyGrantee)
			r.ConsentHex = "00"
		}},
		{"assent-party", "ASSENT_PARTY", func(r *GrantV4Request, _ grantv4.Event) {
			g, _ := v4Grant(t, "grant-v-01")
			r.AssentHex = v4TestAssent(t, g.Contract(), v4RequestKey, keyLandlord)
		}},
		{"event-shape", "CONSENT_SHAPE", func(r *GrantV4Request, e grantv4.Event) {
			e.Tags[0][1] = "swarma-contract-consent"
			r.ConsentHex = v4TestEventHex(t, e)
		}},
		{"event-key-shape", "CONSENT_SHAPE", func(r *GrantV4Request, e grantv4.Event) {
			e.Pubkey = strings.Repeat("f", 64)
			r.ConsentHex = v4TestEventHex(t, e)
		}},
		{"event-binding-before-signature", "CONSENT_BINDING", func(r *GrantV4Request, e grantv4.Event) {
			e.Tags[1][1] = strings.Repeat("0", 64)
			e.Sig = strings.Repeat("0", 128)
			r.ConsentHex = v4TestEventHex(t, e)
		}},
		{"event-key-before-signature", "CONSENT_KEY", func(r *GrantV4Request, e grantv4.Event) { e.Pubkey = v4IssuerKey; r.ConsentHex = v4TestEventHex(t, e) }},
		{"event-signature-before-time", "CONSENT_SIGNATURE", func(r *GrantV4Request, e grantv4.Event) {
			e.Sig = strings.Repeat("0", 128)
			r.ConsentHex = v4TestEventHex(t, e)
			r.Now = 1699999999
		}},
		{"event-time", "CONSENT_TIME", func(r *GrantV4Request, _ grantv4.Event) { r.Now = 1699999999 }},
		{"event-duplicate", "CONSENT_SHAPE", func(r *GrantV4Request, _ grantv4.Event) {
			raw, _ := hex.DecodeString(r.ConsentHex)
			raw = bytes.Replace(raw, []byte(`"kind":8181`), []byte(`"kind":8181,"kind":8181`), 1)
			r.ConsentHex = hex.EncodeToString(raw)
		}},
		{"event-signature-form", "CONSENT_SHAPE", func(r *GrantV4Request, e grantv4.Event) { e.Sig = "00"; r.ConsentHex = v4TestEventHex(t, e) }},
		{"child-assent-open", "UNSUPPORTED_CAPABILITY", func(r *GrantV4Request, _ grantv4.Event) {
			child, parent := v4Grant(t, "grant-v-05")
			r.SignedHex = hex.EncodeToString(child.Signed())
			r.ParentHex = hex.EncodeToString(parent)
		}},
		{"name-evidence-unavailable", "UNSUPPORTED_CAPABILITY", func(r *GrantV4Request, e grantv4.Event) {
			g, _ := v4Grant(t, "grant-v-02")
			r.SignedHex = hex.EncodeToString(g.Signed())
			r.NameOutput = &grantv4.Outpoint{TxID: strings.Repeat("1", 64)}
			e.Tags = append(e.Tags, []string{"name", "id/lip0020-recipient"})
			r.ConsentHex = v4TestEventHex(t, e)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, event := v4PreparationControl(t)
			e, exit := v4CLI(t, "grant anchor-v4", req)
			mustOK(t, e, exit)
			c.change(&req, event)
			e, exit = v4CLI(t, "grant anchor-v4", req)
			if exit != 3 || e.OK || e.Result != nil || e.Error == nil || e.Error.Code != c.code {
				t.Fatalf("want %s; got %+v", c.code, e.Error)
			}
		})
	}
	if len(cases) != 12 {
		t.Fatal("refusal table count")
	}
}

// TestV4ChildReviewLabel proves a child review uses its fixed parent delegation key label, never a root grant or request key label, before display or private-key use.
func TestV4ChildReviewLabel(t *testing.T) {
	r := v4KeyRequest(t, "grant-v-05")
	positive := newKCWithStore(t, confirmWord, keychainfake.New(), "0000000000000000000000000000000000000000000000000000000000000009")
	e, exit := v4KC(t, positive, "review-v4", r)
	mustOK(t, e, exit)
	for _, scalar := range []string{v4PublicTestScalar, bip340Secrets[keyLandlord]} {
		h := newKCWithStore(t, confirmWord, keychainfake.New(), scalar)
		e, exit = v4KC(t, h, "review-v4", r)
		if exit != 3 || e.Error == nil || e.Error.Code != "KEY_MISMATCH" || e.Result != nil || h.keyRead || h.term.shown.Len() != 0 {
			t.Fatal("child key-label separation failed")
		}
	}
}

// TestV4CalendarCLI proves explicit calendar inputs become only heights, and malformed members refuse before conversion even when the calendar is invalid too.
func TestV4CalendarCLI(t *testing.T) {
	r := v4Request(t, "grant-v-01")
	r.Calendar = &GrantV4Calendar{CurrentHeight: 200000, StartAfterSeconds: 61, EndAfterSeconds: 3600, TargetBlockSeconds: 60}
	e, exit := v4CLI(t, "grant draft-v4", r)
	mustOK(t, e, exit)
	result := v4Result(t, e)
	raw, _ := hex.DecodeString(result.PayloadHex)
	if !bytes.Contains(raw, []byte(`"not_before_height":200002`)) || !bytes.Contains(raw, []byte(`"not_after_height":200060`)) || bytes.Contains(raw, []byte("clock")) || bytes.Contains(raw, []byte("seconds")) {
		t.Fatal("calendar bytes instead of heights")
	}
	r.Calendar.TargetBlockSeconds = 0
	payload, _ := hex.DecodeString(r.PayloadHex)
	payload = bytes.Replace(payload, []byte(`"contract":`), []byte(`"clock":1,"contract":`), 1)
	r.PayloadHex = hex.EncodeToString(payload)
	e, exit = v4CLI(t, "grant draft-v4", r)
	if exit != 3 || e.Error == nil || e.Error.Code != "WIRE_MEMBER" || e.Result != nil {
		t.Fatal("calendar reordered document refusal")
	}
}

// TestV4ScopeCannotBeSupplied proves scope prose is derived from immutable document members, and the closed request accepts no caller-written scope text or digest.
func TestV4ScopeCannotBeSupplied(t *testing.T) {
	r := v4KeyRequest(t, "grant-v-01")
	h := newKCWithStore(t, confirmWord, keychainfake.New(), v4PublicTestScalar)
	e, exit := v4KC(t, h, "review-v4", r)
	mustOK(t, e, exit)
	for _, member := range []string{"scope_text", "digest"} {
		h := newKCWithStore(t, confirmWord, keychainfake.New(), v4PublicTestScalar)
		raw, _ := json.Marshal(r)
		var obj map[string]any
		if json.Unmarshal(raw, &obj) != nil {
			t.Fatal("request")
		}
		obj[member] = "caller text"
		e, exit := h.run("keychain", "review-v4", "--label", kcLabel, "--request", writeInput(t, obj))
		if exit != 2 || e.Error == nil || e.Error.Code != "BAD_INPUT" || e.Result != nil || h.keyRead || h.term.shown.Len() != 0 {
			t.Fatal("untrusted scope or digest accepted")
		}
	}
}
