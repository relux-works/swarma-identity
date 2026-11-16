package facade

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-identity/internal/grantv4"
	"github.com/relux-works/swarma-identity/internal/keychain/keychainfake"
)

const v4IssuerKey = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
const v4RequestKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"

// Public BIP-340 vector 0, fixed outside the generated corpus.
const v4PublicTestScalar = "0000000000000000000000000000000000000000000000000000000000000003"

func v4Corpus(t *testing.T) map[string][]byte {
	t.Helper()
	raw, e := os.ReadFile("../grantv4/testdata/grant-v4.json")
	if e != nil {
		t.Fatal(e)
	}
	if sha256Hex(raw) != "66d4a5b1738b746bd5403e30ed1bbd30be9aac256a2559795d038f3455b2b106" {
		t.Fatal("corpus pin changed")
	}
	var data struct {
		Valid []struct {
			ID  string `json:"id"`
			Hex string `json:"signed_form_hex"`
		} `json:"valid"`
	}
	if json.Unmarshal(raw, &data) != nil || len(data.Valid) != 11 {
		t.Fatal("corpus count")
	}
	out := map[string][]byte{}
	for _, v := range data.Valid {
		out[v.ID], e = hex.DecodeString(v.Hex)
		if e != nil {
			t.Fatal(e)
		}
	}
	return out
}
func v4Grant(t *testing.T, id string) (*grantv4.Grant, []byte) {
	t.Helper()
	data := v4Corpus(t)
	var parent *grantv4.Grant
	var raw []byte
	if id == "grant-v-05" {
		raw = data["grant-v-03"]
		var e error
		parent, e = grantv4.Read(raw, nil, nil)
		if e != nil {
			t.Fatal(e)
		}
	}
	g, e := grantv4.Read(data[id], parent, nil)
	if e != nil {
		t.Fatal(e)
	}
	return g, raw
}
func v4Request(t *testing.T, id string) GrantV4Request {
	t.Helper()
	g, parent := v4Grant(t, id)
	return GrantV4Request{Schema: GrantV4RequestSchema, PayloadHex: hex.EncodeToString(g.Payload()), ParentHex: hex.EncodeToString(parent)}
}
func v4Result(t *testing.T, e Envelope) GrantV4Draft {
	t.Helper()
	b, err := json.Marshal(e.Result)
	var r GrantV4Draft
	if err != nil || closedObject(b, reflect.TypeOf(r)) != nil || json.Unmarshal(b, &r) != nil {
		t.Fatal("v4 result does not match its closed type")
	}
	return r
}

func v4KeyRequest(t *testing.T, id string) KeychainV4Request {
	t.Helper()
	r := v4Request(t, id)
	return KeychainV4Request{Schema: KeychainV4Schema, PayloadHex: r.PayloadHex, ParentHex: r.ParentHex, LandlordValueHex: hex.EncodeToString([]byte(landlordValue(v4IssuerKey)))}
}
func v4CLI(t *testing.T, command string, r any) (Envelope, int) {
	t.Helper()
	var out, diag bytes.Buffer
	code := run(context.Background(), append(strings.Fields(command), "--request", writeInput(t, r), "--json"), &out, &diag, keychainDeps{})
	var e Envelope
	if json.Unmarshal(out.Bytes(), &e) != nil || diag.Len() != 0 {
		t.Fatal("CLI envelope")
	}
	return e, code
}
func v4KC(t *testing.T, h *kcHarness, command string, r KeychainV4Request) (Envelope, int) {
	t.Helper()
	return h.run("keychain", command, "--label", kcLabel, "--request", writeInput(t, r))
}

// TestGrantV4CLI proves every valid root/child including the 65536-byte boundary is re-drafted and externally sealed with identical bytes, without private-key custody.
func TestGrantV4CLI(t *testing.T) {
	for i := 1; i <= 11; i++ {
		id := fmt.Sprintf("grant-v-%02d", i)
		t.Run(id, func(t *testing.T) {
			r := v4Request(t, id)
			g, _ := v4Grant(t, id)
			e, exit := v4CLI(t, "grant draft-v4", r)
			mustOK(t, e, exit)
			d := v4Result(t, e)
			if d.PayloadHex != r.PayloadHex || d.TypedDigest != g.Digest() || d.GrantID != g.ID() || d.AdmissionChecked || d.SignedHex != "" {
				t.Fatal("draft changed bytes or claimed admission")
			}
			r.Signature = g.Signature()
			e, exit = v4CLI(t, "grant sign-v4", r)
			mustOK(t, e, exit)
			d = v4Result(t, e)
			if d.SignedHex != hex.EncodeToString(g.Signed()) || d.ContentAddress != g.ContentAddress() || d.AdmissionChecked {
				t.Fatal("external signature assembly changed bytes")
			}
		})
	}
}

// TestGrantV4CLIRefusals proves malformed, noncanonical, cross-stage and parentless requests release no draft, beside a valid root or child control for every exact refusal.
func TestGrantV4CLIRefusals(t *testing.T) {
	cases := []struct {
		name, code string
		id         string
		change     func(*GrantV4Request)
	}{
		{"clock", "WIRE_MEMBER", "grant-v-01", func(r *GrantV4Request) {
			raw, _ := hex.DecodeString(r.PayloadHex)
			raw = bytes.Replace(raw, []byte(`"contract":`), []byte(`"clock":1,"contract":`), 1)
			r.PayloadHex = hex.EncodeToString(raw)
		}},
		{"canonical", "WIRE_NOT_CANONICAL", "grant-v-01", func(r *GrantV4Request) { r.PayloadHex += "20" }},
		{"parent", "WIRE_ID", "grant-v-05", func(r *GrantV4Request) { r.ParentHex = "" }},
		{"signature-stage", "BAD_INPUT", "grant-v-01", func(r *GrantV4Request) { r.Signature = strings.Repeat("0", 128) }},
		{"invalid-hex", "BAD_INPUT", "grant-v-01", func(r *GrantV4Request) { r.PayloadHex = "zz" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := v4Request(t, c.id)
			e, exit := v4CLI(t, "grant draft-v4", r)
			mustOK(t, e, exit)
			c.change(&r)
			e, exit = v4CLI(t, "grant draft-v4", r)
			if exit != 3 && exit != 2 {
				t.Fatal("negative exit")
			}
			if e.OK || e.Result != nil || e.Error == nil || e.Error.Code != c.code {
				t.Fatalf("want %s, got %+v", c.code, e.Error)
			}
		})
	}
}

// expectedV4Leaves is an independent test walker; it does not call jsonLeaves
// or the renderer. Numbers are preserved exactly, not read through binary64.
func expectedV4Leaves(t *testing.T, raw []byte) []string {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		t.Fatal("payload")
	}
	var out []string
	var walk func(string, any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			if len(x) == 0 {
				out = append(out, path+" = {}")
				return
			}
			names := make([]string, 0, len(x))
			for k := range x {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				p := k
				if path != "" {
					p = path + "." + k
				}
				walk(p, x[k])
			}
		case []any:
			if len(x) == 0 {
				out = append(out, path+" = []")
				return
			}
			for i, v := range x {
				walk(fmt.Sprintf("%s[%d]", path, i), v)
			}
		default:
			b, e := json.Marshal(v)
			if e != nil {
				t.Fatal(e)
			}
			out = append(out, path+" = "+string(b))
		}
	}
	walk("", v)
	return out
}
func shownV4Payloads(t *testing.T, shown string) [][]byte {
	t.Helper()
	var result [][]byte
	var current []byte
	active := false
	for _, line := range strings.Split(shown, "\n") {
		if strings.HasPrefix(line, "  exact payload (") {
			active = true
			current = nil
			continue
		}
		if active && strings.HasPrefix(line, "    ") && len(line) > 10 {
			offset, e := strconv.Atoi(line[4:9])
			if e != nil || line[9] != ' ' || offset != len(current) {
				t.Fatal("display offset")
			}
			s := line[10:]
			for len(s) > 0 {
				if strings.HasPrefix(s, `\x`) {
					if len(s) < 4 {
						t.Fatal("escape")
					}
					b, e := hex.DecodeString(s[2:4])
					if e != nil {
						t.Fatal(e)
					}
					current = append(current, b...)
					s = s[4:]
				} else {
					current = append(current, s[0])
					s = s[1:]
				}
			}
			continue
		}
		if active {
			result = append(result, current)
			active = false
		}
	}
	return result
}

// TestV4DisplayCoverage proves every preimage leaf and exact byte for all 11 valid root/child documents is shown, with independently fixed leaf counts and scope text last.
func TestV4DisplayCoverage(t *testing.T) {
	counts := []int{30, 31, 81, 45, 22, 30, 21, 1511, 30, 80, 293}
	for i, count := range counts {
		id := fmt.Sprintf("grant-v-%02d", i+1)
		t.Run(id, func(t *testing.T) {
			scalar := v4PublicTestScalar
			if id == "grant-v-05" {
				scalar = "0000000000000000000000000000000000000000000000000000000000000009"
			}
			h := newKCWithStore(t, confirmWord, keychainfake.New(), scalar)
			r := v4KeyRequest(t, id)
			g, _ := v4Grant(t, id)
			e, exit := v4KC(t, h, "review-v4", r)
			mustOK(t, e, exit)
			shown := h.term.shown.String()
			fields := expectedV4Leaves(t, g.Payload())
			if len(fields) != count || !strings.Contains(shown, fmt.Sprintf("  committed fields (%d):\n", count)) {
				t.Fatal("display field count")
			}
			for _, field := range fields {
				if strings.Count(shown, "    "+field+"\n") != 1 {
					t.Fatalf("omitted or repeated preimage field: %s", field)
				}
			}
			raw := shownV4Payloads(t, shown)
			if len(raw) != 1 || !bytes.Equal(raw[0], g.Payload()) {
				t.Fatal("display does not reconstruct exact payload")
			}
			if !strings.Contains(shown, "Landlord value: NOT VERIFIED BY THIS SIGNER.") || !strings.Contains(shown, "no chain was read.") {
				t.Fatal("stated value overclaimed")
			}
			scope := strings.Index(shown, "SCOPE TEXT:")
			if scope < strings.Index(shown, "exact payload") || !strings.HasSuffix(shown, "Review only: no confirmation and no signature will be requested.\n") {
				t.Fatal("scope text not last")
			}
			if h.keyRead || strings.Contains(strings.Join(h.log, " "), "confirm") {
				t.Fatal("review used a private key or asked for approval")
			}
		})
	}
}

// TestV4RootAssentOnly proves one fake-keychain authentication follows exact displayed preimages and confirmation, and its signature verifies for the assent but not the grant.
func TestV4RootAssentOnly(t *testing.T) {
	h := newKCWithStore(t, confirmWord, keychainfake.New(), v4PublicTestScalar)
	e, exit := v4KC(t, h, "sign-v4", v4KeyRequest(t, "grant-v-01"))
	mustOK(t, e, exit)
	var r struct {
		PayloadHex      string `json:"payload_hex"`
		Digest          string `json:"typed_digest"`
		Signature       string `json:"signature"`
		SignedAssentHex string `json:"signed_assent_hex"`
	}
	b, _ := json.Marshal(e.Result)
	if json.Unmarshal(b, &r) != nil {
		t.Fatal("assent output")
	}
	if !h.keyRead || h.preKey != h.term.shown.String() || !strings.HasSuffix(h.preKey, wantPrompt) {
		t.Fatal("signature preceded full display and confirmation")
	}
	secretReads := 0
	for _, e := range h.log {
		if strings.HasPrefix(e, "secret:") {
			secretReads++
		}
	}
	if secretReads != 1 {
		t.Fatalf("private-key reads: %d", secretReads)
	}
	g, _ := v4Grant(t, "grant-v-01")
	if !grantv4.Verify(v4IssuerKey, r.Digest, r.Signature) || grantv4.Verify(v4IssuerKey, g.Digest(), r.Signature) {
		t.Fatal("signature domain confusion")
	}
	payloads := shownV4Payloads(t, h.preKey)
	raw, _ := hex.DecodeString(r.PayloadHex)
	if len(payloads) != 2 || !bytes.Equal(payloads[0], g.Payload()) || !bytes.Equal(payloads[1], raw) {
		t.Fatal("signed assent differs from shown bytes")
	}
	for _, field := range expectedV4Leaves(t, raw) {
		if !strings.Contains(h.preKey, "    "+field+"\n") {
			t.Fatalf("assent field missing: %s", field)
		}
	}
}

// TestV4KeychainRefusals proves wrong labels, unsupported child signing, malformed requests and declines have exact codes before private-key use, beside valid signing controls.
func TestV4KeychainRefusals(t *testing.T) {
	cases := []struct {
		name, code, id, scalar, answer string
		mutate                         func(*KeychainV4Request)
		shown                          bool
	}{
		{"wrong-label", "KEY_MISMATCH", "grant-v-01", bip340Secrets[keyOther], confirmWord, nil, false},
		{"child-signing", "UNSUPPORTED_CAPABILITY", "grant-v-05", v4PublicTestScalar, confirmWord, nil, false},
		{"stated-value", "STATED_LANDLORD_VALUE_KEY_MISMATCH", "grant-v-01", v4PublicTestScalar, confirmWord, func(r *KeychainV4Request) {
			r.LandlordValueHex = hex.EncodeToString([]byte(landlordValue(v4RequestKey)))
		}, false},
		{"noncanonical", "WIRE_NOT_CANONICAL", "grant-v-01", v4PublicTestScalar, confirmWord, func(r *KeychainV4Request) { r.PayloadHex += "20" }, false},
		{"declined", "CONFIRMATION_DECLINED", "grant-v-01", v4PublicTestScalar, "NO", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			positive := newKCWithStore(t, confirmWord, keychainfake.New(), v4PublicTestScalar)
			e, exit := v4KC(t, positive, "sign-v4", v4KeyRequest(t, "grant-v-01"))
			mustOK(t, e, exit)
			if !positive.keyRead {
				t.Fatal("positive made no signature")
			}
			h := newKCWithStore(t, c.answer, keychainfake.New(), c.scalar)
			r := v4KeyRequest(t, c.id)
			if c.mutate != nil {
				c.mutate(&r)
			}
			e, exit = v4KC(t, h, "sign-v4", r)
			if exit != 3 || e.OK || e.Result != nil || e.Error == nil || e.Error.Code != c.code {
				t.Fatalf("want %s, got %+v", c.code, e.Error)
			}
			if h.keyRead || (h.term.shown.Len() > 0) != c.shown {
				t.Fatal("refusal used a key or showed an unbound document")
			}
		})
	}
}

// TestV4OfflinePreparation proves the defined by-key root assent/consent/preparation/frame bytes compose without claiming admission, and exports an externally signed grant for the independent checker.
func TestV4OfflinePreparation(t *testing.T) {
	r := v4Request(t, "grant-v-01")
	e, exit := v4CLI(t, "grant consent-v4", func() GrantV4Request { x := r; x.CreatedAt = 1700000000; return x }())
	mustOK(t, e, exit)
	var consent struct {
		Event grantv4.Event `json:"event_template"`
	}
	b, _ := json.Marshal(e.Result)
	if json.Unmarshal(b, &consent) != nil {
		t.Fatal("consent output")
	}
	if consent.Event.Pubkey != v4RequestKey || len(consent.Event.Tags) != 4 || consent.Event.Tags[3][1] != v4IssuerKey {
		t.Fatal("consent identity changed")
	}
	consent.Event.Sig = sign(t, testSigner(t, keyLandlord), consent.Event.ID)
	eventRaw, _ := json.Marshal(consent.Event)
	h := newKCWithStore(t, confirmWord, keychainfake.New(), v4PublicTestScalar)
	e, exit = v4KC(t, h, "sign-v4", v4KeyRequest(t, "grant-v-01"))
	mustOK(t, e, exit)
	var assent struct {
		Hex string `json:"signed_assent_hex"`
	}
	b, _ = json.Marshal(e.Result)
	if json.Unmarshal(b, &assent) != nil {
		t.Fatal("assent output")
	}
	g, _ := v4Grant(t, "grant-v-01")
	// The external test signer is not the production device grant route. That
	// route remains disabled until the issuer's pre-sign duties are integrated.
	r.Signature = sign(t, testSigner(t, keyGrantee), g.Digest())
	e, exit = v4CLI(t, "grant sign-v4", r)
	mustOK(t, e, exit)
	signed := v4Result(t, e)
	req := GrantV4Request{Schema: GrantV4RequestSchema, SignedHex: signed.SignedHex, AssentHex: assent.Hex, ConsentHex: hex.EncodeToString(eventRaw), Now: 1700000001}
	e, exit = v4CLI(t, "grant anchor-v4", req)
	mustOK(t, e, exit)
	var anchor struct {
		Prep       string `json:"preparation_hex"`
		Commitment string `json:"commitment"`
		Frame      string `json:"frame_hex"`
		Dry        bool   `json:"dry_run"`
		Admission  bool   `json:"admission_checked"`
	}
	b, _ = json.Marshal(e.Result)
	if json.Unmarshal(b, &anchor) != nil {
		t.Fatal("anchor output")
	}
	if !anchor.Dry || anchor.Admission || len(anchor.Frame) != 144 || !strings.HasPrefix(anchor.Frame, "6a03534c014202") || !strings.HasSuffix(anchor.Frame, "01"+signed.ContentAddress) {
		t.Fatal("wrong v4 anchor or admission claim")
	}
	prep, _ := hex.DecodeString(anchor.Prep)
	if bytes.Contains(prep, []byte("clock")) || bytes.Contains(prep, []byte("created_at")) || !bytes.Contains(prep, []byte(`"type":"swarma-issuance/1"`)) {
		t.Fatal("wrong preparation members")
	}
	for _, c := range []struct {
		name, code string
		change     func(*GrantV4Request)
	}{
		{"mode", "ISSUANCE_MODE", func(r *GrantV4Request) { r.NameOutput = &grantv4.Outpoint{}; r.AssentHex = "00" }},
		{"consent-time", "CONSENT_TIME", func(r *GrantV4Request) { r.Now = 1699999999 }},
		{"frame-version", "ISSUANCE_FRAME", func(r *GrantV4Request) { r.FrameHex = anchor.Frame[:12] + "01" + anchor.Frame[14:] }},
		{"frame-pointer", "ISSUANCE_FRAME", func(r *GrantV4Request) { r.FrameHex = anchor.Frame[:80] + g.ID() }},
		{"commitment", "ISSUANCE_COMMITMENT", func(r *GrantV4Request) { r.FrameHex = anchor.Frame[:14] + strings.Repeat("0", 64) + anchor.Frame[78:] }},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, exit := v4CLI(t, "grant anchor-v4", req)
			mustOK(t, e, exit)
			bad := req
			c.change(&bad)
			e, exit = v4CLI(t, "grant anchor-v4", bad)
			if exit != 3 || e.OK || e.Result != nil || e.Error == nil || e.Error.Code != c.code {
				t.Fatalf("want %s, got %+v", c.code, e.Error)
			}
		})
	}
	if dir := os.Getenv("GRANTV4_ISSUED_DIR"); dir != "" {
		raw, _ := hex.DecodeString(signed.SignedHex)
		doc := map[string]any{"valid": []any{map[string]any{"id": "issued-root", "expect": "ok", "octets": len(raw), "signed_form_hex": signed.SignedHex, "signature": r.Signature, "typed_digest": signed.TypedDigest, "grant_id": signed.GrantID, "content_address": signed.ContentAddress, "seal_script": signed.SealScript}}, "invalid": []any{}, "compound": []any{}, "undetermined": []any{}, "rules": []any{}, "codes_exercised": []any{}, "not_exercised": []any{}, "no_neighbour": []any{}}
		data, _ := json.Marshal(doc)
		if e := os.WriteFile(filepath.Join(dir, "issued-root.json"), data, 0600); e != nil {
			t.Fatal(e)
		}
		data, _ = json.Marshal(map[string]any{"preparation_hex": anchor.Prep, "commitment": anchor.Commitment, "frame_hex": anchor.Frame, "signed_hex": signed.SignedHex, "assent_hex": assent.Hex, "consent_hex": hex.EncodeToString(eventRaw)})
		if e := os.WriteFile(filepath.Join(dir, "preparation.json"), data, 0600); e != nil {
			t.Fatal(e)
		}
		// Bytes plus an expected verdict and the parent bytes are an explicit
		// provisional junction format; no consumer format was supplied here.
		child, parent := v4Grant(t, "grant-v-05")
		junction := map[string]any{"schema": "swarma-grant-v4/junction/1", "cases": []any{map[string]any{"id": "root", "signed_form_hex": signed.SignedHex, "expect": "ok"}, map[string]any{"id": "child", "signed_form_hex": hex.EncodeToString(child.Signed()), "parent_hex": hex.EncodeToString(parent), "expect": "ok"}}}
		data, _ = json.Marshal(junction)
		if e := os.WriteFile(filepath.Join(dir, "junction.json"), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
