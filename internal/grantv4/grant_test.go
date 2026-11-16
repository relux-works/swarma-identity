package grantv4

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type vector struct {
	ID             string `json:"id"`
	SignedFormHex  string `json:"signed_form_hex"`
	Expect         string `json:"expect"`
	ValidNeighbour string `json:"valid_neighbour"`
	Context        struct {
		Parent    string  `json:"parent"`
		Reference *string `json:"reference"`
	} `json:"context"`
	Digest     string   `json:"typed_digest"`
	GrantID    string   `json:"grant_id"`
	Address    string   `json:"content_address"`
	Script     string   `json:"seal_script"`
	Payload    string   `json:"payload"`
	Signature  string   `json:"signature"`
	SignedForm string   `json:"signed_form"`
	Octets     int      `json:"octets"`
	Outcomes   []string `json:"outcomes"`
	Judged     string   `json:"judged"`
}
type corpus struct {
	Valid        []vector `json:"valid"`
	Invalid      []vector `json:"invalid"`
	Compound     []vector `json:"compound"`
	Undetermined []vector `json:"undetermined"`
}

func loadCorpus(t *testing.T) ([]byte, corpus) {
	t.Helper()
	raw, e := os.ReadFile("testdata/grant-v4.json")
	if e != nil {
		t.Fatal(e)
	}
	// This pin and the identity literals below live outside the corpus: replacing
	// the corpus with one regenerated under another key cannot bless that key.
	if hash(raw) != "66d4a5b1738b746bd5403e30ed1bbd30be9aac256a2559795d038f3455b2b106" {
		t.Fatal("specification corpus pin changed")
	}
	var c corpus
	if e = json.Unmarshal(raw, &c); e != nil {
		t.Fatal(e)
	}
	return raw, c
}
func octets(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func validGrants(t *testing.T, c corpus) map[string]*Grant {
	t.Helper()
	out := map[string]*Grant{}
	for _, v := range c.Valid {
		g, e := Read(octets(t, v.SignedFormHex), out[v.Context.Parent], v.Context.Reference)
		if e != nil {
			t.Fatalf("%s: %v", v.ID, e)
		}
		out[v.ID] = g
	}
	return out
}

// TestVectors proves all 112 pinned outcomes, all four derived values, exact re-drafting of 11 valid grants, and all 19 refusal counts with adjacent positive controls.
func TestVectors(t *testing.T) {
	raw, c := loadCorpus(t)
	if len(c.Valid) != 11 || len(c.Invalid) != 84 || len(c.Compound) != 13 || len(c.Undetermined) != 4 {
		t.Fatal("vector count table changed")
	}
	grants := validGrants(t, c)
	byID := map[string]vector{}
	for _, v := range c.Valid {
		byID[v.ID] = v
	}
	for _, v := range c.Valid {
		t.Run(v.ID, func(t *testing.T) {
			g := grants[v.ID]
			if g.Digest() != v.Digest || g.ID() != v.GrantID || g.ContentAddress() != v.Address || g.SealScript() != v.Script {
				t.Fatal("derived values differ from specification")
			}
			if (v.Payload != "" && string(g.Payload()) != v.Payload) || g.Signature() != v.Signature || (v.SignedForm != "" && string(g.Signed()) != v.SignedForm) || len(g.Signed()) != v.Octets {
				t.Fatal("literal vector octets or signature differ")
			}
			// Identity expectations are fixed literals, never read from test_keys.
			if !g.Child() {
				issuer := obj(g.payload, "issuer")
				if str(issuer, "name") != "id/lip0020-issuer" || str(issuer, "grant_key") != "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" || str(issuer, "owner") != "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13" {
					t.Fatal("issuer identity changed")
				}
			} else if g.Signer() != "acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe" || str(obj(g.payload, "executor"), "name") != "id/lip0020-row-executor" {
				t.Fatal("child identity changed")
			}
			drafted, e := Draft(g.Payload(), grants[v.Context.Parent])
			if e != nil {
				t.Fatal(e)
			}
			signed, e := Attach(drafted, g.Signature(), grants[v.Context.Parent])
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(signed.Signed(), g.Signed()) || drafted.Digest() != v.Digest || drafted.ID() != v.GrantID {
				t.Fatal("round trip changed bytes or hashes")
			}
		})
	}
	counts := map[string]int{}
	for _, v := range append(c.Invalid, c.Compound...) {
		t.Run(v.ID, func(t *testing.T) {
			control := v.ValidNeighbour
			if control == "" {
				control = "grant-v-01"
			}
			positive := grants[control]
			if positive == nil {
				t.Fatal("missing positive control")
			}
			parent := grants[v.Context.Parent]
			if _, e := Read(positive.Signed(), grants[byID[control].Context.Parent], byID[control].Context.Reference); e != nil {
				t.Fatalf("positive control: %v", e)
			}
			_, e := Read(octets(t, v.SignedFormHex), parent, v.Context.Reference)
			if e == nil || e.Error() != v.Expect {
				t.Fatalf("want %s; got %v", v.Expect, e)
			}
		})
		counts[v.Expect]++
	}
	want := map[string]int{"WIRE_SIZE": 1, "WIRE_NOT_CANONICAL": 1, "WIRE_MEMBER": 34, "WIRE_TYPE": 1, "WIRE_VALUE": 3, "WIRE_INTEGER": 7, "WIRE_KEY": 3, "WIRE_SIGNATURE_FORM": 1, "WIRE_SIGNATURE": 3, "WIRE_ID": 4, "CHILD_SIGNER": 3, "NOT_DELEGABLE": 1, "CHAIN_DEPTH": 1, "GRANT_SHAPE": 5, "GRANT_DELEGATE": 22, "WIRE_JSON": 1, "WIRE_DUPLICATE": 2, "WIRE_NUMBER": 2, "WIRE_STRING": 2}
	if !reflect.DeepEqual(counts, want) {
		t.Fatalf("refusal counts differ: %v", counts)
	}
	for _, v := range c.Undetermined {
		t.Run(v.ID, func(t *testing.T) {
			if !reflect.DeepEqual(v.Outcomes, []string{"ok", "GRANT_DELEGATE"}) || v.Judged == "" {
				t.Fatal("proposal outcomes or judged point missing")
			}
			if _, e := Read(grants["grant-v-03"].Signed(), nil, nil); e != nil {
				t.Fatal(e)
			}
			if _, e := Read(octets(t, v.SignedFormHex), nil, nil); e != nil {
				t.Fatalf("proposal-only defect must read ok: %v", e)
			}
		})
	}
	// Export independently re-drafted valid bytes in the specification checker's
	// own format. Expected verdicts and all corpus pins remain unchanged.
	if path := os.Getenv("GRANTV4_OUTPUT"); path != "" {
		var data map[string]any
		if e := json.Unmarshal(raw, &data); e != nil {
			t.Fatal(e)
		}
		for _, entry := range data["valid"].([]any) {
			m := entry.(map[string]any)
			id := m["id"].(string)
			g := grants[id]
			parent := grants[byID[id].Context.Parent]
			d, e := Draft(g.Payload(), parent)
			if e != nil {
				t.Fatal(e)
			}
			s, e := Attach(d, g.Signature(), parent)
			if e != nil {
				t.Fatal(e)
			}
			m["signed_form_hex"] = hex.EncodeToString(s.Signed())
		}
		b, e := json.Marshal(data)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
}

// TestCalendarHeights proves explicit interval conversion rounds conservatively, bounds arithmetic, and emits no clock member, beside a valid draft for every refusal.
func TestCalendarHeights(t *testing.T) {
	_, c := loadCorpus(t)
	g := validGrants(t, c)["grant-v-01"]
	before, after, e := Heights(200000, 61, 3600, 60)
	if e != nil || before != 200002 || after != 200060 {
		t.Fatal("height conversion")
	}
	raw, e := WithHeights(g.Payload(), nil, before, after)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("clock")) || bytes.Contains(raw, []byte("seconds")) || !bytes.Contains(raw, []byte(`"not_before_height":200002`)) {
		t.Fatal("calendar data leaked into grant")
	}
	for _, v := range [][4]uint64{{0, 0, 1, 0}, {MaxNumber, 0, 120, 60}, {0, 60, 60, 60}, {0, 1, 2, 60}} {
		if _, _, e = Heights(200000, 0, 3600, 60); e != nil {
			t.Fatal(e)
		}
		if _, _, e = Heights(v[0], v[1], v[2], v[3]); e == nil || e.Error() != "GRANT_SHAPE" {
			t.Fatalf("want GRANT_SHAPE; got %v", e)
		}
	}
	p := bytes.Replace(g.Payload(), []byte(`"contract":`), []byte(`"clock":1,"contract":`), 1)
	if _, e = Draft(g.Payload(), nil); e != nil {
		t.Fatal(e)
	}
	if _, e = Draft(p, nil); e == nil || e.Error() != "WIRE_MEMBER" {
		t.Fatalf("clock member: %v", e)
	}
}

// TestCanonicalDocument proves UTF-16 sorting, literal JCS strings and globally ordered refusals beside valid canonical controls.
func TestCanonicalDocument(t *testing.T) {
	cases := []struct{ good, bad, code string }{
		{`{"a":1}`, `{"a":1} `, "WIRE_NOT_CANONICAL"},
		{`{"a":1}`, `{"a":null,"a":1.5}`, "WIRE_DUPLICATE"},
		{`{"a":1}`, `{"a":1.5,"b":null}`, "WIRE_VALUE"},
		{`{"a":1}`, `{"a":"\u0001","b":1.5}`, "WIRE_NUMBER"},
		{`{"a":1}`, `{"a":"\ud800"}`, "WIRE_STRING"},
		{`{"😀":1,"דּ":2}`, `{"דּ":2,"😀":1}`, "WIRE_NOT_CANONICAL"},
		{`{"a":"<>&/ "}`, `{"a":"\u003c>&/ "}`, "WIRE_NOT_CANONICAL"},
		{`{"a":1}`, `{"a":01}`, "WIRE_JSON"},
	}
	for _, v := range cases {
		t.Run(v.code+v.bad, func(t *testing.T) {
			read := func(b []byte) (err error) { defer guard(&err); parseDocument(b, MaxBytes); return nil }
			if e := read([]byte(v.good)); e != nil {
				t.Fatalf("control: %v", e)
			}
			if e := read([]byte(v.bad)); e == nil || e.Error() != v.code {
				t.Fatalf("want %s; got %v", v.code, e)
			}
		})
	}
}
