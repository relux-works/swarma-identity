package grantv4

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func documentOutcome(raw []byte) (err error) {
	defer guard(&err)
	parseDocument(raw, MaxBytes)
	return nil
}

// TestDocumentEdges proves syntax/depth byte precedence and distinct decoded surrogate names cannot invent a duplicate refusal, beside valid controls.
func TestDocumentEdges(t *testing.T) {
	nested := func(n int) string { return `{"a":` + strings.Repeat("[", n) + `0` + strings.Repeat("]", n) + `}` }
	cases := []struct{ bad, code string }{
		{`{"\ud800":1,"�":2}`, "WIRE_STRING"},
		{`{"\ud800":1,"\ud801":2}`, "WIRE_STRING"},
		{`{"\ud800":1,"\ud800":2}`, "WIRE_DUPLICATE"},
		{`{"a":1,"\u0061":2}`, "WIRE_DUPLICATE"},
		{`{"a":"\u+001"}`, "WIRE_JSON"},
		{`{"a":"\ud800\u0001"}`, "WIRE_STRING"},
		{`{"a":"\ud800\uXXXX"}`, "WIRE_JSON"},
		{`{"a":"` + string([]byte{0xff}) + `"}`, "WIRE_JSON"},
		{nested(16), "WIRE_SIZE"},
		{strings.TrimSuffix(nested(16), "}"), "WIRE_SIZE"},
		{`{"a":?` + strings.Repeat("[", 17), "WIRE_JSON"},
		{strings.Repeat(" ", MaxBytes+1), "WIRE_SIZE"},
	}
	for _, c := range cases {
		if e := documentOutcome([]byte(nested(15))); e != nil {
			t.Fatalf("valid depth control: %v", e)
		}
		if e := documentOutcome([]byte(c.bad)); e == nil || e.Error() != c.code {
			t.Fatalf("want %s; got %v", c.code, e)
		}
	}
	if len(cases) != 12 {
		t.Fatal("edge count")
	}
}

// TestClosedEnvelope proves a signature replaced by another name and a spliced draft refuse as WIRE_MEMBER, while valid signed and unsigned controls pass unchanged.
func TestClosedEnvelope(t *testing.T) {
	_, c := loadCorpus(t)
	g := validGrants(t, c)["grant-v-01"]
	if _, e := Read(g.Signed(), nil, nil); e != nil {
		t.Fatal(e)
	}
	missing := bytes.Replace(g.Signed(), []byte(`"signature":`), []byte(`"z":`), 1)
	if got, e := Read(missing, nil, nil); e == nil || e.Error() != "WIRE_MEMBER" || got != nil {
		t.Fatalf("missing signature: %v", e)
	}
	if _, e := Draft(g.Payload(), nil); e != nil {
		t.Fatal(e)
	}
	splice := append(g.Payload(), []byte(`,"q":1`)...)
	if got, e := Draft(splice, nil); e == nil || e.Error() != "WIRE_MEMBER" || got != nil {
		t.Fatalf("spliced payload: %v", e)
	}
}

// TestGrantCopies proves callers cannot mutate checked bytes after validation and before display or signature verification.
func TestGrantCopies(t *testing.T) {
	_, c := loadCorpus(t)
	g := validGrants(t, c)["grant-v-01"]
	want := g.ID()
	b := g.Payload()
	b[0] = '['
	b = g.Signed()
	b[0] = '['
	if g.ID() != want {
		t.Fatal("caller mutated checked payload")
	}
	if _, e := Read(g.Signed(), nil, nil); e != nil {
		t.Fatal(e)
	}
}

// TestIntegerForms proves amount strings stay exact at uint64 bounds and never accept signs or numeric substitutes, beside valid draft controls.
func TestIntegerForms(t *testing.T) {
	_, c := loadCorpus(t)
	g := validGrants(t, c)["grant-v-01"]
	for _, v := range []struct {
		value any
		code  string
	}{
		{json.Number("1"), "WIRE_MEMBER"}, {"+1", "WIRE_INTEGER"}, {"-1", "WIRE_INTEGER"}, {"01", "WIRE_INTEGER"}, {"18446744073709551616", "WIRE_INTEGER"},
	} {
		if _, e := Draft(g.Payload(), nil); e != nil {
			t.Fatal(e)
		}
		var p object
		d := json.NewDecoder(bytes.NewReader(g.Payload()))
		d.UseNumber()
		if d.Decode(&p) != nil {
			t.Fatal("payload")
		}
		arr(p, "limits")[0].(object)["amount"] = v.value
		if got, e := Draft(encode(p), nil); e == nil || e.Error() != v.code || got != nil {
			t.Fatalf("want %s; got %v", v.code, e)
		}
	}
}
