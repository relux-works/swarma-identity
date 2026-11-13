package registration

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// Retained public reconstructions reproduce both modes and all eight frozen
// frames without a current clock; changes return no usable context. Journal
// fields in these public fixtures do not authenticate native completion.
func TestRestoreOriginalContext(t *testing.T) {
	for _, mode := range []string{"two-stage", "all-four-before-release"} {
		p, in, rv, _, rawR, rawV := fixture(t, mode)
		_, plans, vectors := wireFixture(t, mode)
		when := p.profile.Policy.CreatedAt + 60
		txs := plans[0].Transactions()
		r, e := p.RestoreReservation(in, when, rawR, [2]PreparedTransaction{txs[0], txs[1]})
		if e != nil {
			t.Fatal(e)
		}
		txs = plans[1].Transactions()
		v, e := p.RestoreReveal(r, rv, when, rawV, [2]PreparedTransaction{txs[0], txs[1]})
		if e != nil {
			t.Fatal(e)
		}
		for _, plan := range []*Plan{r, v} {
			for _, tx := range plan.Transactions() {
				original := requestFor(t, p, plan, tx, vectors[tx.Slot])
				saved := RetainedRequest{Slot: tx.Slot, PreparedAt: when, IDs: RequestIDs{vectors[tx.Slot].RequestID, vectors[tx.Slot].SittingID, vectors[tx.Slot].ExpiresAt}, Request: original.Bytes(), ReviewFrame: original.ReviewFrame()}
				// An admitted alternate JSON representation must survive byte-for-byte.
				saved.Request = append([]byte(" \n"), saved.Request...)
				restored, e := p.RestoreSigningRequest(plan, saved)
				if e != nil {
					t.Fatal(e)
				}
				saved.Request[0] = '\t'
				saved.ReviewFrame[0] ^= 1
				if bytes.Equal(restored.Bytes(), saved.Request) || !bytes.Equal(restored.ReviewFrame(), original.ReviewFrame()) {
					t.Fatal("caller owns restored bytes")
				}
				result := []byte(vectors[tx.Slot].Result)
				if _, e = p.CheckResult(restored, result, ackFor(result), 0); e != nil {
					t.Fatal(e)
				}
				for _, edit := range []func(*RetainedRequest){
					func(x *RetainedRequest) { x.IDs.RequestID = "00" }, func(x *RetainedRequest) { x.IDs.ExpiresAt++ },
					func(x *RetainedRequest) { x.PreparedAt = p.profile.Policy.ReleaseNotAfter },
					func(x *RetainedRequest) { x.ReviewFrame[0] ^= 1 }, func(x *RetainedRequest) { x.Slot = "E" },
					func(x *RetainedRequest) { x.Request = append(x.Request, []byte(`{}`)...) },
					func(x *RetainedRequest) {
						x.Request = bytes.Replace(x.Request, []byte(`"schema":`), []byte(`"Schema":`), 1)
					},
				} {
					bad := RetainedRequest{Slot: tx.Slot, PreparedAt: when, IDs: RequestIDs{vectors[tx.Slot].RequestID, vectors[tx.Slot].SittingID, vectors[tx.Slot].ExpiresAt}, Request: original.Bytes(), ReviewFrame: original.ReviewFrame()}
					edit(&bad)
					got, e := p.RestoreSigningRequest(plan, bad)
					if got != nil || !errors.Is(e, ErrParents) {
						t.Fatalf("partial restoration or wrong error: %v", e)
					}
				}
			}
		}
		bad := append([]byte(nil), rawR...)
		bad[0] ^= 1
		if got, e := p.RestoreReservation(in, when, bad, [2]PreparedTransaction{plans[0].Transactions()[0], plans[0].Transactions()[1]}); got != nil || !errors.Is(e, ErrParents) {
			t.Fatal("changed manifest admitted")
		}
		if got, e := p.Reserve(in, p.profile.Policy.ReleaseNotAfter); got != nil || !errors.Is(e, ErrPolicy) {
			t.Fatal("fresh expired reserve admitted")
		}
	}
}

// Arbitrary UTF-8 and noncanonical d/ values are refused beside the canonical
// frozen positive control, before either reservation or reveal can be emitted.
func TestFixedValueCanonicalAdmission(t *testing.T) {
	p, in, rv, _, _, _ := fixture(t, "two-stage")
	when := p.profile.Policy.CreatedAt + 60
	r, e := p.Reserve(in, when)
	if e != nil {
		t.Fatal(e)
	}
	for _, value := range [][]byte{[]byte("arbitrary"), []byte(`{"nostr":{"names":{"_":"00"}}}`), append(append([]byte(nil), in.Registrations[1].FixedValue...), '\n')} {
		bad := in
		bad.Registrations[1].FixedValue = value
		if got, e := p.Reserve(bad, when); got != nil || !errors.Is(e, ErrValue) {
			t.Fatalf("bad fixed value: %v", e)
		}
	}
	var pin map[string]any
	json.Unmarshal(rv.ValuesPin, &pin)
	rows := pin["registrations"].([]any)
	row := rows[1].(map[string]any)
	row["value_hex"] = "616263"
	row["value_sha256"] = digest([]byte("abc"))
	rv.ValuesPin, _ = json.Marshal(pin)
	if got, e := p.Reveal(r, rv, when); got != nil || !errors.Is(e, ErrValue) {
		t.Fatalf("invalid reveal value: %v", e)
	}
}

// Paired Unicode escapes and escaped literal text survive; unpaired surrogate
// escapes and invalid UTF-8 cannot be silently replaced in retained strings.
func TestRetainedUnicode(t *testing.T) {
	for _, raw := range []string{`{"x":"\ud800\udc00"}`, `{"x":"\\ud800"}`, `{"x":"\u0041"}`} {
		if !retainedUnicode([]byte(raw)) {
			t.Fatal("valid retained escape refused")
		}
	}
	for _, raw := range [][]byte{[]byte(`{"x":"\ud800"}`), []byte(`{"x":"\udc00"}`), []byte(`{"x":"\ud800\u0041"}`), []byte{'"', 0xff, '"'}} {
		if retainedUnicode(raw) {
			t.Fatal("invalid retained escape admitted")
		}
	}
}
