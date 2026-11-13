package registration

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// F3 binds the request's own closed schema, network and exact manifest bytes,
// independently of an otherwise unchanged valid PSBT and review frame.
func TestRestoreRequestBindings(t *testing.T) {
	p, plans, vectors := wireFixture(t, "two-stage")
	plan := plans[0]
	v := vectors["A"]
	r := requestFor(t, p, plan, plan.Transactions()[0], v)
	for _, field := range []string{"network", "schema", "plan_manifest_utf8"} {
		t.Run(field, func(t *testing.T) {
			saved := RetainedRequest{Slot: "A", PreparedAt: p.profile.Policy.CreatedAt + 60, IDs: RequestIDs{v.RequestID, v.SittingID, v.ExpiresAt}, Request: r.Bytes(), ReviewFrame: r.ReviewFrame()}
			if got, err := p.RestoreSigningRequest(plan, saved); got == nil || err != nil {
				t.Fatalf("valid request binding refused: %v", err)
			}
			var d map[string]json.RawMessage
			if err := json.Unmarshal(saved.Request, &d); err != nil {
				t.Fatal(err)
			}
			var old string
			if err := json.Unmarshal(d[field], &old); err != nil {
				t.Fatal(err)
			}
			d[field], _ = json.Marshal(old + " ")
			saved.Request, _ = json.Marshal(d)
			if got, err := p.RestoreSigningRequest(plan, saved); got != nil || !errors.Is(err, ErrParents) {
				t.Fatal("substituted request binding admitted")
			}
		})
	}
}

// Reservation, reveal and request preparation must be in the original window;
// equality at created_at is valid and release_not_after is excluded. All
// request variants keep a 1..600-second lifetime so expiry cannot mask this gate.
func TestRestoreOriginalWindows(t *testing.T) {
	p, in, rv, _, rawR, rawV := fixture(t, "two-stage")
	_, plans, _ := wireFixture(t, "two-stage")
	for _, phase := range []string{"reservation", "reveal", "request"} {
		t.Run(phase, func(t *testing.T) {
			for _, when := range []uint64{p.profile.Policy.CreatedAt, p.profile.Policy.CreatedAt - 1, p.profile.Policy.ReleaseNotAfter - 1, p.profile.Policy.ReleaseNotAfter} {
				valid := when == p.profile.Policy.CreatedAt || when == p.profile.Policy.ReleaseNotAfter-1
				var got any
				var err error
				switch phase {
				case "reservation":
					txs := plans[0].Transactions()
					result, e := p.RestoreReservation(in, when, rawR, [2]PreparedTransaction{txs[0], txs[1]})
					err = e
					if result != nil {
						got = result
					}
				case "reveal":
					txs := plans[1].Transactions()
					result, e := p.RestoreReveal(plans[0], rv, when, rawV, [2]PreparedTransaction{txs[0], txs[1]})
					err = e
					if result != nil {
						got = result
					}
				case "request":
					// Build at an admitted time with IDs whose lifetime remains valid
					// at the neighboring invalid recorded time as well.
					control := when
					if when < p.profile.Policy.CreatedAt {
						control++
					}
					if when == p.profile.Policy.ReleaseNotAfter {
						control--
					}
					ids := RequestIDs{strings.Repeat("11", 32), strings.Repeat("22", 32), control + 300}
					r, e := p.PrepareRequest(plans[0], "A", plans[0].Transactions()[0].PSBT, ids, control)
					if e != nil {
						t.Fatal(e)
					}
					result, e := p.RestoreSigningRequest(plans[0], RetainedRequest{"A", when, ids, r.Bytes(), r.ReviewFrame()})
					err = e
					if result != nil {
						got = result
					}
				}
				if valid && (got == nil || err != nil) {
					t.Fatalf("original window control refused: %v", err)
				}
				if !valid && (got != nil || !errors.Is(err, ErrParents)) {
					t.Fatal("original window violation admitted")
				}
			}
		})
	}
}
