package facade

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"testing"
	"time"

	reg "github.com/relux-works/swarma-identity/internal/registration"
)

// These envelope-only fixtures exercise the size predicates, not semantic PSBT
// admission or a reachable producer maximum. Both ceilings admit equality.
func TestRegistrationEmissionSize(t *testing.T) {
	for _, size := range []int{2097151, 2097152, 2097153} {
		t.Run(fmt.Sprintf("request%d", size), func(t *testing.T) {
			raw := []byte(`{"psbt":"AA==","padding":""}`)
			raw = append(raw[:len(raw)-2], append(bytes.Repeat([]byte{'x'}, size-len(raw)), '"', '}')...)
			if len(raw) != size || !json.Valid(raw) {
				t.Fatal("invalid size fixture")
			}
			regTestEmissionSizeVerdict(t, raw, size > 2097152)
		})
	}
	for _, size := range []int{1048575, 1048576, 1048577} {
		t.Run(fmt.Sprintf("psbt%d", size), func(t *testing.T) {
			raw := regTestJSON(t, struct {
				PSBT string `json:"psbt"`
			}{base64.StdEncoding.EncodeToString(make([]byte, size))})
			if len(raw) >= 2097152 {
				t.Fatal("PSBT fixture did not isolate the decoded-size gate")
			}
			regTestEmissionSizeVerdict(t, raw, size > 1048576)
		})
	}
}

func regTestEmissionSizeVerdict(t *testing.T, raw []byte, refused bool) {
	t.Helper()
	f := regEmissionSize(raw)
	if refused {
		if f == nil || f.Code != "REGISTRATION_FILES" || f.Exit != 1 {
			t.Fatal("oversize fresh request admitted or wrong refusal")
		}
	} else if f != nil {
		t.Fatal("size-admissible fresh request refused")
	}
}

// A real current-clock CLI producer remains admissible and retains exactly the
// generated request/frame digests. The size fixtures above are not this witness.
func TestRegistrationEmissionProducer(t *testing.T) {
	e := newRegTestEnv(t, "two-stage", true)
	reservation, en, exit := e.run(t, "reserve", "reservation", e.reserve)
	regTestSuccess(t, en, exit)
	out, en, exit := e.run(t, "request", "request", regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "A", 600})
	if !en.OK {
		// Tightened-limit mechanism controls must prove the CLI's FILES/1
		// refusal and absent output, rather than merely any failing run.
		if en.Error != nil && en.Error.Code == "REGISTRATION_POLICY_REFUSED" {
			regTestRefusal(t, en, exit, "REGISTRATION_POLICY_REFUSED", out)
			t.Fatal("valid producer refused by emission time guard")
		}
		regTestRefusal(t, en, exit, "REGISTRATION_FILES", out)
		t.Fatal("valid producer refused by emission size guard")
	}
	regTestSuccess(t, en, exit)
	dir := filepath.Dir(out)
	raw := regTestRead(t, filepath.Join(dir, "request.json"))
	var request struct {
		PSBT string `json:"psbt"`
	}
	var state regRequestState
	if json.Unmarshal(raw, &request) != nil || !regState(regTestRead(t, filepath.Join(dir, "request-state.json")), &state, "request-state") {
		t.Fatal("invalid produced state")
	}
	psbt, err := base64.StdEncoding.Strict().DecodeString(request.PSBT)
	if err != nil || len(raw) > 2097152 || len(psbt) > 1048576 || state.RequestHash != regDigest(raw) || state.ReviewHash != regDigest(regTestRead(t, filepath.Join(dir, "review-frame.bin"))) {
		t.Fatal("fresh producer size or retained-byte binding")
	}
	session := regTestSession(t, e)
	plan, f := session.plan(reservation, regTestBundleHash(t, reservation), 1, "reservation")
	if f != nil {
		t.Fatal(f)
	}
	expected, err := session.planner.PrepareRequest(plan, state.Slot, request.PSBT, reg.RequestIDs{RequestID: state.RequestID, SittingID: state.SittingID, ExpiresAt: state.ExpiresAt}, state.PreparedAt)
	if err != nil || !bytes.Equal(expected.Bytes(), raw) || !bytes.Equal(expected.ReviewFrame(), regTestRead(t, filepath.Join(dir, "review-frame.bin"))) {
		t.Fatal("fresh emission changed canonical request or frame")
	}
	t.Logf("actual producer request=%d bytes decoded PSBT=%d bytes", len(raw), len(psbt))
}

// Frozen endpoints admit exactly 30 seconds at the captured instant, never
// 29.999999999 seconds; invalid/expired endpoints and negative time refuse.
func TestRegistrationEmissionMargin(t *testing.T) {
	const epoch = int64(1800000000)
	for _, nanos := range []int64{0, 1, 999999999} {
		for _, request := range []uint64{29, 30, 31} {
			for _, release := range []uint64{29, 30, 31} {
				t.Run(fmt.Sprintf("ns%d-request%d-release%d", nanos, request, release), func(t *testing.T) {
					want := request >= 30 && release >= 30 && (nanos == 0 || (request > 30 && release > 30))
					if regEmissionMargin(uint64(epoch)+request, uint64(epoch)+release, time.Unix(epoch, nanos)) != want {
						t.Fatal("fresh emission margin mismatch")
					}
				})
			}
		}
	}
	for _, tc := range []struct {
		name             string
		now              time.Time
		request, release uint64
	}{
		{"negative", time.Unix(-1, 999999999), 60, 60},
		{"request-expired", time.Unix(epoch, 0), uint64(epoch), uint64(epoch) + 60},
		{"release-expired", time.Unix(epoch, 0), uint64(epoch) + 60, uint64(epoch) - 1},
		{"request-invalid", time.Unix(epoch, 0), math.MaxUint64, uint64(epoch) + 60},
		{"release-invalid", time.Unix(epoch, 0), uint64(epoch) + 60, math.MaxUint64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if regEmissionMargin(tc.request, tc.release, tc.now) {
				t.Fatal("invalid emission endpoint or clock admitted")
			}
		})
	}
	// Near the supported integer ceiling, subtraction must remain checked.
	if !regEmissionMargin(math.MaxInt64, math.MaxInt64, time.Unix(math.MaxInt64-30, 0)) || regEmissionMargin(math.MaxInt64, math.MaxInt64, time.Unix(math.MaxInt64-30, 1)) {
		t.Fatal("large endpoint margin wrapped or rounded")
	}
}

// A real clock capture agrees with an independent duration comparison, including
// fractional seconds. This predicate check does not export a CLI clock override.
func TestRegistrationEmissionActualTime(t *testing.T) {
	now := time.Now()
	for _, seconds := range []int64{29, 30, 31, 600} {
		end := time.Unix(now.Unix()+seconds, 0)
		want := end.Sub(now) >= 30*time.Second
		if regEmissionMargin(uint64(end.Unix()), uint64(end.Unix()), now) != want {
			t.Fatal("actual captured emission margin rounded")
		}
		t.Logf("actual capture: endpoint offset=%d seconds remaining=%s admissible=%t", seconds, end.Sub(now), want)
	}
}
