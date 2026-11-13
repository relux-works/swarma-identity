package facade

import (
	"crypto/rand"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"
)

type regCountedRandom struct {
	reader io.Reader
	reads  int
}

func (r *regCountedRandom) Read(p []byte) (int, error) {
	r.reads++
	return r.reader.Read(p)
}

// The retained preparation gate refuses before consuming either fresh ID,
// even though the final emission gate would also refuse. The observer delegates
// unchanged bytes from the actual CSPRNG; it supplies no seed or test randomness.
func TestRegistrationPreIDMargin(t *testing.T) {
	for _, dimension := range []string{"lifetime", "release"} {
		t.Run(dimension, func(t *testing.T) {
			e := newRegTestEnv(t, "two-stage", true)
			if dimension == "release" {
				e.profile.Policy.ReleaseNotAfter = uint64(time.Now().Unix()) + 29
				e.profileRaw = regTestJSON(t, e.profile)
				regTestWrite(t, e.profilePath, e.profileRaw)
			}
			reservation, en, exit := e.run(t, "reserve", "reservation", e.reserve)
			regTestSuccess(t, en, exit)
			original := rand.Reader
			observer := &regCountedRandom{reader: original}
			rand.Reader = observer
			t.Cleanup(func() { rand.Reader = original })
			lifetime := uint64(600)
			if dimension == "lifetime" {
				lifetime = 29
			}
			out, en, exit := e.run(t, "request", "short", regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "A", lifetime})
			regTestRefusal(t, en, exit, "REGISTRATION_POLICY_REFUSED", out)
			if observer.reads != 0 {
				t.Fatal("short preparation window consumed fresh IDs")
			}
		})
	}
	// A nearby valid preparation must actually exercise this same observer.
	e := newRegTestEnv(t, "two-stage", true)
	reservation, en, exit := e.run(t, "reserve", "reservation", e.reserve)
	regTestSuccess(t, en, exit)
	original := rand.Reader
	observer := &regCountedRandom{reader: original}
	rand.Reader = observer
	t.Cleanup(func() { rand.Reader = original })
	_, en, exit = e.run(t, "request", "valid", regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "A", 600})
	regTestSuccess(t, en, exit)
	if observer.reads != 2 {
		t.Fatal("fresh ID observer did not witness both generated IDs")
	}
	t.Log("valid neighboring request generated both IDs and emitted successfully")
}

// The dispatch policy admits equality at 30 seconds for each independent
// margin, and refuses either shorter margin even when the other is valid.
// This pure predicate uses captured remaining seconds, not a replacement clock.
func TestRegistrationDispatchMargin(t *testing.T) {
	for _, remaining := range []uint64{28, 29, 30, 31, 600} {
		for _, lifetime := range []uint64{28, 29, 30, 31, 600} {
			t.Run(fmt.Sprintf("lifetime%d-release%d", lifetime, remaining), func(t *testing.T) {
				want := lifetime >= 30 && remaining >= 30
				if regDispatchMargin(lifetime, remaining) != want {
					t.Fatal("dispatch margin boundary violated")
				}
			})
		}
	}
}

// Short actual-clock windows refuse POLICY before output. The earlier R2
// preparation predicate still admits equality, but final emission also checks
// fractional time: even lifetime 30 can be consumed without changing expiry.
// Successful neighbors retain their original preparation clock and lifetime.
func TestRegistrationFreshDispatchWindow(t *testing.T) {
	for _, lifetime := range []uint64{1, 28, 29, 30, 31, 600} {
		t.Run(fmt.Sprintf("lifetime%d", lifetime), func(t *testing.T) {
			e := newRegTestEnv(t, "two-stage", true)
			reservation, en, exit := e.run(t, "reserve", "reservation", e.reserve)
			regTestSuccess(t, en, exit)
			started := time.Now()
			out, en, exit := e.run(t, "request", "request", regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "A", lifetime})
			if lifetime < 30 {
				regTestRefusal(t, en, exit, "REGISTRATION_POLICY_REFUSED", out)
			} else if !en.OK {
				regTestRefusal(t, en, exit, "REGISTRATION_POLICY_REFUSED", out)
				// The preparation capture cannot precede started. Refusal before
				// even that earliest possible margin deadline is not justified.
				if time.Now().Before(time.Unix(started.Unix()+int64(lifetime)-30, 0)) {
					t.Fatal("valid request margin refused")
				}
			} else {
				regTestSuccess(t, en, exit)
				var state regRequestState
				if !regState(regTestRead(t, filepath.Join(filepath.Dir(out), "request-state.json")), &state, "request-state") || state.ExpiresAt-state.PreparedAt != lifetime || e.profile.Policy.ReleaseNotAfter-state.PreparedAt < 30 {
					t.Fatal("request did not retain the admitted captured window")
				}
			}
		})
	}
	for _, remaining := range []uint64{25, 28, 29, 30, 31, 60} {
		t.Run(fmt.Sprintf("release%d", remaining), func(t *testing.T) {
			e := newRegTestEnv(t, "two-stage", true)
			now := uint64(time.Now().Unix())
			e.profile.Policy.CreatedAt = now - 60
			e.profile.Policy.ReleaseNotAfter = now + remaining
			e.profileRaw = regTestJSON(t, e.profile)
			regTestWrite(t, e.profilePath, e.profileRaw)
			reservation, en, exit := e.run(t, "reserve", "reservation", e.reserve)
			regTestSuccess(t, en, exit)
			out, en, exit := e.run(t, "request", "request", regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "A", 600})
			if remaining < 30 {
				regTestRefusal(t, en, exit, "REGISTRATION_POLICY_REFUSED", out)
			} else {
				// No upper timing bound is assumed: scheduling may consume the margin.
				if en.OK {
					regTestSuccess(t, en, exit)
					var state regRequestState
					if !regState(regTestRead(t, filepath.Join(filepath.Dir(out), "request-state.json")), &state, "request-state") || e.profile.Policy.ReleaseNotAfter-state.PreparedAt < 30 {
						t.Fatal("actual captured release margin below 30 admitted")
					}
					t.Logf("actual captured release margin=%d seconds", e.profile.Policy.ReleaseNotAfter-state.PreparedAt)
				} else {
					regTestRefusal(t, en, exit, "REGISTRATION_POLICY_REFUSED", out)
					if time.Now().Before(time.Unix(int64(e.profile.Policy.ReleaseNotAfter)-30, 0)) {
						t.Fatal("valid release margin refused")
					}
				}
			}
		})
	}
}
