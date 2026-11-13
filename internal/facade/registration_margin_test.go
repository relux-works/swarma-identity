package facade

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

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

// Actual-clock CLI requests with 1/28/29-second lifetimes or <30 seconds
// until policy release refuse POLICY before creating output. Valid lifetime
// neighbors emit state using the same captured clock as both margin checks.
func TestRegistrationFreshDispatchWindow(t *testing.T) {
	for _, lifetime := range []uint64{1, 28, 29, 30, 31, 600} {
		t.Run(fmt.Sprintf("lifetime%d", lifetime), func(t *testing.T) {
			e := newRegTestEnv(t, "two-stage", true)
			reservation, en, exit := e.run(t, "reserve", "reservation", e.reserve)
			regTestSuccess(t, en, exit)
			out, en, exit := e.run(t, "request", "request", regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "A", lifetime})
			if lifetime < 30 {
				regTestRefusal(t, en, exit, "REGISTRATION_POLICY_REFUSED", out)
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
					if uint64(time.Now().Unix()) <= e.profile.Policy.ReleaseNotAfter-30 {
						t.Fatal("valid release margin refused")
					}
				}
			}
		})
	}
}
