package facade

import (
	"context"
	"strings"
	"testing"
)

// Exactly +1 is active; zero and negative counters are expired. Contradictory
// expired/counter pairs must be provider refusals before the post-read tip RPC,
// even when name_show advances the tip. Valid expired records keep exit3.
func TestNameExpiryBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		expires   int64
		expired   bool
		moving    bool
		code      string
		exit      int
		postcheck bool
	}{
		{"active-one", 1, false, false, "", 0, true},
		{"expired-zero", 0, true, false, "NAME_EXPIRED", 3, true},
		{"expired-negative", -1, true, false, "NAME_EXPIRED", 3, true},
		{"inconsistent-true-one", 1, true, false, "PROVIDER_PROTOCOL", 5, false},
		{"inconsistent-true-many", 100, true, false, "PROVIDER_PROTOCOL", 5, false},
		{"inconsistent-false-zero", 0, false, false, "PROVIDER_PROTOCOL", 5, false},
		{"inconsistent-false-negative", -1, false, false, "PROVIDER_PROTOCOL", 5, false},
		{"moving-inconsistent-true-one", 1, true, true, "PROVIDER_PROTOCOL", 5, false},
		{"moving-inconsistent-false-zero", 0, false, true, "PROVIDER_PROTOCOL", 5, false},
		{"moving-inconsistent-false-negative", -1, false, true, "PROVIDER_PROTOCOL", 5, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scenario := nameReadScenario{expiresIn: tc.expires, expired: tc.expired, nameHeight: 99}
			if tc.moving {
				scenario.nextTip = Tip{Hash: strings.Repeat("2", 64), Height: 101}
			}
			c, trace := temporalNameFixture(t, scenario)
			n, f := c.Name(context.Background(), "d/example")
			if tc.code == "" {
				if f != nil || n == nil || n.ExpiresIn != 1 || n.Expired {
					t.Errorf("active +1 control failed: %#v", f)
				}
			} else if n != nil || f == nil || f.Code != tc.code || f.Exit != tc.exit || f.Retryable {
				t.Errorf("expiry boundary verdict = %#v, want %s/exit%d/nonretryable and no result", f, tc.code, tc.exit)
			}
			assertNameCallOrder(t, trace(), tc.postcheck)
		})
	}
}
