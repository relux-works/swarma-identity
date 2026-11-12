package facade

import (
	"context"
	"strings"
	"testing"
)

// Late advancement and equal-height reorganization must be observed after the
// name read. The zero-expired/future-height cross-product distinguishes stable
// provider failure from moving snapshots, with no result, replay or write RPC.
// These evolving fake replies do not establish consensus or atomic snapshots.
func TestNameTemporalSnapshot(t *testing.T) {
	changed := strings.Repeat("2", 64)
	for _, tc := range []struct {
		name      string
		scenario  nameReadScenario
		code      string
		exit      int
		retryable bool
	}{
		{"stable-active", nameReadScenario{1, false, 99, Tip{}}, "", 0, false},
		{"late-advance", nameReadScenario{1, false, 101, Tip{Hash: changed, Height: 101}}, "SNAPSHOT_CHANGED", 4, true},
		{"same-height-reorg", nameReadScenario{1, false, 99, Tip{Hash: changed, Height: 100}}, "SNAPSHOT_CHANGED", 4, true},
		{"zero-expired-future-stable", nameReadScenario{0, true, 101, Tip{}}, "PROVIDER_PROTOCOL", 5, false},
		{"zero-expired-future-moving", nameReadScenario{0, true, 101, Tip{Hash: changed, Height: 101}}, "SNAPSHOT_CHANGED", 4, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, trace := temporalNameFixture(t, tc.scenario)
			n, f := c.Name(context.Background(), "d/example")
			if tc.code == "" {
				if f != nil || n == nil || n.ExpiresIn != 1 || n.Expired || n.ObservedTip != (Tip{Hash: fixtureTip, Height: 100}) {
					t.Errorf("stable active boundary control failed: %#v", f)
				}
			} else if n != nil || f == nil || f.Code != tc.code || f.Exit != tc.exit || f.Retryable != tc.retryable {
				t.Errorf("temporal name verdict = %#v, want %s/exit%d/retryable%v and no result", f, tc.code, tc.exit, tc.retryable)
			}
			assertNameCallOrder(t, trace(), true)
		})
	}
}
