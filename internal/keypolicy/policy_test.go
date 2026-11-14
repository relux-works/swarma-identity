package keypolicy

import (
	"errors"
	"testing"
)

// Claim: each named policy maps to its distinct Security SDK flag, round-trips, and the default stays current-set.
func TestSecurityFlags(t *testing.T) {
	if Default != CurrentSet {
		t.Fatal("default changed")
	}
	for _, tc := range []struct {
		policy Policy
		flags  uint64
	}{
		{CurrentSet, 8}, {Any, 2}, {OrPasscode, 1},
	} {
		t.Run(string(tc.policy), func(t *testing.T) {
			flags, err := tc.policy.SecurityFlags()
			if err != nil || flags != tc.flags {
				t.Fatalf("flags = %d, %v; want %d", flags, err, tc.flags)
			}
			got, err := FromFlags(flags)
			if err != nil || got != tc.policy {
				t.Fatalf("round trip = %q, %v", got, err)
			}
		})
	}
}

// Claim: unknown names (including empty) and unknown or combined flag values refuse without a usable mapping.
func TestUnknownPolicy(t *testing.T) {
	for _, p := range []Policy{"", "unknown", "Biometry-any", "biometry-any "} {
		if flags, err := p.SecurityFlags(); !errors.Is(err, ErrUnknown) || flags != 0 {
			t.Fatalf("%q = %d, %v", p, flags, err)
		}
	}
	for _, flags := range []uint64{0, 3, 10, 16, 255} {
		if p, err := FromFlags(flags); !errors.Is(err, ErrUnknown) || p != "" {
			t.Fatalf("%d = %q, %v", flags, p, err)
		}
	}
}
