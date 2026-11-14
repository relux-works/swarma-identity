//go:build darwin && cgo

package keychain

import (
	"github.com/relux-works/swarma-identity/internal/keypolicy"
	"testing"
)

// Claim: the real Security framework constructs each mapped policy with the creation helper's fixed device-only protection; no authentication or enrollment behavior is exercised.
func TestNativeAccessPolicyConstruction(t *testing.T) {
	for _, access := range []keypolicy.Policy{keypolicy.CurrentSet, keypolicy.Any, keypolicy.OrPasscode} {
		if !nativeControlValid(access) {
			t.Fatalf("cannot construct %s", access)
		}
	}
	if nativeControlValid("unknown") {
		t.Fatal("unknown policy reached native construction")
	}
}
