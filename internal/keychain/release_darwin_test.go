//go:build darwin && cgo && !keychaintest

package keychain

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// Claim: on the hosted runner, which has no biometry, the release store's
// keygen preflight refuses with BIOMETRY_UNAVAILABLE, so a release keygen
// creates nothing there; and a read-only lookup of a random label in the data
// protection keychain returns no item. The lookup status is logged as
// evidence of the entitlement behaviour of an unsigned binary.
// Limit: skipped off CI, since a developer Mac may have Touch ID.
func TestReleaseStoreOnRunner(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("hosted runner only")
	}
	s, err := Default()
	if err != nil || TestMode {
		t.Fatal("release build expected")
	}
	if err := s.Preflight(); !errors.Is(err, ErrBiometry) {
		t.Fatalf("preflight on a runner without biometry: %v", err)
	}
	_, err = s.Public(fmt.Sprintf("probe-%d", time.Now().UnixNano()))
	t.Logf("release store lookup of a random label: %v", err)
	if err == nil {
		t.Fatal("a random label resolved to an item")
	}
}
