package facade

import (
	"testing"

	"github.com/relux-works/swarma-identity/internal/keychain/keychainfake"
	"github.com/relux-works/swarma-identity/internal/keypolicy"
	"github.com/relux-works/swarma-identity/internal/keysign"
)

// newV4GateKC holds the key that signs the v4 test root under both the
// ordinary grant label and the reserved label, so only the label rule can
// refuse the same request under the reserved label.
func newV4GateKC(t *testing.T) *kcHarness {
	t.Helper()
	h := newKCWithAccess(t, confirmWord, keychainfake.New(), bip340Secrets[keyGrantee], keypolicy.CurrentSet)
	if _, err := keysign.NewWithStore(h.store, fixedReader(mustDecode(bip340Secrets[keyGrantee]))).Keygen(gateLabel, keypolicy.CurrentSet); err != nil {
		t.Fatal(err)
	}
	h.log = nil
	return h
}

func (h *kcHarness) runV4As(t *testing.T, command, label string, r KeychainV4Request) (Envelope, int) {
	t.Helper()
	return h.run("keychain", command, "--label", label, "--request", writeInput(t, r))
}

// Claim: the reserved label refuses a v4 assent with KEY_PURPOSE before any public, access, display or signing event, beside the same request under an ordinary label, which signs.
func TestKeychainSignV4ReservedLabel(t *testing.T) {
	r := v4KeyRequest(t, "grant-v-01")

	control := newV4GateKC(t)
	e, code := control.runV4As(t, "sign-v4", kcLabel, r)
	mustOK(t, e, code)
	if !control.keyRead || control.count("secret:") == 0 || control.count("show") != 1 {
		t.Fatalf("valid control did not sign: %v", control.log)
	}

	h := newV4GateKC(t)
	before := len(h.store.Events)
	e, code = h.runV4As(t, "sign-v4", gateLabel, r)
	refusedGate(t, h, e, code, "KEY_PURPOSE", 3)
	if len(h.log) != 0 || len(h.store.Events) != before {
		t.Fatalf("a refused purpose reached the store or the terminal: %v", h.log)
	}
}

// Claim: the reserved label refuses a v4 review with KEY_PURPOSE before any public, access or display event, beside the same request under an ordinary label, which reviews without signing.
func TestKeychainReviewV4ReservedLabel(t *testing.T) {
	r := v4KeyRequest(t, "grant-v-01")

	control := newV4GateKC(t)
	e, code := control.runV4As(t, "review-v4", kcLabel, r)
	mustOK(t, e, code)
	if control.keyRead || control.count("secret:") != 0 || control.count("show") != 1 {
		t.Fatalf("valid control did not review as expected: %v", control.log)
	}

	h := newV4GateKC(t)
	before := len(h.store.Events)
	e, code = h.runV4As(t, "review-v4", gateLabel, r)
	refusedGate(t, h, e, code, "KEY_PURPOSE", 3)
	if len(h.log) != 0 || len(h.store.Events) != before {
		t.Fatalf("a refused purpose reached the store or the terminal: %v", h.log)
	}
}
