package facade

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-identity/internal/keychain/keychainfake"
	"github.com/relux-works/swarma-identity/internal/keypolicy"
)

func v4PolicyControl(t *testing.T, network string, access keypolicy.Policy, hidden bool) (*kcHarness, KeychainV4Request, string) {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal("test key generation")
	}
	pub := hex.EncodeToString(schnorr.SerializePubKey(key.PubKey()))
	h := newKCWithAccess(t, confirmWord, keychainfake.New(), hex.EncodeToString(key.Serialize()), access)
	h.store.HideAccessInspection = hidden
	r := v4KeyRequest(t, "grant-v-01")
	raw, _ := hex.DecodeString(r.PayloadHex)
	raw = bytes.ReplaceAll(raw, []byte(v4IssuerKey), []byte(pub))
	raw = bytes.ReplaceAll(raw, []byte(pinnedGenesis("main")), []byte(pinnedGenesis(network)))
	r.PayloadHex = hex.EncodeToString(raw)
	r.LandlordValueHex = hex.EncodeToString([]byte(landlordValue(pub)))
	return h, r, pub
}

// TestV4AccessInspection proves inspected and uninspected reviews/signatures show the exact policy caveat, network and approval text before any private-key use.
func TestV4AccessInspection(t *testing.T) {
	for _, n := range []struct{ name, genesis string }{
		{"main", "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"},
		{"regtest", "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"},
	} {
		network := n.name
		for _, access := range []keypolicy.Policy{keypolicy.CurrentSet, keypolicy.Any, keypolicy.OrPasscode} {
			for _, hidden := range []bool{false, true} {
				for _, command := range []string{"review-v4", "sign-v4"} {
					t.Run(fmt.Sprintf("%s/%s/%t/%s", network, access, hidden, command), func(t *testing.T) {
						h, r, pub := v4PolicyControl(t, network, access, hidden)
						e, exit := v4KC(t, h, command, r)
						mustOK(t, e, exit)
						caveat := ""
						if hidden {
							caveat = "Native ACL flags   : unavailable through public Security APIs; authenticated policy metadata is checked before signing.\n"
						}
						header := "\n=== SWARMA V4 DOCUMENT REVIEW ===\nKeychain label: " + kcLabel + "\nSigning key x-only: " + pub + "\nAccess policy: " + string(access) + " (this-device-only)\n" + caveat + "Network: " + network + " (genesis " + n.genesis + ")\n"
						shown := h.term.shown.String()
						if !strings.HasPrefix(shown, header) || strings.Count(shown, "Native ACL flags") != map[bool]int{false: 0, true: 1}[hidden] {
							t.Fatal("access inspection disclosure or network text differs")
						}
						if command == "sign-v4" {
							if !h.keyRead || h.preKey != shown || !strings.HasSuffix(shown, "Type SIGN to sign exactly the above, anything else declines: ") {
								t.Fatal("approval text or order differs")
							}
							if len(h.store.Reasons) != 1 || h.store.Reasons[0] != "sign root contract assent [access: "+string(access)+"]" {
								t.Fatal("authentication prompt text differs")
							}
						} else if h.keyRead || !strings.HasSuffix(shown, "Review only: no confirmation and no signature will be requested.\n") {
							t.Fatal("review text or key-use differs")
						}
					})
				}
			}
		}
	}
}

// TestV4AccessPolicyRefusals proves metadata/ACL mismatches and unknown policies release no signature, including hidden inspection and changes after approval, beside valid signing controls.
func TestV4AccessPolicyRefusals(t *testing.T) {
	for _, hidden := range []bool{false, true} {
		for _, which := range []string{"record", "unknown", "after-display", "acl"} {
			if hidden && which == "acl" {
				continue
			}
			t.Run(fmt.Sprintf("%t/%s", hidden, which), func(t *testing.T) {
				good, r, _ := v4PolicyControl(t, "main", keypolicy.CurrentSet, hidden)
				e, exit := v4KC(t, good, "sign-v4", r)
				mustOK(t, e, exit)
				h, r, _ := v4PolicyControl(t, "main", keypolicy.CurrentSet, hidden)
				want := "ACCESS_POLICY_MISMATCH"
				switch which {
				case "record":
					h.store.SetAccess(kcLabel, keypolicy.Any)
				case "unknown":
					h.store.SetAccess(kcLabel, "future-policy")
					want = "UNKNOWN_ACCESS_POLICY"
				case "acl":
					h.store.SetActualAccess(kcLabel, keypolicy.OrPasscode)
				case "after-display":
					h.deps.terminal = func() (Terminal, error) {
						return changePolicyTerminal{h.term, func() { h.store.SetAccess(kcLabel, keypolicy.Any) }}, nil
					}
				}
				e, exit = v4KC(t, h, "sign-v4", r)
				mustRefuse(t, e, exit, want)
				if e.Result != nil {
					t.Fatal("policy refusal released a signature")
				}
				if which == "unknown" && (h.keyRead || h.term.shown.Len() != 0) {
					t.Fatal("unknown policy reached display or authentication")
				}
			})
		}
	}
}
