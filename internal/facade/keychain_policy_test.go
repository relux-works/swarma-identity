package facade

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-identity/internal/keychain/keychainfake"
	"github.com/relux-works/swarma-identity/internal/keypolicy"
)

// Claim: the omitted flag and all three explicit choices persist in the public item and JSON public record, including a file round trip.
func TestKeychainAccessPolicyKeygen(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want keypolicy.Policy
	}{
		{"default", nil, keypolicy.CurrentSet},
		{"current", []string{"--access", "biometry-current-set"}, keypolicy.CurrentSet},
		{"any", []string{"--access=biometry-any"}, keypolicy.Any},
		{"passcode", []string{"--access", "biometry-or-passcode"}, keypolicy.OrPasscode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newKC(t, confirmWord)
			args := append([]string{"keychain", "keygen", "--label", "new-grant"}, tc.args...)
			e, code := h.run(args...)
			mustOK(t, e, code)
			pub := resultAs[KeychainPublic](t, e)
			if pub.AccessPolicy != tc.want {
				t.Fatalf("record policy = %q", pub.AccessPolicy)
			}
			stored, err := h.store.Access("new-grant")
			if err != nil || stored != tc.want {
				t.Fatalf("stored = %q, %v", stored, err)
			}
			raw, err := json.Marshal(e)
			if err != nil || !strings.Contains(string(raw), `"access_policy":"`+string(tc.want)+`"`) {
				t.Fatalf("public JSON: %s, %v", raw, err)
			}
			path := filepath.Join(t.TempDir(), "grant-key-new-grant.public.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			var roundTrip Envelope
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(saved, &roundTrip); err != nil {
				t.Fatal(err)
			}
			if got := resultAs[KeychainPublic](t, roundTrip); got != pub {
				t.Fatalf("record round trip = %+v", got)
			}
		})
	}
}

// Claim: unknown and empty policies refuse by name, and malformed flags refuse, before any Keychain call or key creation.
func TestKeychainUnknownAccessPolicyNoStoreCall(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code string
	}{
		{[]string{"--access", "unknown"}, "UNKNOWN_ACCESS_POLICY"},
		{[]string{"--access="}, "UNKNOWN_ACCESS_POLICY"},
		{[]string{"--access", "Biometry-any"}, "UNKNOWN_ACCESS_POLICY"},
		{[]string{"--access", "biometry-any "}, "UNKNOWN_ACCESS_POLICY"},
		{[]string{"--access"}, "BAD_INPUT"},
		{[]string{"--access", "biometry-any", "--access", "biometry-current-set"}, "BAD_INPUT"},
	} {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			h := newKC(t, confirmWord)
			before := len(h.store.Events)
			e, code := h.run(append([]string{"keychain", "keygen", "--label", "new-grant"}, tc.args...)...)
			mustRefuse(t, e, code, tc.code)
			if code != 2 {
				t.Fatalf("invalid flag exit = %d, want 2", code)
			}
			if e.Result != nil || len(h.store.Events) != before {
				t.Fatal("invalid access reached store or returned a result")
			}
			if _, exists := h.store.SecretOf("new-grant"); exists {
				t.Fatal("invalid access created a key")
			}
		})
	}
}

// Claim: each policy appears before confirmation/secret reads, in every authentication reason, and in the sign result for all three signing paths.
func TestKeychainAccessPolicySign(t *testing.T) {
	f := preparedFlow(t)
	for _, access := range []keypolicy.Policy{keypolicy.CurrentSet, keypolicy.Any, keypolicy.OrPasscode} {
		t.Run(string(access), func(t *testing.T) {
			h := newKCWithAccess(t, confirmWord, keychainfake.New(), bip340Secrets[keyLandlord], access)
			e, code := h.sign(fullRequest(t, f))
			mustOK(t, e, code)
			res := resultAs[KeychainSignResult](t, e)
			if res.Key.AccessPolicy != access || len(res.Signatures) != 2 || res.SealSpend == nil {
				t.Fatalf("sign result: %+v", res)
			}
			if !strings.Contains(h.preKey, "Access policy      : "+string(access)+" (this-device-only)") {
				t.Fatal("policy not shown before secret read")
			}
			if len(h.store.Reasons) != 3 {
				t.Fatalf("auth reasons = %v", h.store.Reasons)
			}
			for _, reason := range h.store.Reasons {
				if !strings.Contains(reason, "[access: "+string(access)+"]") {
					t.Fatal("auth reason omitted policy")
				}
			}
			if access == keypolicy.OrPasscode && !strings.Contains(h.preKey, "device passcode/password") {
				t.Fatal("passcode fallback omitted from display")
			}
			assertNoSecrets(t, h.blobs)
		})
	}
}

// Claim: a changed public record or independently inspectable actual ACL refuses with no signature; an unknown stored policy refuses before authentication.
func TestKeychainAccessPolicyMismatch(t *testing.T) {
	f := preparedFlow(t)
	for _, which := range []string{"public-record", "actual-acl", "unknown-record"} {
		t.Run(which, func(t *testing.T) {
			h := newKC(t, confirmWord)
			want := "ACCESS_POLICY_MISMATCH"
			switch which {
			case "public-record":
				h.store.SetAccess(kcLabel, keypolicy.Any)
			case "actual-acl":
				h.store.SetActualAccess(kcLabel, keypolicy.OrPasscode)
			case "unknown-record":
				h.store.SetAccess(kcLabel, "future-policy")
				want = "UNKNOWN_ACCESS_POLICY"
			}
			e, code := h.sign(fullRequest(t, f))
			mustRefuse(t, e, code, want)
			if e.Result != nil {
				t.Fatal("mismatch returned partial signatures")
			}
			if which == "unknown-record" && h.count("secret:") != 0 {
				t.Fatal("unknown record authenticated")
			}
			assertNoSecrets(t, h.blobs)
		})
	}
}

// Claim: lack of native flag introspection is stated before approval, while authenticated metadata still gates signing; this models the public macOS API limit.
func TestKeychainAccessPolicyInspectionUnavailable(t *testing.T) {
	f := preparedFlow(t)
	h := newKC(t, confirmWord)
	h.store.HideAccessInspection = true
	e, code := h.sign(fullRequest(t, f))
	mustOK(t, e, code)
	if !strings.Contains(h.preKey, "Native ACL flags   : unavailable through public Security APIs") {
		t.Fatal("unavailable inspection was hidden")
	}
	h.store.SetAccess(kcLabel, keypolicy.Any)
	e, code = h.sign(fullRequest(t, f))
	mustRefuse(t, e, code, "ACCESS_POLICY_MISMATCH")
	if e.Result != nil {
		t.Fatal("metadata mismatch returned a signature")
	}
}

// Claim: keygen with a different policy refuses an occupied label and preserves its existing secret and recorded policy.
func TestKeychainAccessPolicyNeverUpdatesExistingItem(t *testing.T) {
	h := newKC(t, confirmWord)
	before, _ := h.store.SecretOf(kcLabel)
	e, code := h.run("keychain", "keygen", "--label", kcLabel, "--access", "biometry-or-passcode")
	mustRefuse(t, e, code, "KEY_EXISTS")
	after, _ := h.store.SecretOf(kcLabel)
	access, err := h.store.Access(kcLabel)
	if before != after || err != nil || access != keypolicy.CurrentSet {
		t.Fatal("existing key or policy changed")
	}
}

type changePolicyTerminal struct {
	Terminal
	change func()
}

func (t changePolicyTerminal) Confirm(prompt string) (bool, error) {
	ok, err := t.Terminal.Confirm(prompt)
	t.change()
	return ok, err
}

// Claim: a policy record changed after display cannot borrow that approval; signing refuses without any signature.
func TestKeychainAccessPolicyChangedAfterDisplay(t *testing.T) {
	f := preparedFlow(t)
	h := newKC(t, confirmWord)
	h.deps.terminal = func() (Terminal, error) {
		return changePolicyTerminal{h.term, func() { h.store.SetAccess(kcLabel, keypolicy.Any) }}, nil
	}
	e, code := h.sign(fullRequest(t, f))
	mustRefuse(t, e, code, "ACCESS_POLICY_MISMATCH")
	if e.Result != nil || !strings.Contains(h.preKey, "biometry-current-set") {
		t.Fatal("changed record borrowed approval")
	}
}
