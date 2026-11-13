package facade

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-identity/internal/keychain"
	"github.com/relux-works/swarma-identity/internal/keychain/keychainfake"
	"github.com/relux-works/swarma-identity/internal/keysign"
)

func interactionStore() *keychainfake.Store {
	s := keychainfake.New()
	s.InteractionRequired = true
	return s
}

// Claim: keygen's post-add read and sign's pre-display reads work when every
// unauthenticated protected-item read is refused. All three signatures verify
// through the CLI; the display and confirmation precede all secret reads and
// no output contains a test secret. Limit: fake ACL behaviour, not macOS auth.
func TestKeychainInteractionRequiredKeygenSign(t *testing.T) {
	f := preparedFlow(t)
	h := newKCWithStore(t, confirmWord, interactionStore(), bip340Secrets[keyLandlord])
	if h.keyRead {
		t.Fatal("keygen read the protected secret")
	}
	direct := captureFDs(t, func() {
		e, code := h.sign(fullRequest(t, f))
		mustOK(t, e, code)
		res := resultAs[KeychainSignResult](t, e)
		if len(res.Signatures) != 2 || res.SealSpend == nil || !sigValid(f.draft.Draft.IssuerKey, res.Signatures[0].Digest, res.Signatures[0].Signature) || !sigValid(f.draft.Draft.IssuerKey, res.Signatures[1].Digest, res.Signatures[1].Signature) {
			t.Fatal("positive control did not return the requested verified signatures")
		}
	})
	if h.count("secret:") != 3 || h.log[0] != "public:"+kcLabel || h.log[1] != "show" || h.log[2] != "confirm" || !strings.Contains(h.preKey, f.draft.Draft.ContractSHA256) {
		t.Fatalf("display/confirmation/secret order: %v", h.log)
	}
	assertNoSecrets(t, append(h.blobs, direct))
}

// Claim: either a protected item alone (whose no-UI read returns -25308) or a
// public item alone reserves the label: KEY_EXISTS, no entropy, no Create,
// no authentication, and no change to the existing item.
func TestKeychainInteractionRequiredExistingItem(t *testing.T) {
	for _, which := range []string{"protected-only", "public-only"} {
		t.Run(which, func(t *testing.T) {
			h := newKCWithStore(t, confirmWord, interactionStore(), bip340Secrets[keyLandlord])
			before, _ := h.store.SecretOf(kcLabel)
			if which == "protected-only" {
				h.store.SetPublic(kcLabel, nil)
			} else {
				// Use a new store containing only the independent public item.
				h.store = interactionStore()
				h.store.OnEvent = func(e string) { h.log = append(h.log, e) }
				h.store.SetPublic(kcLabel, p2pkhPub(mustDecode(bip340Secrets[keyLandlord])))
			}
			r := &entropyCount{}
			h.deps.signer = keysign.NewWithStore(h.store, r)
			e, code := h.run("keychain", "keygen", "--label", kcLabel)
			mustRefuse(t, e, code, "KEY_EXISTS")
			if r.n != 0 || h.count("secret:") != 0 || h.count("create:") != 0 {
				t.Fatal("duplicate check consumed entropy, created or authenticated")
			}
			if which == "protected-only" {
				if after, ok := h.store.SecretOf(kcLabel); !ok || before != after {
					t.Fatal("duplicate check changed the protected item")
				}
			} else if pub, err := h.store.Public(kcLabel); err != nil || !bytes.Equal(pub, p2pkhPub(mustDecode(bip340Secrets[keyLandlord]))) {
				t.Fatal("duplicate check changed the public item")
			}
			if which == "public-only" {
				if _, ok := h.store.SecretOf(kcLabel); ok {
					t.Fatal("duplicate check added a secret item")
				}
			}
		})
	}
}

type entropyCount struct{ n int }

func (r *entropyCount) Read(p []byte) (int, error) {
	r.n += len(p)
	return copy(p, mustDecode(bip340Secrets[keyRotated])), nil
}

// Claim: a protected item without its public companion refuses by name before
// display, confirmation or Touch ID, and returns no partial result.
func TestKeychainInteractionRequiredMissingPublic(t *testing.T) {
	f := preparedFlow(t)
	h := newKCWithStore(t, confirmWord, interactionStore(), bip340Secrets[keyLandlord])
	h.store.SetPublic(kcLabel, nil)
	e, code := h.sign(fullRequest(t, f))
	mustRefuse(t, e, code, "KEY_PUBLIC_NOT_FOUND")
	if e.Result != nil || h.count("secret:") != 0 || h.count("show") != 0 || h.count("confirm") != 0 {
		t.Fatalf("missing public reached approval/authentication/output: %v", h.log)
	}
}

// Claim: a substituted public item can reach the display when the request is
// bound to that substitute, but the authenticated secret then disagrees and
// KEY_ITEM_INVALID returns no signature or partial result.
func TestKeychainInteractionRequiredSwappedPublic(t *testing.T) {
	f := preparedFlow(t)
	h := newKCWithStore(t, confirmWord, interactionStore(), bip340Secrets[keyGrantee])
	h.store.SetPublic(kcLabel, p2pkhPub(mustDecode(bip340Secrets[keyLandlord])))
	e, code := h.sign(fullRequest(t, f))
	mustRefuse(t, e, code, "KEY_ITEM_INVALID")
	if e.Result != nil || h.count("secret:") != 1 || h.count("show") != 1 || h.count("confirm") != 1 {
		t.Fatalf("swapped public did not refuse after one authenticated read: %v", h.log)
	}
	assertNoSecrets(t, h.blobs)
}

// Claim: a failed second add leaves neither item under the new label and
// returns no keygen output; clearing the injected failure permits a clean retry.
func TestKeychainInteractionRequiredPublicAddRollback(t *testing.T) {
	h := newKCWithStore(t, confirmWord, interactionStore(), bip340Secrets[keyLandlord])
	h.store.PublicAddErr = keychain.ErrStore
	e, code := h.run("keychain", "keygen", "--label", "rollback")
	mustRefuse(t, e, code, "KEYCHAIN_ERROR")
	if _, ok := h.store.SecretOf("rollback"); ok || e.Result != nil {
		t.Fatal("failed public add left a secret or returned public output")
	}
	if exists, err := h.store.Exists("rollback"); err != nil || exists {
		t.Fatal("failed public add left an item")
	}
	h.store.PublicAddErr = nil
	e, code = h.run("keychain", "keygen", "--label", "rollback")
	mustOK(t, e, code)
}

// Claim: even when the secret agrees with the displayed public item, changing
// only its authenticated kSecAttrGeneric causes KEY_ITEM_INVALID after Touch ID
// and before any signature or partial result. This is the fifth negative.
func TestKeychainInteractionRequiredSwappedGeneric(t *testing.T) {
	f := preparedFlow(t)
	h := newKCWithStore(t, confirmWord, interactionStore(), bip340Secrets[keyLandlord])
	h.store.SetGeneric(kcLabel, p2pkhPub(mustDecode(bip340Secrets[keyGrantee])))
	e, code := h.sign(fullRequest(t, f))
	mustRefuse(t, e, code, "KEY_ITEM_INVALID")
	if e.Result != nil || h.count("secret:") != 1 || h.count("show") != 1 || h.count("confirm") != 1 {
		t.Fatalf("swapped metadata did not refuse after one authenticated read: %v", h.log)
	}
	assertNoSecrets(t, h.blobs)
}

// Claim: restoring 562501ff's protected-item public re-read makes the exact
// positive keygen/sign test fail with interaction-required, while that test is
// green without the plant. It changes only the fake read target, never a live
// Keychain. A compile failure or unrelated test failure is not calibration.
func TestKeychainInteractionRequiredCalibration(t *testing.T) {
	o, root := controlScratch(t, "keychain-interaction-")
	const test = "^TestKeychainInteractionRequiredKeygenSign$"
	baseline := filepath.Join(o.scratch, "baseline.test")
	o.goCommand(t, "baseline-build", "test", "-mod=readonly", "-p", "1", "-c", "-o", baseline, "./internal/facade")
	t.Cleanup(func() { os.Remove(baseline) })
	if code, _ := o.testProcess(t, baseline, "baseline", test); code != 0 {
		t.Fatal("unmodified interaction-required positive failed")
	}
	path := filepath.Join(root, "internal/keychain/keychainfake/fake.go")
	source, err := os.ReadFile(path)
	before := []byte(`pub, ok := s.publicItems[label]
	if !ok {
		return nil, keychain.ErrNotFound
	}
	return append([]byte{}, pub...), nil`)
	if err != nil || bytes.Count(source, before) != 1 {
		t.Fatal("calibration setup: expected exactly one public-read anchor")
	}
	copyPath := filepath.Join(o.scratch, "protected-public.go")
	if err := os.WriteFile(copyPath, bytes.Replace(source, before, []byte("return s.protectedPublic(label)"), 1), 0600); err != nil {
		t.Fatal(err)
	}
	overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{path: copyPath}})
	if err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(o.scratch, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0600); err != nil {
		t.Fatal(err)
	}
	mutant := filepath.Join(o.scratch, "protected-public.test")
	o.goCommand(t, "protected-public-build", "test", "-mod=readonly", "-p", "1", "-c", "-overlay", overlayPath, "-o", mutant, "./internal/facade")
	t.Cleanup(func() { os.Remove(mutant) })
	code, log := o.testProcess(t, mutant, "protected-public-negative", test)
	if code != 1 || !strings.Contains(log, "--- FAIL: TestKeychainInteractionRequiredKeygenSign") || !strings.Contains(log, "KEYCHAIN_INTERACTION_REQUIRED") || strings.Contains(log, "panic:") {
		t.Fatalf("old public-read behaviour missed its assertion: exit%d; logs: %s", code, o.scratch)
	}
	t.Log("old protected-public re-read: positive exit0; calibrated mutant exit1 at KEYCHAIN_INTERACTION_REQUIRED")
}
