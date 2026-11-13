//go:build darwin && cgo && keychaintest

package facade

import (
	"fmt"
	"testing"
	"time"

	"github.com/relux-works/swarma-identity/internal/keychain"
	"github.com/relux-works/swarma-identity/internal/keysign"
)

// recordingStore logs every call of the real test-keychain store.
type recordingStore struct {
	keychain.Store
	log *[]string
}

func (r recordingStore) Secret(label, reason string, dst *[32]byte) ([]byte, error) {
	*r.log = append(*r.log, "secret:"+label)
	return r.Store.Secret(label, reason, dst)
}

func (r recordingStore) Create(label string, secret *[32]byte, public []byte) error {
	*r.log = append(*r.log, "create:"+label)
	return r.Store.Create(label, secret, public)
}

// Claim: end to end against the CI job's throwaway file keychain (test build,
// no biometry): keygen stores a published test key and prints only public
// data, keygen refuses the existing label without calling Create, sign shows
// the request and reads the key only after confirmation, its signatures
// complete PR 8's grant sign, a declined confirmation reads nothing, and no
// encoding of the secret appears in any output or on the process's
// stdout/stderr descriptors.
func TestKeychainDarwinEndToEnd(t *testing.T) {
	store, err := keychain.Default()
	if err != nil {
		t.Fatal(err)
	}
	label := fmt.Sprintf("e2e-%d", time.Now().UnixNano())
	t.Cleanup(func() { keychain.Delete(label) })
	f := preparedFlow(t)
	h := newKC(t, confirmWord)
	rec := recordingStore{store, &h.log}
	h.deps.signer = keysign.NewWithStore(rec, fixedReader(mustDecode(bip340Secrets[keyLandlord])))
	direct := captureFDs(t, func() {
		e, code := h.run("keychain", "keygen", "--label", label, "--network", "regtest")
		mustOK(t, e, code)
		if resultAs[KeychainPublic](t, e).XOnlyKey != f.draft.Draft.IssuerKey {
			t.Fatal("keygen key")
		}
		before := len(h.log)
		e, code = h.run("keychain", "keygen", "--label", label)
		mustRefuse(t, e, code, "KEY_EXISTS")
		if len(h.log) != before {
			t.Fatalf("existing label reached Create: %v", h.log[before:])
		}
		h.log = nil
		e, code = h.run("keychain", "sign", "--label", label, "--request", writeInput(t, fullRequestLabel(t, f)))
		mustOK(t, e, code)
		if len(h.log) != 5 || h.log[0] != "show" || h.log[1] != "confirm" || h.count("secret:") != 3 {
			t.Fatalf("order %v", h.log)
		}
		res := resultAs[KeychainSignResult](t, e)
		e, code = f.signCmd(GrantSignRequest{Schema: GrantSignSchema, Draft: f.draft.Draft, ConsentEvent: f.consent.ConsentEvent, LandlordSig: f.landlordSig, GrantSig: res.Signatures[1].Signature})
		mustOK(t, e, code)
		h.log = nil
		h.term.answer = "no"
		e, code = h.run("keychain", "sign", "--label", label, "--request", writeInput(t, fullRequestLabel(t, f)))
		mustRefuse(t, e, code, "CONFIRMATION_DECLINED")
		if h.count("secret:") != 0 {
			t.Fatal("declined sign read the key")
		}
	})
	assertNoSecrets(t, append(h.blobs, direct))
}

func fullRequestLabel(t *testing.T, f *flow) KeychainSignRequest { return fullRequest(t, f) }
