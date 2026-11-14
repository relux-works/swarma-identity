//go:build darwin && cgo && keychaintest

package keychain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/relux-works/swarma-identity/internal/keypolicy"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// BIP-340 vector 1: a published test key, never anyone's key.
const vectorSecret = "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef"

// Claim: against the throwaway file keychain the CI job created, Create
// stores the secret and the public key under the label, Public returns the
// public key without the secret, Secret returns exactly the 32 stored bytes,
// a second Create under the same label is KEY_EXISTS and leaves the item
// unchanged, Exists sees both absence and presence, and deleting a label
// removes both items. An absent label is KEY_NOT_FOUND. Secret returns the
// authenticated kSecAttrGeneric beside the secret. A successful Secret read
// leaves the framework's result buffer all zero before it is released
// (observed in C after the wipe); the absent read resets the observation.
// Limit: this is the file keychain's result object; the data protection
// keychain's is not reachable from CI.
func TestTestKeychainRoundTrip(t *testing.T) {
	s, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	label := fmt.Sprintf("ci-%d", time.Now().UnixNano())
	t.Cleanup(func() { Delete(label) })
	var secret [32]byte
	raw, _ := hex.DecodeString(vectorSecret)
	copy(secret[:], raw)
	public := bytes.Repeat([]byte{0x02}, 33)
	if exists, err := s.Exists(label); err != nil || exists {
		t.Fatalf("absent existence check: %v", err)
	}
	if _, err := s.Public(label); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent label: %v", err)
	}
	if err := s.Create(label, &secret, public, keypolicy.Default); err != nil {
		t.Fatal(err)
	}
	if exists, err := s.Exists(label); err != nil || !exists {
		t.Fatalf("stored existence check: %v", err)
	}
	got, err := s.Public(label)
	if err != nil || !bytes.Equal(got, public) {
		t.Fatalf("public: %x %v", got, err)
	}
	var other [32]byte
	other[0] = 1
	if err := s.Create(label, &other, public, keypolicy.Default); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate label: %v", err)
	}
	var read [32]byte
	if metadata, err := s.Secret(label, "test read", &read, keypolicy.Default); err != nil || read != secret || !bytes.Equal(metadata, public) {
		t.Fatalf("secret read: %v", err)
	}
	if !LastReadWiped() {
		t.Fatal("the Keychain result buffer was released without being wiped")
	}
	if _, err := s.Secret(label+"-absent", "test read", &read, keypolicy.Default); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent secret: %v", err)
	}
	if LastReadWiped() {
		t.Fatal("wipe observation not reset by a read with no result")
	}
	if err := Delete(label); err != nil {
		t.Fatal(err)
	}
	if exists, err := s.Exists(label); err != nil || exists {
		t.Fatalf("deletion left an item: %v", err)
	}
	if _, err := s.Public(label); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deletion left the public item: %v", err)
	}
	if _, err := s.Secret(label, "test deleted read", &read, keypolicy.Default); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deletion left the secret item: %v", err)
	}
}

// Claim: the test store refuses any keychain path that is not an absolute
// swarma-test-*.keychain-db regular file, including the login keychain.
func TestTestKeychainPathGuard(t *testing.T) {
	home, _ := os.UserHomeDir()
	for _, p := range []string{filepath.Join(home, "Library/Keychains/login.keychain-db"), "swarma-test-x.keychain-db", "", filepath.Join(t.TempDir(), "swarma-test-missing.keychain-db")} {
		t.Setenv(TestKeychainEnv, p)
		if _, err := Default(); !errors.Is(err, ErrTestPath) {
			t.Fatalf("path %q admitted", p)
		}
	}
}

// Claim: each policy survives the real file-Keychain round trip; duplicates never rotate, mismatched/unknown records refuse without secret output, and authenticated mismatch results are wiped (no biometric ACL in this build).
func TestTestKeychainAccessPolicies(t *testing.T) {
	s, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, access := range []keypolicy.Policy{keypolicy.CurrentSet, keypolicy.Any, keypolicy.OrPasscode} {
		t.Run(string(access), func(t *testing.T) {
			label := fmt.Sprintf("policy-%d", time.Now().UnixNano())
			t.Cleanup(func() {
				if err := Delete(label); err != nil {
					t.Error(err)
				}
			})
			var secret [32]byte
			raw, _ := hex.DecodeString(vectorSecret)
			copy(secret[:], raw)
			public := bytes.Repeat([]byte{0x02}, 33)
			if err := s.Create(label, &secret, public, access); err != nil {
				t.Fatal(err)
			}
			got, err := s.Access(label)
			if err != nil || got != access {
				t.Fatalf("policy = %q, %v", got, err)
			}
			var read [32]byte
			if metadata, err := s.Secret(label, "policy round trip", &read, access); err != nil || read != secret || !bytes.Equal(metadata, public) || !LastReadWiped() {
				t.Fatalf("round trip: %v", err)
			}
			other := keypolicy.Any
			if access == other {
				other = keypolicy.OrPasscode
			}
			if err := s.Create(label, &secret, public, other); !errors.Is(err, ErrExists) {
				t.Fatalf("duplicate rotated policy: %v", err)
			}
			if got, err := s.Access(label); err != nil || got != access {
				t.Fatal("duplicate changed policy")
			}
			flags, _ := other.SecurityFlags()
			if err := setTestAccess(label, byte(flags)); err != nil {
				t.Fatal(err)
			}
			read = [32]byte{}
			// Now public metadata matches the supplied choice, but authenticated metadata does not.
			if metadata, err := s.Secret(label, "policy mismatch", &read, other); !errors.Is(err, keypolicy.ErrMismatch) || read != [32]byte{} || metadata != nil || !LastReadWiped() {
				t.Fatalf("mismatch: %v", err)
			}
			if err := setTestAccess(label, 255); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Access(label); !errors.Is(err, keypolicy.ErrUnknown) {
				t.Fatalf("unknown record: %v", err)
			}
		})
	}
}

// Claim: a pre-policy two-item key is read as current-set without rewriting it, while another expected policy refuses with no secret output.
func TestTestKeychainLegacyAccessPolicy(t *testing.T) {
	s, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	label := fmt.Sprintf("legacy-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		if err := Delete(label); err != nil {
			t.Error(err)
		}
	})
	var secret [32]byte
	raw, _ := hex.DecodeString(vectorSecret)
	copy(secret[:], raw)
	public := bytes.Repeat([]byte{0x02}, 33)
	if err := s.Create(label, &secret, public, keypolicy.Default); err != nil {
		t.Fatal(err)
	}
	if err := setTestLegacy(label); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Access(label); err != nil || got != keypolicy.CurrentSet {
		t.Fatalf("legacy = %q, %v", got, err)
	}
	var read [32]byte
	if _, err := s.Secret(label, "legacy read", &read, keypolicy.CurrentSet); err != nil || read != secret {
		t.Fatalf("legacy read: %v", err)
	}
	read = [32]byte{}
	if metadata, err := s.Secret(label, "wrong legacy policy", &read, keypolicy.Any); !errors.Is(err, keypolicy.ErrMismatch) || metadata != nil || read != [32]byte{} {
		t.Fatalf("legacy mismatch: %v", err)
	}
	if got, err := s.Access(label); err != nil || got != keypolicy.CurrentSet {
		t.Fatal("legacy policy changed")
	}
}
