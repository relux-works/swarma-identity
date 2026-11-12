//go:build darwin && cgo && keychaintest

package keychain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
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
// unchanged, and an absent label is KEY_NOT_FOUND.
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
	if _, err := s.Public(label); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent label: %v", err)
	}
	if err := s.Create(label, &secret, public); err != nil {
		t.Fatal(err)
	}
	got, err := s.Public(label)
	if err != nil || !bytes.Equal(got, public) {
		t.Fatalf("public: %x %v", got, err)
	}
	var other [32]byte
	other[0] = 1
	if err := s.Create(label, &other, public); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate label: %v", err)
	}
	var read [32]byte
	if err := s.Secret(label, "test read", &read); err != nil || read != secret {
		t.Fatalf("secret read: %v", err)
	}
	if err := s.Secret(label+"-absent", "test read", &read); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent secret: %v", err)
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
