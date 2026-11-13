// Package keysign is the only product code that handles the grant secret. It
// generates the secp256k1 key from the OS CSPRNG into a Keychain item, and
// signs one digest per call after reading the secret under one fresh store
// authentication. Signing is implemented here (BIP-340 and RFC 6979 ECDSA
// over btcec's scalar and point primitives) rather than through the
// library's signers, because those keep copies of the key and nonce in
// buffers they never clear. Every secret-bearing value this package names —
// including its SHA-256 working state and the verifier's copy of an
// unverified S — lives in one scratch value that is wiped on every return
// path; docs/KEYCHAIN.md "Residual memory" names what the curve library, the
// compiler and the Go runtime still keep outside it. Every signature is verified
// with the library against the stored public key before it is returned.
// Only the swarma-keychain binary links this package; swarma-identity never
// does.
package keysign

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/relux-works/swarma-identity/internal/keychain"
)

// ErrSignature means a produced signature did not verify against the stored
// key; nothing is returned.
var ErrSignature = errors.New("SIGNATURE_VERIFY")

type Signer struct {
	store   func() (keychain.Store, error)
	entropy io.Reader
}

// New uses the build's Keychain store and the OS CSPRNG.
func New() *Signer { return &Signer{keychain.Default, rand.Reader} }

// NewWithStore is for tests: an explicit store and entropy source.
func NewWithStore(store keychain.Store, entropy io.Reader) *Signer {
	return &Signer{func() (keychain.Store, error) { return store, nil }, entropy}
}

// Keygen creates the key under a label that must not exist and returns only
// the 33-byte compressed public key. The secret is drawn into a scratch and
// wiped on every return path.
func (s *Signer) Keygen(label string) ([]byte, error) {
	if !keychain.ValidLabel(label) {
		return nil, keychain.ErrItem
	}
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	if err := store.Preflight(); err != nil {
		return nil, err
	}
	switch _, err := store.Public(label); {
	case err == nil:
		return nil, keychain.ErrExists
	case !errors.Is(err, keychain.ErrNotFound):
		return nil, err
	}
	sc := newScratch()
	defer sc.wipe()
	for attempt := 0; ; attempt++ {
		if attempt == 8 {
			return nil, keychain.ErrStore
		}
		if _, err := io.ReadFull(s.entropy, sc.secret[:]); err != nil {
			return nil, keychain.ErrStore
		}
		if sc.loadKey() {
			break
		}
	}
	compressed := sc.public()
	if err := store.Create(label, &sc.secret, compressed); err != nil {
		return nil, err
	}
	sc.wipe()
	stored, err := store.Public(label)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(stored, compressed) {
		return nil, keychain.ErrItem
	}
	return compressed, nil
}

// Public returns the stored compressed public key without authentication.
func (s *Signer) Public(label string) ([]byte, error) {
	if !keychain.ValidLabel(label) {
		return nil, keychain.ErrItem
	}
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	pub, err := store.Public(label)
	if err != nil {
		return nil, err
	}
	if _, err := btcec.ParsePubKey(pub); err != nil || len(pub) != 33 {
		return nil, keychain.ErrItem
	}
	return pub, nil
}

// withKey reads the secret once under a fresh authentication into a new
// scratch, refuses a secret that is not the stored key, runs one signing
// step, and wipes the scratch on every return path.
func (s *Signer) withKey(label, reason string, step func(*scratch, *btcec.PublicKey) ([]byte, error)) ([]byte, error) {
	stored, err := s.Public(label)
	if err != nil {
		return nil, err
	}
	pub, _ := btcec.ParsePubKey(stored)
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	sc := newScratch()
	defer sc.wipe()
	if err := store.Secret(label, reason, &sc.secret); err != nil {
		return nil, err
	}
	ok := sc.loadKey()
	clear(sc.secret[:])
	if !ok || !bytes.Equal(sc.public(), stored) {
		return nil, keychain.ErrItem
	}
	return step(sc, pub)
}

// SignSchnorr returns a 64-byte BIP-340 signature over a 32-byte digest, with
// fresh auxiliary randomness from the entropy source (crypto/rand in
// production), verified with the library against the stored key.
func (s *Signer) SignSchnorr(label, reason string, digest []byte) ([]byte, error) {
	if len(digest) != 32 || reason == "" {
		return nil, keychain.ErrItem
	}
	return s.withKey(label, reason, func(sc *scratch, pub *btcec.PublicKey) ([]byte, error) {
		if _, err := io.ReadFull(s.entropy, sc.aux[:]); err != nil {
			return nil, keychain.ErrStore
		}
		return signSchnorr(sc, pub, digest)
	})
}

// signSchnorr signs with the key loaded in sc and returns a copy of the
// signature only if the library's BIP-340 verification accepts it for pub. A
// refused signature exists only in sc.out, which the caller's wipe clears.
func signSchnorr(sc *scratch, pub *btcec.PublicKey, digest []byte) ([]byte, error) {
	if err := sc.schnorr(digest); err != nil || !SchnorrVerifies(sc.out[:64], digest, pub) {
		return nil, ErrSignature
	}
	return bytes.Clone(sc.out[:64]), nil
}

// SchnorrVerifies is the library's BIP-340 verification of a 64-byte
// signature over a 32-byte digest for the x-only form of pub.
func SchnorrVerifies(sig, digest []byte, pub *btcec.PublicKey) bool {
	parsed, err := schnorr.ParseSignature(sig)
	xonly, perr := schnorr.ParsePubKey(schnorr.SerializePubKey(pub))
	return err == nil && perr == nil && len(digest) == 32 && parsed.Verify(digest, xonly)
}

// SignECDSA returns a strict-DER, low-S ECDSA signature over a 32-byte
// sighash (RFC 6979 nonce), verified with the library against the stored
// key. The caller adds the sighash type byte.
func (s *Signer) SignECDSA(label, reason string, hash []byte) ([]byte, error) {
	if len(hash) != 32 || reason == "" {
		return nil, keychain.ErrItem
	}
	return s.withKey(label, reason, func(sc *scratch, pub *btcec.PublicKey) ([]byte, error) {
		return signECDSA(sc, pub, hash)
	})
}

// signECDSA signs with the key loaded in sc and returns a copy of the DER
// signature only if it is low-S and the library's verification accepts it
// for pub. A refused signature exists in this package only in sc.out, sc.s
// and the verifier's copy of S, sc.vs; the caller's wipe clears all three.
func signECDSA(sc *scratch, pub *btcec.PublicKey, hash []byte) ([]byte, error) {
	n := sc.ecdsaSign((*[32]byte)(hash))
	if !sc.lowSVerifies(sc.out[:n], hash, pub) {
		return nil, ErrSignature
	}
	return bytes.Clone(sc.out[:n]), nil
}

// lowSVerifies parses der as strict DER, requires S <= n/2 and verifies it
// with the library. The S it inspects is copied into sc.vs, not into a local,
// so the caller's wipe of sc clears it on every path, refusal included. The
// library's parsed signature is its own copy (docs/KEYCHAIN.md "Residual
// memory").
func (sc *scratch) lowSVerifies(der, hash []byte, pub *btcec.PublicKey) bool {
	sig, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		return false
	}
	sc.vs = sig.S()
	return !sc.vs.IsOverHalfOrder() && sig.Verify(hash, pub)
}
