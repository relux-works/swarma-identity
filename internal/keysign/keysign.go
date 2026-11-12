// Package keysign is the only product code that handles the grant secret. It
// generates the secp256k1 key from the OS CSPRNG into a Keychain item, and
// signs one digest per call after reading the secret under one fresh store
// authentication. Every signature is checked against the stored public key
// before it is returned, and every secret copy is zeroed. Only the
// swarma-keychain binary links this package; swarma-identity never does.
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
// the 33-byte compressed public key.
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
	var secret [32]byte
	defer clear(secret[:])
	var scalar btcec.ModNScalar
	defer scalar.Zero()
	for attempt := 0; ; attempt++ {
		if attempt == 8 {
			return nil, keychain.ErrStore
		}
		if _, err := io.ReadFull(s.entropy, secret[:]); err != nil {
			return nil, keychain.ErrStore
		}
		if overflow := scalar.SetByteSlice(secret[:]); !overflow && !scalar.IsZero() {
			break
		}
	}
	priv := btcec.PrivKeyFromScalar(&scalar)
	compressed := priv.PubKey().SerializeCompressed()
	priv.Zero()
	if err := store.Create(label, &secret, compressed); err != nil {
		return nil, err
	}
	clear(secret[:])
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

// withKey reads the secret once under a fresh authentication, refuses a
// secret that is not the stored key, runs one signing step and zeroes the
// secret and the scalar.
func (s *Signer) withKey(label, reason string, step func(*btcec.PrivateKey, *btcec.PublicKey) ([]byte, error)) ([]byte, error) {
	stored, err := s.Public(label)
	if err != nil {
		return nil, err
	}
	pub, _ := btcec.ParsePubKey(stored)
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	var secret [32]byte
	defer clear(secret[:])
	if err := store.Secret(label, reason, &secret); err != nil {
		return nil, err
	}
	priv, derived := btcec.PrivKeyFromBytes(secret[:])
	clear(secret[:])
	defer priv.Zero()
	if !derived.IsEqual(pub) {
		return nil, keychain.ErrItem
	}
	return step(priv, pub)
}

// SignSchnorr returns a 64-byte BIP-340 signature over a 32-byte digest, with
// fresh auxiliary randomness, verified against the stored key.
func (s *Signer) SignSchnorr(label, reason string, digest []byte) ([]byte, error) {
	if len(digest) != 32 || reason == "" {
		return nil, keychain.ErrItem
	}
	return s.withKey(label, reason, func(priv *btcec.PrivateKey, pub *btcec.PublicKey) ([]byte, error) {
		var aux [32]byte
		if _, err := io.ReadFull(s.entropy, aux[:]); err != nil {
			return nil, keychain.ErrStore
		}
		return signSchnorrAux(priv, pub, digest, aux)
	})
}

func signSchnorrAux(priv *btcec.PrivateKey, pub *btcec.PublicKey, digest []byte, aux [32]byte) ([]byte, error) {
	sig, err := schnorr.Sign(priv, digest, schnorr.CustomNonce(aux))
	if err != nil {
		return nil, ErrSignature
	}
	again, err := schnorr.ParseSignature(sig.Serialize())
	xonly, perr := schnorr.ParsePubKey(schnorr.SerializePubKey(pub))
	if err != nil || perr != nil || !again.Verify(digest, xonly) {
		return nil, ErrSignature
	}
	return sig.Serialize(), nil
}

// SignECDSA returns a strict-DER, low-S ECDSA signature over a 32-byte
// sighash (RFC 6979 nonce), verified against the stored key. The caller adds
// the sighash type byte.
func (s *Signer) SignECDSA(label, reason string, hash []byte) ([]byte, error) {
	if len(hash) != 32 || reason == "" {
		return nil, keychain.ErrItem
	}
	return s.withKey(label, reason, func(priv *btcec.PrivateKey, pub *btcec.PublicKey) ([]byte, error) {
		return signECDSA(priv, pub, hash)
	})
}

func signECDSA(priv *btcec.PrivateKey, pub *btcec.PublicKey, hash []byte) ([]byte, error) {
	der := ecdsa.Sign(priv, hash).Serialize()
	if !LowSVerifies(der, hash, pub) {
		return nil, ErrSignature
	}
	return der, nil
}

// LowSVerifies parses strict DER, requires S <= n/2 and verifies.
func LowSVerifies(der, hash []byte, pub *btcec.PublicKey) bool {
	sig, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		return false
	}
	s := sig.S()
	return !s.IsOverHalfOrder() && sig.Verify(hash, pub)
}
