package keysign

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/relux-works/swarma-identity/internal/keychain"
	"github.com/relux-works/swarma-identity/internal/keychain/keychainfake"
)

// BIP-340 test vectors 0..3: published secret keys and aux_rand. The expected
// signatures are read from the repository's BIP-340 verification vectors.
var vectors = []struct{ secret, aux string }{
	{"0000000000000000000000000000000000000000000000000000000000000003", "0000000000000000000000000000000000000000000000000000000000000000"},
	{"b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef", "0000000000000000000000000000000000000000000000000000000000000001"},
	{"c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9", "c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906"},
	{"0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Claim: signSchnorrAux reproduces the published BIP-340 signatures of
// vectors 0..3 byte for byte, and its self-check refuses a signature for a
// different public key. Limit: the four signing vectors BIP-340 publishes
// with secret keys.
func TestBIP340SigningVectors(t *testing.T) {
	raw, err := os.ReadFile("../facade/testdata/nostr/bip340-verification.json")
	if err != nil {
		t.Fatal(err)
	}
	var published []struct {
		Index     string `json:"index"`
		PublicKey string `json:"public_key"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &published); err != nil {
		t.Fatal(err)
	}
	for i, v := range vectors {
		p := published[i]
		priv, pub := btcec.PrivKeyFromBytes(mustHex(t, v.secret))
		if got := hex.EncodeToString(schnorr.SerializePubKey(pub)); got != strings.ToLower(p.PublicKey) {
			t.Fatalf("vector %d public key %s", i, got)
		}
		var aux [32]byte
		copy(aux[:], mustHex(t, v.aux))
		sig, err := signSchnorrAux(priv, pub, mustHex(t, strings.ToLower(p.Message)), aux)
		if err != nil || hex.EncodeToString(sig) != strings.ToLower(p.Signature) {
			t.Fatalf("vector %d signature %x %v", i, sig, err)
		}
		_, other := btcec.PrivKeyFromBytes(mustHex(t, vectors[(i+1)%4].secret))
		if _, err := signSchnorrAux(priv, other, mustHex(t, strings.ToLower(p.Message)), aux); !errors.Is(err, ErrSignature) {
			t.Fatalf("vector %d: signature for a foreign key not refused", i)
		}
	}
}

// Claim: every ECDSA signature this signer makes is strict DER and low-S and
// verifies, and LowSVerifies refuses the high-S twin of each (the same
// signature with S negated), which plain ECDSA verification would accept.
func TestECDSALowS(t *testing.T) {
	priv, pub := btcec.PrivKeyFromBytes(mustHex(t, vectors[1].secret))
	for i := 0; i < 64; i++ {
		h := sha256.Sum256([]byte{byte(i)})
		der, err := signECDSA(priv, pub, h[:])
		if err != nil || !LowSVerifies(der, h[:], pub) {
			t.Fatalf("hash %d: %v", i, err)
		}
		sig, _ := ecdsa.ParseDERSignature(der)
		r, s := sig.R(), sig.S()
		s.Negate()
		high := ecdsa.NewSignature(&r, &s)
		if !high.Verify(h[:], pub) {
			t.Fatal("high-S twin does not verify as plain ECDSA; the control is void")
		}
		if LowSVerifies(HighSDER(r, s), h[:], pub) {
			t.Fatalf("hash %d: high-S signature accepted", i)
		}
	}
}

// HighSDER encodes (r, s) as DER without the low-S canonicalisation that
// Signature.Serialize applies.
func HighSDER(r, s btcec.ModNScalar) []byte {
	enc := func(v btcec.ModNScalar) []byte {
		b := v.Bytes()
		out := bytes.TrimLeft(b[:], "\x00")
		if len(out) == 0 || out[0]&0x80 != 0 {
			out = append([]byte{0}, out...)
		}
		return append([]byte{0x02, byte(len(out))}, out...)
	}
	body := append(enc(r), enc(s)...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

type countingReader struct {
	data []byte
	n    int
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.n += len(p)
	return copy(p, r.data), nil
}

// Claim: keygen refuses a label that already exists before it draws any
// entropy or calls Create, and leaves the existing item unchanged; on a free
// label it stores exactly the drawn secret and returns only its compressed
// public key. Limit: the fake store; the darwin keychaintest suite repeats
// the refusal against a real file keychain.
func TestKeygenRefusesExistingLabel(t *testing.T) {
	store := keychainfake.New()
	first := &countingReader{data: mustHex(t, vectors[1].secret)}
	pub, err := NewWithStore(store, first).Keygen("grant-a")
	_, want := btcec.PrivKeyFromBytes(mustHex(t, vectors[1].secret))
	if err != nil || !bytes.Equal(pub, want.SerializeCompressed()) {
		t.Fatalf("positive control: %v", err)
	}
	if bytes.Contains(pub, mustHex(t, vectors[1].secret)) {
		t.Fatal("keygen returned secret bytes")
	}
	before := len(store.Events)
	second := &countingReader{data: mustHex(t, vectors[2].secret)}
	if _, err := NewWithStore(store, second).Keygen("grant-a"); !errors.Is(err, keychain.ErrExists) {
		t.Fatalf("existing label: %v, want KEY_EXISTS", err)
	}
	for _, e := range store.Events[before:] {
		if strings.HasPrefix(e, "create:") {
			t.Fatal("keygen called Create for an existing label")
		}
	}
	if second.n != 0 {
		t.Fatal("keygen drew entropy for an existing label")
	}
	if s, _ := store.SecretOf("grant-a"); hex.EncodeToString(s[:]) != vectors[1].secret {
		t.Fatal("existing item changed")
	}
	if _, err := NewWithStore(store, second).Keygen("Bad Label"); !errors.Is(err, keychain.ErrItem) {
		t.Fatal("invalid label admitted")
	}
	store.PreflightErr = keychain.ErrBiometry
	if _, err := NewWithStore(store, second).Keygen("grant-b"); !errors.Is(err, keychain.ErrBiometry) || second.n != 0 {
		t.Fatal("keygen continued without biometry")
	}
}

// Claim: a signature is refused (KEY_ITEM_INVALID) when the secret read from
// the item is not the key whose public key is stored beside it, and the
// positive control signs with one secret read per call.
func TestSignRefusesSwappedItem(t *testing.T) {
	store := keychainfake.New()
	s := NewWithStore(store, &countingReader{data: mustHex(t, vectors[1].secret)})
	if _, err := s.Keygen("grant-a"); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("digest"))
	if _, err := s.SignSchnorr("grant-a", "reason", h[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SignECDSA("grant-a", "reason", h[:]); err != nil {
		t.Fatal(err)
	}
	reads := 0
	for _, e := range store.Events {
		if e == "secret:grant-a" {
			reads++
		}
	}
	if reads != 2 {
		t.Fatalf("%d secret reads for 2 signatures", reads)
	}
	var other [32]byte
	copy(other[:], mustHex(t, vectors[2].secret))
	store.Swap = &other
	if _, err := s.SignSchnorr("grant-a", "reason", h[:]); !errors.Is(err, keychain.ErrItem) {
		t.Fatalf("swapped item: %v", err)
	}
	if _, err := s.SignECDSA("grant-a", "reason", h[:]); !errors.Is(err, keychain.ErrItem) {
		t.Fatalf("swapped item: %v", err)
	}
}
