package keysign

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/relux-works/swarma-identity/internal/keychain"
	"github.com/relux-works/swarma-identity/internal/keychain/keychainfake"
)

// The BIP-340 signing vectors: every published vector that carries a secret
// key (0..3 and 15..18), with its aux_rand. Public keys, messages and
// expected signatures are read from the repository's copy of the published
// test-vectors.csv (all 19 vectors).
var vectors = map[int]struct{ secret, aux string }{
	0:  {"0000000000000000000000000000000000000000000000000000000000000003", "0000000000000000000000000000000000000000000000000000000000000000"},
	1:  {"b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef", "0000000000000000000000000000000000000000000000000000000000000001"},
	2:  {"c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9", "c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906"},
	3:  {"0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
	15: {"0340034003400340034003400340034003400340034003400340034003400340", "0000000000000000000000000000000000000000000000000000000000000000"},
	16: {"0340034003400340034003400340034003400340034003400340034003400340", "0000000000000000000000000000000000000000000000000000000000000000"},
	17: {"0340034003400340034003400340034003400340034003400340034003400340", "0000000000000000000000000000000000000000000000000000000000000000"},
	18: {"0340034003400340034003400340034003400340034003400340034003400340", "0000000000000000000000000000000000000000000000000000000000000000"},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// loaded is a scratch holding secret as the loaded key; the caller wipes it.
func loaded(t *testing.T, secret []byte) *scratch {
	t.Helper()
	sc := newScratch()
	copy(sc.secret[:], secret)
	if !sc.loadKey() {
		t.Fatalf("secret %x is not a key", secret)
	}
	return sc
}

type published struct {
	Index     string `json:"index"`
	PublicKey string `json:"public_key"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

func publishedVectors(t *testing.T) []published {
	raw, err := os.ReadFile("../facade/testdata/nostr/bip340-verification.json")
	if err != nil {
		t.Fatal(err)
	}
	var out []published
	if err := json.Unmarshal(raw, &out); err != nil || len(out) != 19 {
		t.Fatalf("published vectors: %d %v", len(out), err)
	}
	return out
}

// Claim: the package's BIP-340 signer reproduces every published BIP-340
// signing vector (0..3 and 15..18) byte for byte from its secret key and
// aux_rand, including the empty, 1-, 17- and 100-byte messages; for the
// 32-byte messages the production path (signSchnorr) returns it only after
// the library's verification, and that guard refuses the same signature for
// a different public key.
func TestBIP340SigningVectors(t *testing.T) {
	all := publishedVectors(t)
	for _, i := range []int{0, 1, 2, 3, 15, 16, 17, 18} {
		v, p := vectors[i], all[i]
		msg := mustHex(t, strings.ToLower(p.Message))
		sc := loaded(t, mustHex(t, v.secret))
		copy(sc.aux[:], mustHex(t, v.aux))
		if got := hex.EncodeToString(sc.public()[1:]); got != strings.ToLower(p.PublicKey) {
			t.Fatalf("vector %d public key %s", i, got)
		}
		pub, _ := btcec.ParsePubKey(sc.public())
		var sig []byte
		var err error
		if len(msg) == 32 {
			sig, err = signSchnorr(sc, pub, msg)
		} else {
			err = sc.schnorr(msg)
			sig = bytes.Clone(sc.out[:64])
		}
		sc.wipe()
		if err != nil || hex.EncodeToString(sig) != strings.ToLower(p.Signature) {
			t.Fatalf("vector %d signature %x %v", i, sig, err)
		}
		if len(msg) != 32 {
			continue
		}
		_, other := btcec.PrivKeyFromBytes(mustHex(t, vectors[(i+1)%4].secret))
		sc = loaded(t, mustHex(t, v.secret))
		copy(sc.aux[:], mustHex(t, v.aux))
		if got, err := signSchnorr(sc, other, msg); got != nil || !errors.Is(err, ErrSignature) {
			t.Fatalf("vector %d: signature for a foreign key not refused", i)
		}
		if hex.EncodeToString(sc.out[:64]) != strings.ToLower(p.Signature) {
			t.Fatalf("vector %d: the refused signature is not where the wipe reaches", i)
		}
		sc.wipe()
		if sc.out != [72]byte{} {
			t.Fatalf("vector %d: refused signature survives the wipe", i)
		}
	}
}

// The RFC 6979 / low-S vectors btcec v2.3.5 tests against (Trezor and
// CoreBitcoin): key, message (hashed with SHA-256), first nonce, DER.
var rfc6979Vectors = []struct{ key, msg, nonce, sig string }{
	{"cca9fbcc1b41e5a95d369eaa6ddcff73b61a4efaa279cfc6567e8daa39cbaf50", "sample", "2df40ca70e639d89528a6b670d9d48d9165fdc0febc0974056bdce192b8e16a3", "3045022100af340daf02cc15c8d5d08d7735dfe6b98a474ed373bdb5fbecf7571be52b384202205009fb27f37034a9b24b707b7c6b79ca23ddef9e25f7282e8a797efe53a8f124"},
	{"0000000000000000000000000000000000000000000000000000000000000001", "Satoshi Nakamoto", "8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15", "3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d802202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"},
	{"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", "Satoshi Nakamoto", "33a19b60e25fb6f4435af53a3d42d493644827367e6453928554f43e49aa6f90", "3045022100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d002206b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5"},
	{"f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181", "Alan Turing", "525a82b70e67874398067543fd84c83d30c175fdc45fdeee082fe13b1d7cfdf1", "304402207063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c022058dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea"},
	{"0000000000000000000000000000000000000000000000000000000000000001", "All those moments will be lost in time, like tears in rain. Time to die...", "38aa22d72376b4dbc472e06c3ba403ee0a394da63fc58d88686c611aba98d6b3", "30450221008600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b0220547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21"},
	{"e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2", "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!", "1f4b84c23a86a221d233f2521be018d9318639d5b8bbd6374a8a59232d16ad3d", "3045022100b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b0220279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6"},
}

// Claim: the package's RFC 6979 DRBG yields each vector's published first
// nonce, and its ECDSA signer yields each published low-S DER signature
// (vector 2 is the case where the raw S is above n/2), through the
// production path that returns it only after library verification; the
// same path refuses it for a different public key, returns no bytes, and
// leaves the refused DER, s and the verifier's copy of S (vs) only in the
// scratch, which the wipe clears.
func TestRFC6979Vectors(t *testing.T) {
	for i, v := range rfc6979Vectors {
		hash := sha256.Sum256([]byte(v.msg))
		sc := loaded(t, mustHex(t, v.key))
		sc.nonceRFC6979(&hash)
		nonce := sc.k.Bytes()
		sc.wipe()
		if hex.EncodeToString(nonce[:]) != v.nonce {
			t.Fatalf("vector %d nonce %x", i, nonce)
		}
		sc = loaded(t, mustHex(t, v.key))
		pub, _ := btcec.ParsePubKey(sc.public())
		der, err := signECDSA(sc, pub, hash[:])
		sc.wipe()
		if err != nil || hex.EncodeToString(der) != v.sig {
			t.Fatalf("vector %d signature %x %v", i, der, err)
		}
		_, other := btcec.PrivKeyFromBytes(mustHex(t, vectors[1].secret))
		sc = loaded(t, mustHex(t, v.key))
		if got, err := signECDSA(sc, other, hash[:]); got != nil || !errors.Is(err, ErrSignature) {
			t.Fatalf("vector %d: signature for a foreign key not refused", i)
		}
		if hex.EncodeToString(sc.out[:len(v.sig)/2]) != v.sig || sc.s.IsZero() || !sc.vs.Equals(&sc.s) {
			t.Fatalf("vector %d: the refused signature is not where the wipe reaches", i)
		}
		sc.wipe()
		if sc.out != [72]byte{} || sc.s != (btcec.ModNScalar{}) || sc.vs != (btcec.ModNScalar{}) {
			t.Fatalf("vector %d: refused signature survives the wipe", i)
		}
	}
}

// Claim: putDER is byte-for-byte the library's strict DER (Signature.
// Serialize) for (r, s) values chosen at every minimal-encoding boundary:
// the high bit set (a zero byte is prepended), the high bit clear, one to
// thirty-one leading zero bytes followed by a byte with the high bit set or
// clear, the value 1 and n/2; plus 64 random low-S pairs. Each case also
// checks the library parses the result strictly. Limit: s is always at most
// n/2 here, as ecdsaSign guarantees before it calls putDER.
func TestDERMatchesLibrary(t *testing.T) {
	var vals [][32]byte
	for _, top := range []byte{0x01, 0x7f, 0x80, 0xff} {
		for lead := 0; lead < 32; lead++ {
			var b [32]byte
			b[lead] = top
			for j := lead + 1; j < 32; j++ {
				b[j] = byte(j * 37)
			}
			vals = append(vals, b)
		}
	}
	var one [32]byte
	one[31] = 1
	halfOrder := mustHex(t, "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0")
	vals = append(vals, one, [32]byte(halfOrder))
	for i := 0; i < 64; i++ {
		var b [32]byte
		rand.Read(b[:])
		vals = append(vals, b)
	}
	for i, rb := range vals {
		sb := vals[(i*7+3)%len(vals)]
		var r, s btcec.ModNScalar
		r.SetBytes(&rb)
		s.SetBytes(&sb)
		if s.IsOverHalfOrder() {
			s.Negate()
		}
		if r.IsZero() || s.IsZero() {
			continue
		}
		sc := newScratch()
		sc.s = s
		got := bytes.Clone(sc.out[:sc.putDER(&r)])
		sc.wipe()
		want := ecdsa.NewSignature(&r, &s).Serialize()
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d: %x != %x", i, got, want)
		}
		if _, err := ecdsa.ParseDERSignature(got); err != nil {
			t.Fatalf("case %d: not strict DER: %v", i, err)
		}
	}
}

// Claim: on 128 random keys, digests and aux values the package's signers
// produce exactly the library's signatures (schnorr.Sign with CustomNonce,
// ecdsa.Sign), so the reimplementation is the same deterministic function as
// the reviewed library on these inputs. Limit: random sampling; the
// published vectors above pin the edge cases.
func TestSignersMatchLibrary(t *testing.T) {
	for i := 0; i < 128; i++ {
		var secret, digest, aux [32]byte
		rand.Read(secret[:])
		rand.Read(digest[:])
		rand.Read(aux[:])
		priv, pub := btcec.PrivKeyFromBytes(secret[:])
		want, err := schnorr.Sign(priv, digest[:], schnorr.CustomNonce(aux))
		if err != nil {
			t.Fatal(err)
		}
		sc := loaded(t, secret[:])
		sc.aux = aux
		got, err := signSchnorr(sc, pub, digest[:])
		sc.wipe()
		if err != nil || !bytes.Equal(got, want.Serialize()) {
			t.Fatalf("schnorr %d: %x != %x (%v)", i, got, want.Serialize(), err)
		}
		sc = loaded(t, secret[:])
		der, err := signECDSA(sc, pub, digest[:])
		sc.wipe()
		if err != nil || !bytes.Equal(der, ecdsa.Sign(priv, digest[:]).Serialize()) {
			t.Fatalf("ecdsa %d: %x (%v)", i, der, err)
		}
	}
}

// Claim: the wipeable SHA-256 equals crypto/sha256 for every length 0..300
// (all padding boundaries) and the FIPS "abc" vector, and the wipeable
// HMAC-SHA256 equals crypto/hmac for 32-byte keys.
func TestSHA256MatchesStdlib(t *testing.T) {
	var d hashState
	var out [32]byte
	d.reset()
	d.write([]byte("abc"))
	d.sum(&out)
	if hex.EncodeToString(out[:]) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("abc: %x", out)
	}
	for n := 0; n <= 300; n++ {
		msg := make([]byte, n)
		rand.Read(msg)
		d.reset()
		d.write(msg[:n/3])
		d.write(msg[n/3:])
		d.sum(&out)
		if want := sha256.Sum256(msg); out != want {
			t.Fatalf("length %d", n)
		}
		var key, mac [32]byte
		rand.Read(key[:])
		var m hmacState
		m.start(&key)
		m.inner.write(msg)
		m.finish(&mac)
		ref := hmac.New(sha256.New, key[:])
		ref.Write(msg)
		if !bytes.Equal(mac[:], ref.Sum(nil)) {
			t.Fatalf("hmac length %d", n)
		}
	}
}

// Claim: mulG equals the library's ScalarBaseMultNonConst for 1, n-1 and 64
// random scalars, and invert(v)*v = 1 and equals the library's inverse for
// 64 random scalars.
func TestPointAndInverseMatchLibrary(t *testing.T) {
	var one, nMinusOne btcec.ModNScalar
	one.SetInt(1)
	nMinusOne.SetInt(1).Negate()
	scalars := []btcec.ModNScalar{one, nMinusOne}
	for i := 0; i < 64; i++ {
		var b [32]byte
		rand.Read(b[:])
		var v btcec.ModNScalar
		v.SetBytes(&b)
		scalars = append(scalars, v)
	}
	for i := range scalars {
		v := &scalars[i]
		var sc scratch
		var got, want btcec.JacobianPoint
		sc.mulG(v, &got)
		btcec.ScalarBaseMultNonConst(v, &want)
		got.ToAffine()
		want.ToAffine()
		if !got.X.Equals(&want.X) || !got.Y.Equals(&want.Y) {
			t.Fatalf("scalar %d: mulG differs", i)
		}
		var inv, check, lib btcec.ModNScalar
		invert(&inv, v)
		check.Mul2(&inv, v)
		lib.InverseValNonConst(v)
		if !check.Equals(&one) || !inv.Equals(&lib) {
			t.Fatalf("scalar %d: inverse differs", i)
		}
	}
}

// Claim: every ECDSA signature this signer makes is strict DER and low-S and
// verifies, and lowSVerifies refuses the high-S twin of each (the same
// signature with S negated), which plain ECDSA verification would accept.
func TestECDSALowS(t *testing.T) {
	_, pub := btcec.PrivKeyFromBytes(mustHex(t, vectors[1].secret))
	verifier := newScratch()
	defer verifier.wipe()
	for i := 0; i < 64; i++ {
		h := sha256.Sum256([]byte{byte(i)})
		sc := loaded(t, mustHex(t, vectors[1].secret))
		der, err := signECDSA(sc, pub, h[:])
		sc.wipe()
		if err != nil || !verifier.lowSVerifies(der, h[:], pub) {
			t.Fatalf("hash %d: %v", i, err)
		}
		sig, _ := ecdsa.ParseDERSignature(der)
		r, s := sig.R(), sig.S()
		s.Negate()
		high := ecdsa.NewSignature(&r, &s)
		if !high.Verify(h[:], pub) {
			t.Fatal("high-S twin does not verify as plain ECDSA; the control is void")
		}
		if verifier.lowSVerifies(HighSDER(r, s), h[:], pub) {
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

// nonzeroFields names the scratch fields that are not all zero.
func nonzeroFields(sc *scratch) []string {
	v := reflect.ValueOf(sc).Elem()
	var out []string
	for i := 0; i < v.NumField(); i++ {
		if !v.Field(i).IsZero() {
			out = append(out, v.Type().Field(i).Name)
		}
	}
	return out
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// Claim: after Keygen, SignSchnorr and SignECDSA return — on success and on
// each refusal path (keygen entropy that never yields a scalar or fails,
// store authentication error, swapped item, a stored secret that is not a
// scalar, aux entropy failure) — every field of every
// scratch the operation allocated is zero, observed through scratchHook
// after the public call returned. The positive control: just before the
// wipe, the success paths had populated every secret-bearing field (union
// over the three operations), so the zero check is not vacuous. Limit: kb
// and acc are cleared inside mulG itself; their in-use state is not
// observed here. This is the package's own memory; library stack frames and
// registers are outside it (docs/KEYCHAIN.md "Residual memory").
func TestScratchClearedOnEveryReturn(t *testing.T) {
	var seen []*scratch
	used := map[string]bool{}
	scratchHook = func(sc *scratch) { seen = append(seen, sc) }
	scratchUsed = func(sc *scratch) {
		for _, f := range nonzeroFields(sc) {
			used[f] = true
		}
	}
	t.Cleanup(func() { scratchHook, scratchUsed = nil, nil })
	h := sha256.Sum256([]byte("digest"))
	var notScalar [32]byte
	for i := range notScalar {
		notScalar[i] = 0xff
	}
	cases := []struct {
		name string
		want error
		run  func(*keychainfake.Store, *Signer) error
	}{
		{"keygen", nil, func(st *keychainfake.Store, s *Signer) error { _, err := s.Keygen("grant-b"); return err }},
		{"keygen-no-valid-scalar", keychain.ErrStore, func(st *keychainfake.Store, s *Signer) error {
			_, err := NewWithStore(st, &countingReader{data: notScalar[:]}).Keygen("grant-b")
			return err
		}},
		{"keygen-entropy-fails", keychain.ErrStore, func(st *keychainfake.Store, s *Signer) error {
			_, err := NewWithStore(st, failingReader{}).Keygen("grant-b")
			return err
		}},
		{"schnorr", nil, func(st *keychainfake.Store, s *Signer) error {
			_, err := s.SignSchnorr("grant-a", "r", h[:])
			return err
		}},
		{"ecdsa", nil, func(st *keychainfake.Store, s *Signer) error { _, err := s.SignECDSA("grant-a", "r", h[:]); return err }},
		{"schnorr-auth-canceled", keychain.ErrCanceled, func(st *keychainfake.Store, s *Signer) error {
			st.SecretErr = keychain.ErrCanceled
			_, err := s.SignSchnorr("grant-a", "r", h[:])
			return err
		}},
		{"ecdsa-swapped-item", keychain.ErrItem, func(st *keychainfake.Store, s *Signer) error {
			var other [32]byte
			copy(other[:], mustHex(t, vectors[2].secret))
			st.Swap = &other
			_, err := s.SignECDSA("grant-a", "r", h[:])
			return err
		}},
		{"schnorr-not-a-scalar", keychain.ErrItem, func(st *keychainfake.Store, s *Signer) error {
			st.Swap = &notScalar
			_, err := s.SignSchnorr("grant-a", "r", h[:])
			return err
		}},
		{"schnorr-aux-entropy-fails", keychain.ErrStore, func(st *keychainfake.Store, s *Signer) error {
			_, err := NewWithStore(st, failingReader{}).SignSchnorr("grant-a", "r", h[:])
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := keychainfake.New()
			s := NewWithStore(store, &countingReader{data: mustHex(t, vectors[1].secret)})
			if _, err := s.Keygen("grant-a"); err != nil {
				t.Fatal(err)
			}
			seen = nil
			if err := c.run(store, s); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if len(seen) == 0 {
				t.Fatal("no scratch observed")
			}
			for _, sc := range seen {
				if f := nonzeroFields(sc); len(f) != 0 {
					t.Fatalf("scratch not wiped after return: %v", f)
				}
			}
		})
	}
	all := reflect.TypeOf(scratch{})
	for i := 0; i < all.NumField(); i++ {
		name := all.Field(i).Name
		if name != "kb" && name != "acc" && !used[name] {
			t.Errorf("field %s never populated before a wipe: the zero check on it is vacuous", name)
		}
	}
}

// workingValues names the package's own hash and verifier working values in
// sc that are not all zero: for each SHA-256 state (the BIP-340 hash and the
// HMAC inner and outer hashes) its chaining value, buffer, schedule, working
// variables a..h, round temporaries T1/T2 and counters; the HMAC pad; and the
// verifier's copy of S.
func workingValues(sc *scratch) []string {
	var out []string
	add := func(name string, nonzero bool) {
		if nonzero {
			out = append(out, name)
		}
	}
	for _, hs := range []struct {
		name string
		d    *hashState
	}{{"h", &sc.h}, {"mac.inner", &sc.mac.inner}, {"mac.outer", &sc.mac.outer}} {
		add(hs.name+".h", hs.d.h != [8]uint32{})
		add(hs.name+".x", hs.d.x != [64]byte{})
		add(hs.name+".w", hs.d.w != [64]uint32{})
		add(hs.name+".v", hs.d.v != [8]uint32{})
		add(hs.name+".t", hs.d.t != [2]uint32{})
		add(hs.name+".count", hs.d.nx != 0 || hs.d.len != 0)
	}
	add("mac.pad", sc.mac.pad != [64]byte{})
	add("vs", sc.vs != btcec.ModNScalar{})
	return out
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// Claim: the SHA-256 working variables a..h, the round temporaries T1/T2 and
// the message schedule of every hash this package runs over secret input, and
// the verifier's copy of an ECDSA S, are held in the operation's scratch and
// are zero once the call that allocated it has returned — on success
// (public SignECDSA and SignSchnorr), on verification refusal, on error
// returns (authentication canceled, aux entropy failure) and on a panic
// after signing. Observed through scratchHook after the call returned, with
// a per-case positive control: just before the wipe, the values the case
// exercises were populated, so a design that kept them in named locals
// (outside the scratch) fails here as "not populated".
// Refusal paths: the BIP-340 refusal goes through public SignSchnorr with a
// fault injected by its aux entropy reader (the private scalar in the
// scratch is moved off the stored key after the key check, so the library's
// verification refuses). ECDSA verification refusal is not reachable through
// public SignECDSA without fault injection (nothing runs between the key
// check and the verification), so that case runs the same withKey wrapper
// with the production signECDSA step and a foreign public key.
// Limit: this observes the package's own named values only; registers,
// unnamed compiler temporaries and the curve library's frames are the
// documented residual (docs/KEYCHAIN.md "Residual memory").
func TestOwnedWorkingStateCleared(t *testing.T) {
	var seen []*scratch
	var used []string
	scratchHook = func(sc *scratch) { seen = append(seen, sc) }
	scratchUsed = func(sc *scratch) { used = append(used, workingValues(sc)...) }
	t.Cleanup(func() { scratchHook, scratchUsed = nil, nil })
	h := sha256.Sum256([]byte("digest"))
	_, foreign := btcec.PrivKeyFromBytes(mustHex(t, vectors[2].secret))
	hashed := []string{"h.v", "h.t", "h.w", "h.h"}
	macced := []string{"mac.inner.v", "mac.inner.t", "mac.inner.w", "mac.outer.v", "mac.outer.t", "mac.outer.w"}
	cases := []struct {
		name     string
		want     error
		panics   bool
		populate []string
		run      func(*keychainfake.Store, *Signer) error
	}{
		{"ecdsa-signed", nil, false, append(slices.Clone(macced), "vs"), func(st *keychainfake.Store, s *Signer) error {
			_, err := s.SignECDSA("grant-a", "r", h[:])
			return err
		}},
		{"schnorr-signed", nil, false, hashed, func(st *keychainfake.Store, s *Signer) error {
			_, err := s.SignSchnorr("grant-a", "r", h[:])
			return err
		}},
		{"schnorr-verify-refused", ErrSignature, false, hashed, func(st *keychainfake.Store, s *Signer) error {
			fault := readerFunc(func(p []byte) (int, error) {
				var one btcec.ModNScalar
				one.SetInt(1)
				seen[len(seen)-1].d.Add(&one)
				clear(p)
				return len(p), nil
			})
			_, err := NewWithStore(st, fault).SignSchnorr("grant-a", "r", h[:])
			return err
		}},
		{"ecdsa-verify-refused", ErrSignature, false, append(slices.Clone(macced), "vs"), func(st *keychainfake.Store, s *Signer) error {
			_, err := s.withKey("grant-a", "r", func(sc *scratch, _ *btcec.PublicKey) ([]byte, error) {
				return signECDSA(sc, foreign, h[:])
			})
			return err
		}},
		{"panic-after-signing", nil, true, append(append(slices.Clone(macced), hashed...), "vs"), func(st *keychainfake.Store, s *Signer) error {
			_, err := s.withKey("grant-a", "r", func(sc *scratch, pub *btcec.PublicKey) ([]byte, error) {
				_, e1 := signECDSA(sc, pub, h[:])
				_, e2 := signSchnorr(sc, pub, h[:])
				panic(errors.Join(errors.New("injected after signing"), e1, e2))
			})
			return err
		}},
		{"schnorr-auth-canceled", keychain.ErrCanceled, false, nil, func(st *keychainfake.Store, s *Signer) error {
			st.SecretErr = keychain.ErrCanceled
			_, err := s.SignSchnorr("grant-a", "r", h[:])
			return err
		}},
		{"schnorr-aux-entropy-fails", keychain.ErrStore, false, nil, func(st *keychainfake.Store, s *Signer) error {
			_, err := NewWithStore(st, failingReader{}).SignSchnorr("grant-a", "r", h[:])
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := keychainfake.New()
			s := NewWithStore(store, &countingReader{data: mustHex(t, vectors[1].secret)})
			if _, err := s.Keygen("grant-a"); err != nil {
				t.Fatal(err)
			}
			seen, used = nil, nil
			var err error
			panicked := func() (p bool) {
				defer func() { p = recover() != nil }()
				err = c.run(store, s)
				return false
			}()
			if panicked != c.panics || (!c.panics && !errors.Is(err, c.want)) {
				t.Fatalf("got err %v panicked %v, want %v panicked %v", err, panicked, c.want, c.panics)
			}
			if len(seen) == 0 {
				t.Fatal("no scratch observed")
			}
			for _, name := range c.populate {
				if !slices.Contains(used, name) {
					t.Errorf("%s not populated in the scratch before the wipe: the zero check on it is vacuous, or the value lives outside the scratch", name)
				}
			}
			for _, sc := range seen {
				if left := workingValues(sc); len(left) != 0 {
					t.Fatalf("owned working values survive the return: %v", left)
				}
			}
		})
	}
}

// secretPathLocals are the only named locals allowed in the package's
// functions that compute over secret-derived words, each public: a byte
// count, a loop index, the message bit length, and the library's parsed
// signature (the curve library's own copy, docs/KEYCHAIN.md "Residual
// memory") with its parse error.
var secretPathLocals = map[string][]string{
	"sha256.go:hashState.reset":       nil,
	"sha256.go:hashState.write":       {"n"},
	"sha256.go:hashState.block":       {"i", "i", "i", "i"},
	"sha256.go:hashState.sum":         {"length", "lb", "i"},
	"sha256.go:hashState.tagged":      nil,
	"sha256.go:hmacState.start":       {"i", "i"},
	"sha256.go:hmacState.finish":      nil,
	"keysign.go:scratch.lowSVerifies": {"sig", "err"},
}

// Claim: the SHA-256, HMAC and ECDSA-verifier functions that compute over
// secret-derived words declare no named local variable except the listed
// public ones, so every secret-bearing word they name is a field of the
// wiped scratch. A reintroduced local (for example "a, b, ... := d.h[0],
// ..." in block, "for i, v := range d.h" in sum, or "s := sig.S()" in
// lowSVerifies) fails here even where no runtime observation can see it.
// Limit: source level only; it says nothing about registers or unnamed
// compiler temporaries.
func TestHashCodeHasNoSecretLocals(t *testing.T) {
	got := map[string][]string{}
	fset := token.NewFileSet()
	for _, file := range []string{"sha256.go", "keysign.go"} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			recv := fn.Recv.List[0].Type
			if star, ok := recv.(*ast.StarExpr); ok {
				recv = star.X
			}
			key := file + ":" + recv.(*ast.Ident).Name + "." + fn.Name.Name
			if _, tracked := secretPathLocals[key]; !tracked {
				continue
			}
			names := []string{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					if n.Tok == token.DEFINE {
						for _, l := range n.Lhs {
							names = append(names, l.(*ast.Ident).Name)
						}
					}
				case *ast.RangeStmt:
					if n.Tok == token.DEFINE {
						for _, l := range []ast.Expr{n.Key, n.Value} {
							if l != nil {
								names = append(names, l.(*ast.Ident).Name)
							}
						}
					}
				case *ast.ValueSpec:
					for _, l := range n.Names {
						names = append(names, l.Name)
					}
				case *ast.FuncLit:
					names = append(names, "<func literal>")
				}
				return true
			})
			got[key] = names
		}
	}
	for key, want := range secretPathLocals {
		names, ok := got[key]
		if !ok {
			t.Errorf("%s not found", key)
			continue
		}
		if !slices.Equal(names, append([]string{}, want...)) {
			t.Errorf("%s declares locals %v, want only %v", key, names, want)
		}
	}
}
