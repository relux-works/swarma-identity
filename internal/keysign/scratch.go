package keysign

import (
	"github.com/btcsuite/btcd/btcec/v2"
)

// scratch holds every secret-bearing value of one key operation: the key
// bytes read from the store, the private scalar and its byte form, the
// BIP-340 nonce derivation (aux, t, rand), the RFC 6979 HMAC_DRBG state and
// its input, the nonce and its inverse, the point accumulators of k*G, the
// hash and MAC states that consume secret input, the products that mix the
// key into a public value, and the signature itself until it has verified.
// Nothing secret is held anywhere else in this package, and no library
// routine is given the secret except as a pointer into this struct. The
// library routines keep their own arithmetic temporaries in their frames;
// docs/KEYCHAIN.md "Residual memory" names them.
//
// One scratch is allocated per operation and wipe runs on every return path
// (deferred right after allocation). TestScratchClearedOnEveryReturn observes
// it through scratchHook.
type scratch struct {
	secret [32]byte         // the 32 key bytes from the store or the CSPRNG
	d      btcec.ModNScalar // the private scalar (negated for BIP-340 when P.y is odd)
	dBytes [32]byte         // bytes(d): BIP-340 t input, RFC 6979 int2octets(x)
	aux    [32]byte         // BIP-340 auxiliary randomness
	t      [32]byte         // BIP-340 t = bytes(d) xor hash_aux(aux)
	rand   [32]byte         // BIP-340 rand = hash_nonce(t || P || m)
	seed   [64]byte         // RFC 6979 int2octets(x) || bits2octets(h1)
	drbgK  [32]byte         // RFC 6979 HMAC_DRBG K
	drbgV  [32]byte         // RFC 6979 HMAC_DRBG V
	k      btcec.ModNScalar // the nonce
	kinv   btcec.ModNScalar // ECDSA k^-1
	mix    btcec.ModNScalar // e*d (BIP-340) or r*d + e (ECDSA) before it is public
	s      btcec.ModNScalar // ECDSA s = k^-1 * (r*d + e), public only once it verifies
	out    [72]byte         // the signature bytes (64 BIP-340, at most 72 DER), public only once they verify
	kb     [32]byte         // the bytes of the scalar being multiplied by G
	acc    btcec.JacobianPoint
	P      btcec.JacobianPoint // d'*G (public once affine)
	R      btcec.JacobianPoint // k*G (public once affine)
	h      hashState
	mac    hmacState
}

// scratchHook, when set (tests only), receives each operation's scratch as it
// is allocated, so a test can read it after the operation returned.
// scratchUsed, when set (tests only), sees the scratch just before it is
// wiped, so a test can prove the fields it checks were in use.
var scratchHook, scratchUsed func(*scratch)

func newScratch() *scratch {
	sc := new(scratch)
	if scratchHook != nil {
		scratchHook(sc)
	}
	return sc
}

// wipe zeroes every field. Each field is cleared by name so a reviewer can
// match this list against the struct.
func (sc *scratch) wipe() {
	if scratchUsed != nil {
		scratchUsed(sc)
	}
	clear(sc.secret[:])
	sc.d.Zero()
	clear(sc.dBytes[:])
	clear(sc.aux[:])
	clear(sc.t[:])
	clear(sc.rand[:])
	clear(sc.seed[:])
	clear(sc.drbgK[:])
	clear(sc.drbgV[:])
	sc.k.Zero()
	sc.kinv.Zero()
	sc.mix.Zero()
	sc.s.Zero()
	clear(sc.out[:])
	clear(sc.kb[:])
	sc.acc = btcec.JacobianPoint{}
	sc.P = btcec.JacobianPoint{}
	sc.R = btcec.JacobianPoint{}
	sc.h = hashState{}
	sc.mac = hmacState{}
}

// generator is G in Jacobian coordinates.
var generator = func() btcec.JacobianPoint {
	var g btcec.JacobianPoint
	btcec.Generator().AsJacobian(&g)
	return g
}()

// mulG sets out = v*G (normalized, Jacobian) by MSB-first double-and-add over
// btcec's point primitives. The library's ScalarBaseMultNonConst copies the
// whole scalar into an array in its own frame and leaves it there; here the
// scalar's bytes live only in sc.kb and the running sum only in sc.acc. Like
// the library routine it is not constant time.
func (sc *scratch) mulG(v *btcec.ModNScalar, out *btcec.JacobianPoint) {
	v.PutBytes(&sc.kb)
	sc.acc = btcec.JacobianPoint{}
	for i := 0; i < 256; i++ {
		btcec.DoubleNonConst(&sc.acc, &sc.acc)
		if sc.kb[i>>3]>>(7-uint(i&7))&1 == 1 {
			btcec.AddNonConst(&sc.acc, &generator, &sc.acc)
		}
	}
	out.Set(&sc.acc)
	sc.acc = btcec.JacobianPoint{}
	clear(sc.kb[:])
}

// orderMinusTwo is n-2, the Fermat exponent for inversion modulo n.
var orderMinusTwo = [32]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x3f,
}

// invert sets out = v^(n-2) = v^-1 mod n with ModNScalar arithmetic only.
// The library's InverseValNonConst goes through math/big, whose heap words
// are never cleared. The exponent is public, so the branch is too.
func invert(out, v *btcec.ModNScalar) {
	out.SetInt(1)
	for i := 0; i < 256; i++ {
		out.Square()
		if orderMinusTwo[i>>3]>>(7-uint(i&7))&1 == 1 {
			out.Mul(v)
		}
	}
}

// loadKey turns sc.secret into the scalar d' and P = d'*G (affine). A secret
// that is zero or not below n is not a key.
func (sc *scratch) loadKey() bool {
	if overflow := sc.d.SetBytes(&sc.secret); overflow != 0 || sc.d.IsZero() {
		return false
	}
	sc.mulG(&sc.d, &sc.P)
	sc.P.ToAffine()
	return true
}

// public is the compressed serialization of P (public data).
func (sc *scratch) public() []byte {
	return btcec.NewPublicKey(&sc.P.X, &sc.P.Y).SerializeCompressed()
}
