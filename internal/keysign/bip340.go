package keysign

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// schnorr is BIP-340 signing (the "Default Signing" algorithm) of msg with
// the key loaded into sc (loadKey) and the auxiliary randomness in sc.aux.
// Every secret it derives is written into sc. The caller verifies the result
// with the library before it leaves the package.
func (sc *scratch) schnorr(msg []byte) ([]byte, error) {
	// d = d' if has_even_y(P), otherwise n - d'.
	if sc.P.Y.IsOdd() {
		sc.d.Negate()
	}
	sc.d.PutBytes(&sc.dBytes)
	// t = bytes(d) xor hash_BIP0340/aux(a).
	sc.h.tagged(&tagAux)
	sc.h.write(sc.aux[:])
	sc.h.sum(&sc.t)
	for i := range sc.t {
		sc.t[i] ^= sc.dBytes[i]
	}
	// rand = hash_BIP0340/nonce(t || bytes(P) || m).
	var px [32]byte
	sc.P.X.PutBytes(&px)
	sc.h.tagged(&tagNonce)
	sc.h.write(sc.t[:])
	sc.h.write(px[:])
	sc.h.write(msg)
	sc.h.sum(&sc.rand)
	// k' = int(rand) mod n; fail if k' = 0.
	sc.k.SetBytes(&sc.rand)
	if sc.k.IsZero() {
		return nil, ErrSignature
	}
	// R = k'*G; k = k' if has_even_y(R), otherwise n - k'.
	sc.mulG(&sc.k, &sc.R)
	sc.R.ToAffine()
	if sc.R.Y.IsOdd() {
		sc.k.Negate()
	}
	// e = int(hash_BIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
	var rx, eb [32]byte
	sc.R.X.PutBytes(&rx)
	sc.h.tagged(&tagChallenge)
	sc.h.write(rx[:])
	sc.h.write(px[:])
	sc.h.write(msg)
	sc.h.sum(&eb)
	var e btcec.ModNScalar
	e.SetBytes(&eb)
	// sig = bytes(R) || bytes((k + e*d) mod n).
	sig := make([]byte, 64)
	copy(sig, rx[:])
	sc.mix.Mul2(&e, &sc.d).Add(&sc.k)
	sc.mix.PutBytesUnchecked(sig[32:])
	return sig, nil
}

// drbgMAC sets out = HMAC_K(V || sep || seed), omitting sep and seed when
// sep is negative. out may be K or V.
func (sc *scratch) drbgMAC(out *[32]byte, sep int, withSeed bool) {
	sc.mac.start(&sc.drbgK)
	sc.mac.inner.write(sc.drbgV[:])
	if sep >= 0 {
		sc.mac.inner.write([]byte{byte(sep)})
	}
	if withSeed {
		sc.mac.inner.write(sc.seed[:])
	}
	sc.mac.finish(out)
}

// nonceRFC6979 starts the RFC 6979 section 3.2 HMAC-SHA256 DRBG for the key
// in sc.d and the hash, and sets sc.k to its first candidate in [1, n-1].
func (sc *scratch) nonceRFC6979(hash *[32]byte) {
	// seed = int2octets(x) || bits2octets(h1); qlen = hlen = 256.
	sc.d.PutBytes(&sc.dBytes)
	copy(sc.seed[:32], sc.dBytes[:])
	var h1 btcec.ModNScalar
	h1.SetBytes(hash)
	h1.PutBytesUnchecked(sc.seed[32:])
	// Steps b-g.
	for i := range sc.drbgV {
		sc.drbgV[i] = 0x01
	}
	clear(sc.drbgK[:])
	sc.drbgMAC(&sc.drbgK, 0x00, true)
	sc.drbgMAC(&sc.drbgV, -1, false)
	sc.drbgMAC(&sc.drbgK, 0x01, true)
	sc.drbgMAC(&sc.drbgV, -1, false)
	sc.nextNonce()
}

// nextNonce is step h: V = HMAC_K(V); k = bits2int(V), accepted when in
// [1, n-1]; otherwise K = HMAC_K(V || 0x00), V = HMAC_K(V) and again.
func (sc *scratch) nextNonce() {
	for {
		sc.drbgMAC(&sc.drbgV, -1, false)
		if overflow := sc.k.SetBytes(&sc.drbgV); overflow == 0 && !sc.k.IsZero() {
			return
		}
		sc.retryNonce()
	}
}

func (sc *scratch) retryNonce() {
	sc.drbgMAC(&sc.drbgK, 0x00, false)
	sc.drbgMAC(&sc.drbgV, -1, false)
}

// ecdsaSign is RFC 6979 deterministic ECDSA over the 32-byte hash with the
// key loaded into sc, with the low-S rule (BIP 62/146): (r, s) with
// r = (k*G).x mod n and s = k^-1 * (e + r*d) mod n, s negated when above n/2.
// It returns strict DER.
func (sc *scratch) ecdsaSign(hash *[32]byte) []byte {
	var e, r, s btcec.ModNScalar
	e.SetBytes(hash)
	sc.nonceRFC6979(hash)
	for {
		sc.mulG(&sc.k, &sc.R)
		sc.R.ToAffine()
		var rx [32]byte
		sc.R.X.PutBytes(&rx)
		r.SetBytes(&rx)
		if r.IsZero() {
			sc.retryNonce()
			sc.nextNonce()
			continue
		}
		invert(&sc.kinv, &sc.k)
		sc.mix.Mul2(&sc.d, &r).Add(&e)
		s.Mul2(&sc.mix, &sc.kinv)
		if s.IsZero() {
			sc.retryNonce()
			sc.nextNonce()
			continue
		}
		if s.IsOverHalfOrder() {
			s.Negate()
		}
		return ecdsa.NewSignature(&r, &s).Serialize()
	}
}
