package keysign

import (
	"encoding/binary"
	"math/bits"
)

// hashState is SHA-256 (FIPS 180-4) with its whole state — chaining value,
// block buffer and message schedule — in one value the caller wipes. The
// standard library's digest keeps its buffer where this package cannot clear
// it, so every hash over secret bytes (the BIP-340 nonce input, the RFC 6979
// HMAC key and output) uses this one. TestSHA256MatchesStdlib pins it to
// crypto/sha256.
type hashState struct {
	h   [8]uint32
	x   [64]byte
	w   [64]uint32
	nx  int
	len uint64
}

var sha256Init = [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}

var sha256K = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func (d *hashState) reset() {
	d.h = sha256Init
	d.nx = 0
	d.len = 0
}

func (d *hashState) write(p []byte) {
	d.len += uint64(len(p))
	for len(p) > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		p = p[n:]
		if d.nx == len(d.x) {
			d.block()
			d.nx = 0
		}
	}
}

func (d *hashState) block() {
	w := &d.w
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(d.x[4*i:])
	}
	for i := 16; i < 64; i++ {
		v1, v2 := w[i-2], w[i-15]
		s1 := bits.RotateLeft32(v1, -17) ^ bits.RotateLeft32(v1, -19) ^ (v1 >> 10)
		s0 := bits.RotateLeft32(v2, -7) ^ bits.RotateLeft32(v2, -18) ^ (v2 >> 3)
		w[i] = s1 + w[i-7] + s0 + w[i-16]
	}
	a, b, c, dd, e, f, g, h := d.h[0], d.h[1], d.h[2], d.h[3], d.h[4], d.h[5], d.h[6], d.h[7]
	for i := 0; i < 64; i++ {
		t1 := h + (bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)) + ((e & f) ^ (^e & g)) + sha256K[i] + w[i]
		t2 := (bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)) + ((a & b) ^ (a & c) ^ (b & c))
		h, g, f, e, dd, c, b, a = g, f, e, dd+t1, c, b, a, t1+t2
	}
	d.h[0] += a
	d.h[1] += b
	d.h[2] += c
	d.h[3] += dd
	d.h[4] += e
	d.h[5] += f
	d.h[6] += g
	d.h[7] += h
}

var padByte = [1]byte{0x80}
var zeroByte = [1]byte{0}

// sum pads, writes the digest to out and leaves the state needing reset.
func (d *hashState) sum(out *[32]byte) {
	length := d.len << 3
	d.write(padByte[:])
	for d.nx != 56 {
		d.write(zeroByte[:])
	}
	var lb [8]byte
	binary.BigEndian.PutUint64(lb[:], length)
	d.write(lb[:])
	for i, v := range d.h {
		binary.BigEndian.PutUint32(out[4*i:], v)
	}
}

// tagged starts a BIP-340 tagged hash: SHA-256(tag) || SHA-256(tag) || ...
func (d *hashState) tagged(tag *[32]byte) {
	d.reset()
	d.write(tag[:])
	d.write(tag[:])
}

func tagOf(name string) [32]byte {
	var d hashState
	var out [32]byte
	d.reset()
	d.write([]byte(name))
	d.sum(&out)
	return out
}

var (
	tagAux       = tagOf("BIP0340/aux")
	tagNonce     = tagOf("BIP0340/nonce")
	tagChallenge = tagOf("BIP0340/challenge")
)

// hmacState is HMAC-SHA256 (RFC 2104) keyed with 32 bytes, all of whose
// state is wipeable: the padded key and the inner and outer hashes.
type hmacState struct {
	pad   [64]byte
	inner hashState
	outer hashState
}

// start keys a new MAC; the message is then written to m.inner.
func (m *hmacState) start(key *[32]byte) {
	clear(m.pad[:])
	copy(m.pad[:], key[:])
	for i := range m.pad {
		m.pad[i] ^= 0x36
	}
	m.inner.reset()
	m.inner.write(m.pad[:])
	for i := range m.pad {
		m.pad[i] ^= 0x36 ^ 0x5c
	}
	m.outer.reset()
	m.outer.write(m.pad[:])
	clear(m.pad[:])
}

// finish writes the MAC to out; out may be the key the MAC was started with.
func (m *hmacState) finish(out *[32]byte) {
	m.inner.sum(out)
	m.outer.write(out[:])
	m.outer.sum(out)
}
