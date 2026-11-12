package registration

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/wire"
)

type signedCore struct {
	PSBT   string `json:"signed_psbt"`
	Hex    string `json:"signed_hex"`
	TxID   string `json:"txid"`
	VSize  uint32 `json:"vsize"`
	Weight uint32 `json:"weight"`
}

func signedFixture(t *testing.T, mode string) (*Planner, []*Plan, map[string]signedCore) {
	t.Helper()
	p, in, rv, _, _, _ := fixture(t, mode)
	r, e := p.Reserve(in, p.profile.Policy.CreatedAt+60)
	if e != nil {
		t.Fatal(e)
	}
	v, e := p.Reveal(r, rv, p.profile.Policy.CreatedAt+60)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join("testdata", "core28", mode, "signed-graph.json"))
	if e != nil {
		t.Fatal(e)
	}
	var graph map[string]signedCore
	if e := json.Unmarshal(b, &graph); e != nil {
		t.Fatal(e)
	}
	return p, []*Plan{r, v}, graph
}

// Every public signature from both Core graphs verifies, and local witness
// assembly reproduces Core's exact final bytes, txid, weight and virtual size.
// This proves no protected receipt, presence, chain state or release authority.
func TestCore28SignedParity(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		p, plans, graph := signedFixture(t, mode)
		for _, plan := range plans {
			for _, tx := range plan.Transactions() {
				g := graph[tx.Slot]
				v, e := p.VerifySigned(plan, tx.Slot, tx.PSBT, g.PSBT)
				if e != nil {
					t.Fatalf("%s/%s: %v", mode, tx.Slot, e)
				}
				if v.Hex != g.Hex || v.TxID != g.TxID || v.VSize != g.VSize || v.Weight != g.Weight || v.FeeAtoms != 100000 {
					t.Fatalf("%s/%s differs from Core", mode, tx.Slot)
				}
			}
		}
	}
}

func packetText(p *psbtPacket) string {
	var b bytes.Buffer
	b.WriteString("psbt\xff")
	for _, m := range append([]psbtMap{p.global}, append(p.inputs, p.outputs...)...) {
		for k, v := range m {
			_ = wire.WriteVarBytes(&b, 0, []byte(k))
			_ = wire.WriteVarBytes(&b, 0, v)
		}
		b.WriteByte(0)
	}
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

func changed(t *testing.T, s string, edit func(*psbtPacket)) string {
	t.Helper()
	p, e := readPSBT(s)
	if e != nil {
		t.Fatal(e)
	}
	edit(p)
	return packetText(p)
}

func partial(m psbtMap) string {
	for k := range m {
		if k[0] == 2 {
			return k
		}
	}
	panic("fixture has no signature")
}

// The admitted optional BIP174 forms remain valid; signed results must retain
// each admitted map entry exactly, independent of its serialized map order.
func TestPSBTCompatibility(t *testing.T) {
	p, plans, graph := signedFixture(t, "all-four-before-release")
	plan, tx := plans[0], plans[0].Transactions()[0]
	for _, option := range []string{"version-zero", "explicit-all", "without-witness-utxo", "matching-global-xpub", "funding-with-witness", "map-order"} {
		t.Run(option, func(t *testing.T) {
			edit := func(x *psbtPacket) {
				switch option {
				case "version-zero":
					x.global[string([]byte{0xfb})] = []byte{0, 0, 0, 0}
				case "explicit-all":
					x.inputs[0][string([]byte{3})] = []byte{1, 0, 0, 0}
				case "without-witness-utxo":
					delete(x.inputs[0], string([]byte{1}))
				case "matching-global-xpub":
					x.global[string(append([]byte{1}, base58.Decode(p.pin.AccountXPub)[:78]...))] = p.pathBytes(p.pin.AccountPath)
				case "funding-with-witness":
					b, e := os.ReadFile(filepath.Join("testdata", "core28", "all-four-before-release", "funding-signed-full.json"))
					if e != nil {
						t.Fatal(e)
					}
					var full struct {
						Hex string `json:"hex"`
					}
					if e := json.Unmarshal(b, &full); e != nil {
						t.Fatal(e)
					}
					x.inputs[0][string([]byte{0})] = mustHex(t, full.Hex)
				}
			}
			unsigned, signed := changed(t, tx.PSBT, edit), changed(t, graph["A"].PSBT, edit)
			if e := p.ValidateUnsigned(plan, "A", unsigned); e != nil {
				t.Fatal(e)
			}
			if _, e := p.VerifySigned(plan, "A", unsigned, signed); e != nil {
				t.Fatal(e)
			}
			if option == "version-zero" || option == "explicit-all" || option == "matching-global-xpub" {
				if v, e := p.VerifySigned(plan, "A", unsigned, graph["A"].PSBT); !errors.Is(e, ErrPSBT) || v != nil {
					t.Fatal("signed result silently dropped an accepted map entry")
				}
			}
		})
	}
}

// Each malformed map and signature neighbor is rejected with no final result;
// a valid Core signature passes first. No negative case invokes a signer.
func TestSignedRefusals(t *testing.T) {
	p, plans, graph := signedFixture(t, "all-four-before-release")
	plan, tx := plans[1], plans[1].Transactions()[0]
	good := graph["C"].PSBT
	for _, tc := range []struct {
		name string
		edit func(*psbtPacket)
		want error
	}{
		{"changed-output", func(x *psbtPacket) { x.global[string([]byte{0})][len(x.global[string([]byte{0})])-8] ^= 1 }, ErrPSBT},
		{"unknown-global", func(x *psbtPacket) { x.global[string([]byte{0xfc})] = []byte{1} }, ErrPSBT},
		{"version-one", func(x *psbtPacket) { x.global[string([]byte{0xfb})] = []byte{1, 0, 0, 0} }, ErrPSBT},
		{"missing-full-prev", func(x *psbtPacket) { delete(x.inputs[0], string([]byte{0})) }, ErrPSBT},
		{"changed-full-prev", func(x *psbtPacket) { x.inputs[0][string([]byte{0})][9] ^= 1 }, ErrPSBT},
		{"changed-witness-amount", func(x *psbtPacket) { x.inputs[0][string([]byte{1})][0] ^= 1 }, ErrPSBT},
		{"non-all-sighash", func(x *psbtPacket) { x.inputs[0][string([]byte{3})] = []byte{2, 0, 0, 0} }, ErrPSBT},
		{"redeem-script", func(x *psbtPacket) { x.inputs[0][string([]byte{4})] = []byte{0} }, ErrPSBT},
		{"final-witness", func(x *psbtPacket) { x.inputs[0][string([]byte{8})] = []byte{0} }, ErrPSBT},
		{"changed-owned-path", func(x *psbtPacket) {
			for k := range x.inputs[0] {
				if k[0] == 6 {
					x.inputs[0][k][len(x.inputs[0][k])-1] ^= 1
				}
			}
		}, ErrPSBT},
		{"changed-output-derivation", func(x *psbtPacket) {
			for k := range x.outputs[0] {
				x.outputs[0][k][0] ^= 1
			}
		}, ErrPSBT},
		{"one-missing-signature", func(x *psbtPacket) { delete(x.inputs[1], partial(x.inputs[1])) }, ErrSignature},
		{"signature-bitflip", func(x *psbtPacket) { k := partial(x.inputs[0]); x.inputs[0][k][10] ^= 1 }, ErrSignature},
		{"signature-non-all", func(x *psbtPacket) { k := partial(x.inputs[0]); v := x.inputs[0][k]; v[len(v)-1] = 2 }, ErrSignature},
		{"signature-trailing-junk", func(x *psbtPacket) {
			k := partial(x.inputs[0])
			v := x.inputs[0][k]
			x.inputs[0][k] = append(append(append([]byte{}, v[:len(v)-1]...), 0), 1)
		}, ErrSignature},
		{"high-s", func(x *psbtPacket) {
			k := partial(x.inputs[0])
			v := x.inputs[0][k]
			var sig struct{ R, S *big.Int }
			if _, e := asn1.Unmarshal(v[:len(v)-1], &sig); e != nil {
				t.Fatal(e)
			}
			sig.S.Sub(btcec.S256().N, sig.S)
			der, e := asn1.Marshal(sig)
			if e != nil {
				t.Fatal(e)
			}
			x.inputs[0][k] = append(der, 1)
		}, ErrSignature},
		{"foreign-pubkey", func(x *psbtPacket) {
			k := partial(x.inputs[0])
			bad := []byte(k)
			bad[4] ^= 1
			x.inputs[0][string(bad)] = x.inputs[0][k]
			delete(x.inputs[0], k)
		}, ErrSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := p.VerifySigned(plan, "C", tx.PSBT, good); e != nil {
				t.Fatal(e)
			}
			v, e := p.VerifySigned(plan, "C", tx.PSBT, changed(t, good, tc.edit))
			if !errors.Is(e, tc.want) || v != nil {
				t.Fatalf("result=%v error=%v want=%v", v, e, tc.want)
			}
		})
	}
}

// Envelope rejection includes nonminimal lengths, duplicates, truncation,
// trailing maps, noncanonical base64 and resource limits, next to a valid packet.
func TestPSBTEnvelopeRefusals(t *testing.T) {
	p, plans, graph := signedFixture(t, "two-stage")
	plan, tx := plans[0], plans[0].Transactions()[0]
	if e := p.ValidateUnsigned(plan, "A", tx.PSBT); e != nil {
		t.Fatal(e)
	}
	raw, _ := base64.StdEncoding.DecodeString(tx.PSBT)
	duplicate := append([]byte{}, raw[:5]...)
	_ = wire.WriteVarBytes((*byteBuffer)(&duplicate), 0, []byte{0})
	packet, _ := readPSBT(tx.PSBT)
	_ = wire.WriteVarBytes((*byteBuffer)(&duplicate), 0, packet.global[string([]byte{0})])
	duplicate = append(duplicate, raw[5:]...)
	for _, bad := range []string{
		base64.StdEncoding.EncodeToString(duplicate),
		base64.StdEncoding.EncodeToString(append(append([]byte{}, raw[:5]...), append([]byte{0xfd, 1, 0}, raw[6:]...)...)),
		base64.StdEncoding.EncodeToString(raw[:len(raw)-1]),
		base64.StdEncoding.EncodeToString(append(raw, 0)),
		tx.PSBT + "\n", tx.PSBT[:len(tx.PSBT)-1],
		graph["A"].PSBT,
		base64.StdEncoding.EncodeToString(make([]byte, (4<<20)+1)),
	} {
		if e := p.ValidateUnsigned(plan, "A", bad); !errors.Is(e, ErrPSBT) {
			t.Fatalf("error=%v", e)
		}
	}
	if e := p.ValidateUnsigned(nil, "A", tx.PSBT); !errors.Is(e, ErrPSBT) {
		t.Fatal(e)
	}
	if _, e := p.VerifySigned(plan, "B", tx.PSBT, graph["A"].PSBT); !errors.Is(e, ErrPSBT) {
		t.Fatal(e)
	}
	p.profile.Policy.Revision = "different-trusted-profile"
	if e := p.ValidateUnsigned(plan, "A", tx.PSBT); !errors.Is(e, ErrPSBT) {
		t.Fatal(e)
	}
}

type byteBuffer []byte

func (b *byteBuffer) Write(p []byte) (int, error) { *b = append(*b, p...); return len(p), nil }
