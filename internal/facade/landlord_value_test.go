package facade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	vGrant  = "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517" // BIP-340 vector 3
	vSocial = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" // BIP-340 vector 0
)

func valueBuild(t *testing.T, grant, descriptor string) (Envelope, int) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "social.json")
	if err := os.WriteFile(p, []byte(descriptor), 0600); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	code := Run(context.Background(), []string{"value", "build", "--grant-xonly", grant, "--social-descriptor", p, "--json"}, &out, &diag)
	if diag.Len() != 0 || !outputSafe(out.Bytes()) {
		t.Fatal("unsafe output")
	}
	var e Envelope
	if err := DecodeStrictEnvelope(out.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	return e, code
}

// Claim: value build renders the exact LIP-0004 combined landlord value that
// a hand-written expected string spells (independent of the renderer), with
// its hex, and the repo's v3 reader reads back the same grant key and social
// descriptor.
func TestValueBuildVector(t *testing.T) {
	desc := `{"names":{"_":"` + vSocial + `"},"relays":{"` + vSocial + `":["wss://relay.example","wss://second.example/path"]}}`
	want := `{"nostr":{"names":{"_":"` + vSocial + `"},"relays":{"` + vSocial + `":["wss://relay.example","wss://second.example/path"]}},"swarma":{"landlord":{"grant":"` + vGrant + `"}}}`
	e, code := valueBuild(t, vGrant, desc)
	mustOK(t, e, code)
	r := resultAs[LandlordValueResult](t, e)
	if r.Value != want || r.ValueHex != hex.EncodeToString([]byte(want)) || r.Bytes != len(want) || r.GrantKey != vGrant || r.Social.Key != vSocial || len(r.Social.Relays) != 2 {
		t.Fatalf("value build %+v", r)
	}
	v := classifyV3([]byte(r.Value))
	if v.role != "landlord" || v.grantKey != vGrant || v.social.Key != vSocial {
		t.Fatal("v3 reader disagrees")
	}
	// A descriptor without relays is admitted and omits the member.
	e, code = valueBuild(t, vGrant, `{"names":{"_":"`+vSocial+`"}}`)
	mustOK(t, e, code)
	if got := resultAs[LandlordValueResult](t, e).Value; got != `{"nostr":{"names":{"_":"`+vSocial+`"}},"swarma":{"landlord":{"grant":"`+vGrant+`"}}}` {
		t.Fatalf("relay-less value %s", got)
	}
}

// Claim: value build refuses an extra member anywhere in the descriptor file,
// a grant key that is not a lowercase valid x-only key, relays keyed by
// another key, bad relay URLs and a value over 520 bytes, each with its code.
func TestValueBuildRefusals(t *testing.T) {
	ok := `{"names":{"_":"` + vSocial + `"},"relays":{"` + vSocial + `":["wss://relay.example"]}}`
	cases := []struct{ name, grant, desc, want string }{
		{"extra-top-member", vGrant, `{"names":{"_":"` + vSocial + `"},"profile":"x"}`, "BAD_INPUT"},
		{"extra-name", vGrant, `{"names":{"_":"` + vSocial + `","bob":"` + vSocial + `"}}`, "BAD_INPUT"},
		{"duplicate-member", vGrant, `{"names":{"_":"` + vSocial + `"},"names":{"_":"` + vSocial + `"}}`, "BAD_INPUT"},
		{"uppercase-grant", strings.ToUpper(vGrant), ok, "LANDLORD_KEY"},
		{"compressed-grant", "02" + vGrant, ok, "LANDLORD_KEY"},
		{"off-curve-grant", strings.Repeat("ff", 32), ok, "LANDLORD_KEY"},
		{"bad-social-key", vGrant, `{"names":{"_":"` + strings.Repeat("ff", 32) + `"}}`, "NOSTR_KEY"},
		{"relays-other-key", vGrant, `{"names":{"_":"` + vSocial + `"},"relays":{"` + vGrant + `":["wss://relay.example"]}}`, "NOSTR_RELAYS"},
		{"http-relay", vGrant, `{"names":{"_":"` + vSocial + `"},"relays":{"` + vSocial + `":["https://relay.example"]}}`, "NOSTR_RELAY_URL"},
		{"duplicate-relay", vGrant, `{"names":{"_":"` + vSocial + `"},"relays":{"` + vSocial + `":["wss://a.example","wss://a.example"]}}`, "NOSTR_RELAY_URL"},
		{"oversize", vGrant, `{"names":{"_":"` + vSocial + `"},"relays":{"` + vSocial + `":["wss://a.example/` + strings.Repeat("x", 400) + `"]}}`, "LANDLORD_VALUE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, code := valueBuild(t, c.grant, c.desc)
			mustRefuse(t, e, code, c.want)
		})
	}
}

// Claim: the re-parse check refuses a value that differs from the intended
// one by a wrong grant key, a different social key or relay list, an extra
// member at any level, or non-canonical spacing, and accepts the exact
// rendering (positive control).
func TestLandlordValueReparse(t *testing.T) {
	d := ValueNostrDescriptor{Names: valueNostrNames{vSocial}, Relays: map[string][]string{vSocial: {"wss://relay.example"}}}
	good, f := renderLandlordValue(vGrant, d)
	if f != nil || checkLandlordValue(good, vGrant, d) != nil {
		t.Fatal("positive control refused")
	}
	other := "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8"
	bad := map[string]string{
		"wrong-grant":    strings.Replace(good, vGrant, other, 1),
		"wrong-social":   strings.ReplaceAll(good, vSocial, other),
		"other-relay":    strings.Replace(good, "wss://relay.example", "wss://evil.example", 1),
		"extra-top":      strings.TrimSuffix(good, "}") + `,"x":1}`,
		"extra-landlord": strings.Replace(good, `"grant":"`+vGrant+`"`, `"grant":"`+vGrant+`","agent":"id/x"`, 1),
		"spacing":        strings.Replace(good, `,"swarma"`, `, "swarma"`, 1),
		"no-nostr":       `{"swarma":{"landlord":{"grant":"` + vGrant + `"}}}`,
	}
	for name, v := range bad {
		if f := checkLandlordValue(v, vGrant, d); f == nil || f.Code != "VALUE_MISMATCH" {
			t.Fatalf("%s admitted", name)
		}
	}
}

// legacySighash is an independent implementation of the pre-segwit
// SIGHASH_ALL digest from its definition: blank every input script, put the
// prevout script in the signed input, serialize, append the 4-byte type and
// double SHA-256.
func legacySighash(tx *wire.MsgTx, idx int, script []byte) []byte {
	var b bytes.Buffer
	u32 := func(v uint32) { binary.Write(&b, binary.LittleEndian, v) }
	varint := func(n int) { wire.WriteVarInt(&b, 0, uint64(n)) }
	u32(uint32(tx.Version))
	varint(len(tx.TxIn))
	for i, in := range tx.TxIn {
		b.Write(in.PreviousOutPoint.Hash[:])
		u32(in.PreviousOutPoint.Index)
		if i == idx {
			varint(len(script))
			b.Write(script)
		} else {
			varint(0)
		}
		u32(in.Sequence)
	}
	varint(len(tx.TxOut))
	for _, out := range tx.TxOut {
		binary.Write(&b, binary.LittleEndian, out.Value)
		varint(len(out.PkScript))
		b.Write(out.PkScript)
	}
	u32(tx.LockTime)
	u32(uint32(txscript.SigHashAll))
	first := sha256.Sum256(b.Bytes())
	second := sha256.Sum256(first[:])
	return second[:]
}

// Claim: the seal-spend sighash equals an independent implementation of the
// legacy SIGHASH_ALL definition for single- and multi-input transactions,
// each input index, Namecoin's tx version 0x7100 and a non-zero locktime,
// and differs when any committed field changes. Limit: scripts without
// OP_CODESEPARATOR, which a P2PKH prevout never has.
func TestSealSpendSighashVectors(t *testing.T) {
	f := preparedFlow(t)
	script := landlordP2PKH(t)
	raw, _ := hex.DecodeString(bip340Secrets[keyLandlord])
	pub := p2pkhPub(raw)
	for _, version := range []int32{1, 2, 0x7100} {
		for _, inputs := range []int{1, 3} {
			tx := wire.NewMsgTx(version)
			seal, _ := chainhash.NewHashFromStr(f.draft.Draft.Seal.TxID)
			var prevouts []Prevout
			for i := 0; i < inputs; i++ {
				h := chainhash.Hash{byte(i + 1)}
				op := wire.NewOutPoint(&h, uint32(i))
				if i == inputs-1 {
					op = wire.NewOutPoint(seal, f.draft.Draft.Seal.Vout)
				}
				in := wire.NewTxIn(op, nil, nil)
				in.Sequence = 0xfffffffd - uint32(i)
				tx.AddTxIn(in)
				prevouts = append(prevouts, Prevout{hex.EncodeToString(script), 50000})
			}
			tx.AddTxOut(wire.NewTxOut(40000, script))
			tx.LockTime = 812345
			var b bytes.Buffer
			tx.SerializeNoWitness(&b)
			s := SealSpend{TxHex: hex.EncodeToString(b.Bytes()), InputIndex: uint32(inputs - 1), Prevouts: prevouts}
			p, fl := planSealSpend(s, f.draft.Draft, pub, "regtest")
			if fl != nil {
				t.Fatalf("v%d/%d: %+v", version, inputs, fl)
			}
			if want := legacySighash(tx, inputs-1, script); !bytes.Equal(p.sighash, want) {
				t.Fatalf("v%d/%d: sighash %x want %x", version, inputs, p.sighash, want)
			}
			tx.TxOut[0].Value--
			if bytes.Equal(p.sighash, legacySighash(tx, inputs-1, script)) {
				t.Fatal("sighash does not commit to output values")
			}
		}
	}
}
