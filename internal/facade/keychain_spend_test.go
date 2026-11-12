package facade

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func txHex(t *testing.T, tx *wire.MsgTx) string {
	t.Helper()
	var b bytes.Buffer
	if err := tx.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b.Bytes())
}

// prevTx is a previous transaction whose output vout pays value to script.
func prevTx(seed byte, vout uint32, value int64, script []byte) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{seed}, 0), nil, nil))
	for i := uint32(0); i <= vout; i++ {
		tx.AddTxOut(wire.NewTxOut(value, script))
	}
	return tx
}

// spendFixture is a valid request whose seal spend has full previous
// transactions: input 0 spends prevs[0]:0 (1000 sat), input 1 spends the
// draft seal prevs[1]:vout (99000 sat, P2PKH to the landlord key), outputs
// 60000 and 39000. It is the positive control the cases below edit.
type spendFixture struct {
	r      KeychainSignRequest
	tx     *wire.MsgTx
	prevs  []*wire.MsgTx
	script []byte
}

func newSpendFixture(t *testing.T, f *flow) *spendFixture {
	t.Helper()
	script := landlordP2PKH(t)
	r := fullRequest(t, f)
	tx, _ := sealSpendFor(t, r.Draft, script)
	prevA := prevTx(0, 0, 1000, script)
	prevB := prevTx(1, r.Draft.Seal.Vout, 99000, script)
	tx.TxIn[0].PreviousOutPoint = *wire.NewOutPoint(ptr(prevA.TxHash()), 0)
	tx.TxIn[1].PreviousOutPoint = *wire.NewOutPoint(ptr(prevB.TxHash()), r.Draft.Seal.Vout)
	r.Draft = withSeal(t, f, prevB.TxHash().String())
	r.ToSign = []SigningDigest{digestSigner("landlord", r.Draft.IssuerKey, PurposeContract, r.Draft.ContractSHA256)}
	return &spendFixture{r: r, tx: tx, prevs: []*wire.MsgTx{prevA, prevB}, script: script}
}

// raw encodes the fixture as tx_hex with one prevout per input; prevTxs
// attaches the full previous transaction to each prevout.
func (x *spendFixture) raw(t *testing.T, amounts []int64, prevTxs bool) KeychainSignRequest {
	t.Helper()
	var b bytes.Buffer
	if err := x.tx.SerializeNoWitness(&b); err != nil {
		t.Fatal(err)
	}
	spend := SealSpend{TxHex: hex.EncodeToString(b.Bytes()), InputIndex: 1}
	for i := range x.tx.TxIn {
		po := Prevout{ScriptHex: hex.EncodeToString(x.script), AmountSat: amounts[i]}
		if prevTxs {
			po.PrevTxHex = txHex(t, x.prevs[i])
		}
		spend.Prevouts = append(spend.Prevouts, po)
	}
	r := x.r
	r.SealSpend = &spend
	return r
}

// psbt encodes the fixture as a PSBT with each input's full previous tx.
func (x *spendFixture) psbt(t *testing.T, edit func(*psbt.Packet)) KeychainSignRequest {
	t.Helper()
	p, err := psbt.NewFromUnsignedTx(x.tx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range p.Inputs {
		p.Inputs[i].NonWitnessUtxo = x.prevs[i]
	}
	if edit != nil {
		edit(p)
	}
	var b bytes.Buffer
	if err := p.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	r := x.r
	r.SealSpend = &SealSpend{PSBT: base64.StdEncoding.EncodeToString(b.Bytes()), InputIndex: 1}
	return r
}

// Claim: a seal spend that repeats an outpoint is refused with
// SEAL_SPEND_DUPLICATE_INPUT before anything is shown or any secret is read,
// in both encodings, whether the repeated outpoint is the signed seal input
// (whose value would otherwise be counted twice to fund 198000 sat of
// outputs) or another input; the neighbour that differs only by making the
// third input a distinct outpoint of the same value signs (positive
// control), so the refusal is about uniqueness, not about a third input or
// the amounts.
func TestSealSpendRefusesDuplicateInputs(t *testing.T) {
	f := preparedFlow(t)
	build := func(t *testing.T, third func(*spendFixture) (wire.OutPoint, *wire.MsgTx)) (*spendFixture, []int64) {
		x := newSpendFixture(t, f)
		op, prev := third(x)
		x.tx.AddTxIn(wire.NewTxIn(&op, nil, nil))
		x.tx.AddTxOut(wire.NewTxOut(99000, x.script))
		x.prevs = append(x.prevs, prev)
		return x, []int64{1000, 99000, 99000}
	}
	cases := []struct {
		name, want string
		third      func(x *spendFixture) (wire.OutPoint, *wire.MsgTx)
	}{
		{"seal-input-repeated", "SEAL_SPEND_DUPLICATE_INPUT", func(x *spendFixture) (wire.OutPoint, *wire.MsgTx) {
			return x.tx.TxIn[1].PreviousOutPoint, x.prevs[1]
		}},
		{"other-input-repeated", "SEAL_SPEND_DUPLICATE_INPUT", func(x *spendFixture) (wire.OutPoint, *wire.MsgTx) {
			return x.tx.TxIn[0].PreviousOutPoint, x.prevs[0]
		}},
		{"distinct-neighbour", "", func(x *spendFixture) (wire.OutPoint, *wire.MsgTx) {
			c := prevTx(2, 0, 99000, x.script)
			return *wire.NewOutPoint(ptr(c.TxHash()), 0), c
		}},
	}
	for _, c := range cases {
		for _, enc := range []string{"raw", "psbt"} {
			t.Run(c.name+"/"+enc, func(t *testing.T) {
				x, amounts := build(t, c.third)
				if c.name == "other-input-repeated" {
					amounts[2] = 1000
					x.tx.TxOut[2].Value = 1000
				}
				var r KeychainSignRequest
				if enc == "raw" {
					r = x.raw(t, amounts, false)
				} else {
					r = x.psbt(t, nil)
				}
				h := newKC(t, confirmWord)
				e, code := h.sign(r)
				if c.want == "" {
					mustOK(t, e, code)
					if h.count("show") != 1 || h.count("secret:") != 2 {
						t.Fatalf("positive control: %v", h.log)
					}
					return
				}
				mustRefuse(t, e, code, c.want)
				if h.count("show") != 0 || h.count("secret:") != 0 {
					t.Fatalf("duplicate input reached the display or the key: %v", h.log)
				}
			})
		}
	}
}

// Claim: when a full previous transaction is given for a prevout — raw
// prev_tx_hex, or a PSBT witness UTXO beside the full previous tx — a
// supplied amount or script that disagrees with that transaction's output,
// or a transaction that does not hash to the input's txid, is refused with
// SEAL_SPEND_PREVOUTS before display or key read; the same requests with
// agreeing data sign (positive controls), and the display then says the
// amounts come from the previous transactions.
func TestSealSpendPrevoutMatchesPreviousTx(t *testing.T) {
	f := preparedFlow(t)
	refuse := func(t *testing.T, r KeychainSignRequest) {
		t.Helper()
		h := newKC(t, confirmWord)
		e, code := h.sign(r)
		mustRefuse(t, e, code, "SEAL_SPEND_PREVOUTS")
		if h.count("show") != 0 || h.count("secret:") != 0 {
			t.Fatalf("refused prevout reached the display or the key: %v", h.log)
		}
	}
	accept := func(t *testing.T, r KeychainSignRequest) {
		t.Helper()
		h := newKC(t, confirmWord)
		e, code := h.sign(r)
		mustOK(t, e, code)
		shown := h.term.shown.String()
		if !strings.Contains(shown, "txids verified") || strings.Count(shown, "(amount from previous tx)") != 2 {
			t.Fatalf("verified amounts not shown:\n%s", shown)
		}
	}
	t.Run("raw-agreeing", func(t *testing.T) { accept(t, newSpendFixture(t, f).raw(t, []int64{1000, 99000}, true)) })
	t.Run("raw-amount-disagrees", func(t *testing.T) { refuse(t, newSpendFixture(t, f).raw(t, []int64{1000, 98999}, true)) })
	t.Run("raw-other-input-amount-disagrees", func(t *testing.T) { refuse(t, newSpendFixture(t, f).raw(t, []int64{1001, 99000}, true)) })
	t.Run("raw-script-disagrees", func(t *testing.T) {
		x := newSpendFixture(t, f)
		x.prevs[0] = prevTx(0, 0, 1000, []byte{txscript.OP_TRUE})
		x.tx.TxIn[0].PreviousOutPoint = *wire.NewOutPoint(ptr(x.prevs[0].TxHash()), 0)
		refuse(t, x.raw(t, []int64{1000, 99000}, true))
	})
	t.Run("raw-prev-tx-not-the-outpoint", func(t *testing.T) {
		x := newSpendFixture(t, f)
		r := x.raw(t, []int64{1000, 99000}, true)
		r.SealSpend.Prevouts[0].PrevTxHex = txHex(t, prevTx(9, 0, 1000, x.script))
		refuse(t, r)
	})
	t.Run("psbt-witness-utxo-agrees", func(t *testing.T) {
		x := newSpendFixture(t, f)
		accept(t, x.psbt(t, func(p *psbt.Packet) { p.Inputs[1].WitnessUtxo = wire.NewTxOut(99000, x.script) }))
	})
	t.Run("psbt-witness-utxo-amount-disagrees", func(t *testing.T) {
		x := newSpendFixture(t, f)
		refuse(t, x.psbt(t, func(p *psbt.Packet) { p.Inputs[1].WitnessUtxo = wire.NewTxOut(199000, x.script) }))
	})
	t.Run("psbt-witness-utxo-script-disagrees", func(t *testing.T) {
		x := newSpendFixture(t, f)
		refuse(t, x.psbt(t, func(p *psbt.Packet) { p.Inputs[0].WitnessUtxo = wire.NewTxOut(1000, []byte{txscript.OP_TRUE}) }))
	})
}

// Claim: the approval display, produced by the production renderer through
// the CLI, carries every field the legacy SIGHASH_ALL digest commits to,
// derived here from the transaction itself: the version, each input's
// outpoint together with its own sequence, the signed input's prevout
// script, each output's value and script, the locktime and the sighash type
// — plus each prevout's amount and script. The fixture uses version 3,
// distinct non-final sequences, distinct prevout scripts and a non-zero
// locktime, so a display that dropped or swapped any of them fails.
func TestSealDisplayCoversEverySighashField(t *testing.T) {
	f := preparedFlow(t)
	x := newSpendFixture(t, f)
	x.tx.Version = 3
	x.tx.TxIn[0].Sequence = 144
	x.tx.TxIn[1].Sequence = 0xfffffffd
	x.tx.LockTime = 500123
	otherScript := p2pkhScript(make([]byte, 33))
	r := x.raw(t, []int64{1000, 99000}, false)
	r.SealSpend.Prevouts[0].ScriptHex = hex.EncodeToString(otherScript)
	prevScripts := [][]byte{otherScript, x.script}
	h := newKC(t, confirmWord)
	e, code := h.sign(r)
	mustOK(t, e, code)
	shown := h.term.shown.String()
	want := []string{
		fmt.Sprintf("unsigned txid    : %s\n", x.tx.TxHash()),
		fmt.Sprintf("version          : %d\n", x.tx.Version),
		fmt.Sprintf("locktime         : %d\n", x.tx.LockTime),
		"sighash type     : SIGHASH_ALL (0x01)\n",
		fmt.Sprintf("sighash          : %s\n", resultAs[KeychainSignResult](t, e).SealSpend.Sighash),
	}
	for i, in := range x.tx.TxIn {
		want = append(want,
			fmt.Sprintf("input %-3d        : %s:%d  sequence %d (0x%08x)", i, in.PreviousOutPoint.Hash, in.PreviousOutPoint.Index, in.Sequence, in.Sequence),
			fmt.Sprintf("    prevout        : %d sat (amount as supplied)", r.SealSpend.Prevouts[i].AmountSat),
			fmt.Sprintf("    prevout script : %x\n", prevScripts[i]))
	}
	for i, out := range x.tx.TxOut {
		want = append(want, fmt.Sprintf("output %-3d       : %d sat  ", i, out.Value), fmt.Sprintf("output %-3d       : %d sat  %s\n    script         : %x\n", i, out.Value, describeScript(out.PkScript, r.Draft.Network), out.PkScript))
	}
	for _, w := range want {
		if !strings.Contains(shown, w) {
			t.Fatalf("display lacks %q:\n%s", w, shown)
		}
	}
	// The display is a function of the sequences: changing one changes it.
	x.tx.TxIn[0].Sequence = 145
	r2 := x.raw(t, []int64{1000, 99000}, false)
	r2.SealSpend.Prevouts[0].ScriptHex = hex.EncodeToString(otherScript)
	h2 := newKC(t, confirmWord)
	e, code = h2.sign(r2)
	mustOK(t, e, code)
	if !strings.Contains(h2.term.shown.String(), "sequence 145 (0x00000091)") || strings.Contains(h2.term.shown.String(), "sequence 144 ") {
		t.Fatal("display does not follow the input sequence")
	}
}
