package facade

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// SealSpend is the unsigned spend of the grant's P2PKH seal outpoint: either
// a raw unsigned transaction with one prevout (script and amount, optionally
// the full previous transaction) per input, or a PSBT whose every input
// carries its full previous transaction.
type SealSpend struct {
	TxHex      string    `json:"tx_hex,omitempty"`
	PSBT       string    `json:"psbt_b64,omitempty"`
	InputIndex uint32    `json:"input_index"`
	Prevouts   []Prevout `json:"prevouts,omitempty"`
}

type Prevout struct {
	ScriptHex string `json:"script_hex"`
	AmountSat int64  `json:"amount_sat"`
	// PrevTxHex, when given, is the full previous transaction; it must hash
	// to the input's txid and its output must carry exactly ScriptHex and
	// AmountSat.
	PrevTxHex string `json:"prev_tx_hex,omitempty"`
}

type plannedPrevout struct {
	script   []byte
	amount   int64
	shown    string
	verified bool // amount and script read from a full previous tx whose txid matched
}

type sealSpendPlan struct {
	tx           *wire.MsgTx
	index        uint32
	prevouts     []plannedPrevout
	outputs      []string
	totalIn      int64
	totalOut     int64
	sighash      []byte
	amountSource string
}

// describeScript names a standard destination; anything else is shown as hex.
func describeScript(script []byte, network string) string {
	params, _ := networkParams(network)
	class, addrs, _, err := txscript.ExtractPkScriptAddrs(script, params)
	if err == nil && len(addrs) == 1 {
		switch class {
		case txscript.PubKeyHashTy, txscript.WitnessV0PubKeyHashTy, txscript.WitnessV0ScriptHashTy, txscript.WitnessV1TaprootTy:
			return fmt.Sprintf("%s %s", class, addrs[0].EncodeAddress())
		}
	}
	return fmt.Sprintf("%s script %x", class, script)
}

func p2pkhScript(compressed []byte) []byte {
	s, _ := txscript.NewScriptBuilder().AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(btcutil.Hash160(compressed)).AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG).Script()
	return s
}

func amountValid(v int64) bool { return v >= 0 && v <= maxMoneySat }

// planSealSpend checks the spend and computes its legacy SIGHASH_ALL digest.
// The signed input must be the draft's seal outpoint and pay to P2PKH of the
// stored key; the transaction must be unsigned and must not create value.
func planSealSpend(s SealSpend, d GrantDraft, storedPub []byte, network string) (*sealSpendPlan, *Failure) {
	p := &sealSpendPlan{index: s.InputIndex, tx: wire.NewMsgTx(wire.TxVersion)}
	switch {
	case s.TxHex != "" && s.PSBT == "":
		raw, err := hex.DecodeString(s.TxHex)
		if err != nil || hex.EncodeToString(raw) != s.TxHex || p.tx.DeserializeNoWitness(bytes.NewReader(raw)) != nil {
			return nil, keychainRefuse("SEAL_SPEND_ENCODING")
		}
		var again bytes.Buffer
		if p.tx.SerializeNoWitness(&again) != nil || !bytes.Equal(again.Bytes(), raw) {
			return nil, keychainRefuse("SEAL_SPEND_ENCODING")
		}
		if len(s.Prevouts) != len(p.tx.TxIn) {
			return nil, keychainRefuse("SEAL_SPEND_PREVOUTS")
		}
		verified := 0
		for i, po := range s.Prevouts {
			script, err := hex.DecodeString(po.ScriptHex)
			if err != nil || hex.EncodeToString(script) != po.ScriptHex || len(script) == 0 || !amountValid(po.AmountSat) {
				return nil, keychainRefuse("SEAL_SPEND_PREVOUTS")
			}
			planned := plannedPrevout{script: script, amount: po.AmountSat}
			if po.PrevTxHex != "" {
				out, ok := prevTxOutput(po.PrevTxHex, p.tx.TxIn[i].PreviousOutPoint)
				if !ok || out.Value != po.AmountSat || !bytes.Equal(out.PkScript, script) {
					return nil, keychainRefuse("SEAL_SPEND_PREVOUTS")
				}
				planned.verified = true
				verified++
			}
			p.prevouts = append(p.prevouts, planned)
		}
		p.amountSource = "as supplied in the request (a legacy sighash does not commit to amounts; check them)"
		if verified == len(p.prevouts) {
			p.amountSource = "from the full previous transactions in the request (txids verified)"
		}
	case s.PSBT != "" && s.TxHex == "" && s.Prevouts == nil:
		raw, err := base64.StdEncoding.Strict().DecodeString(s.PSBT)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != s.PSBT {
			return nil, keychainRefuse("SEAL_SPEND_ENCODING")
		}
		packet, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
		if err != nil || packet.UnsignedTx == nil {
			return nil, keychainRefuse("SEAL_SPEND_ENCODING")
		}
		p.tx = packet.UnsignedTx
		for i, in := range packet.Inputs {
			prev := in.NonWitnessUtxo
			op := p.tx.TxIn[i].PreviousOutPoint
			if prev == nil || prev.TxHash() != op.Hash || int(op.Index) >= len(prev.TxOut) || len(in.PartialSigs) != 0 || in.FinalScriptSig != nil || in.FinalScriptWitness != nil {
				return nil, keychainRefuse("SEAL_SPEND_PREVOUTS")
			}
			out := prev.TxOut[op.Index]
			if !amountValid(out.Value) || len(out.PkScript) == 0 {
				return nil, keychainRefuse("SEAL_SPEND_PREVOUTS")
			}
			// A witness UTXO is a second statement of the same prevout; it
			// must agree with the full previous transaction.
			if w := in.WitnessUtxo; w != nil && (w.Value != out.Value || !bytes.Equal(w.PkScript, out.PkScript)) {
				return nil, keychainRefuse("SEAL_SPEND_PREVOUTS")
			}
			p.prevouts = append(p.prevouts, plannedPrevout{script: out.PkScript, amount: out.Value, verified: true})
		}
		p.amountSource = "from the full previous transactions in the PSBT (txids verified)"
	default:
		return nil, fail("BAD_INPUT")
	}
	if len(p.tx.TxIn) == 0 || len(p.tx.TxOut) == 0 || int(s.InputIndex) >= len(p.tx.TxIn) || len(p.prevouts) != len(p.tx.TxIn) {
		return nil, keychainRefuse("SEAL_SPEND_SHAPE")
	}
	// An outpoint can be spent once. A repeated input would count its value
	// twice below and makes the transaction invalid, so it is refused before
	// any amount is summed or anything is shown.
	spent := make(map[wire.OutPoint]bool, len(p.tx.TxIn))
	for _, in := range p.tx.TxIn {
		if spent[in.PreviousOutPoint] {
			return nil, keychainRefuse("SEAL_SPEND_DUPLICATE_INPUT")
		}
		spent[in.PreviousOutPoint] = true
	}
	for _, in := range p.tx.TxIn {
		if len(in.SignatureScript) != 0 || len(in.Witness) != 0 {
			return nil, keychainRefuse("SEAL_SPEND_SIGNED")
		}
	}
	op := p.tx.TxIn[s.InputIndex].PreviousOutPoint
	if op.Hash.String() != d.Seal.TxID || op.Index != d.Seal.Vout {
		return nil, keychainRefuse("SEAL_OUTPOINT_MISMATCH")
	}
	if !bytes.Equal(p.prevouts[s.InputIndex].script, p2pkhScript(storedPub)) {
		return nil, keychainRefuse("SEAL_SCRIPT_MISMATCH")
	}
	for i := range p.prevouts {
		p.totalIn += p.prevouts[i].amount
		p.prevouts[i].shown = describeScript(p.prevouts[i].script, network)
		if !amountValid(p.totalIn) {
			return nil, keychainRefuse("SEAL_SPEND_AMOUNT")
		}
	}
	for _, out := range p.tx.TxOut {
		p.totalOut += out.Value
		if !amountValid(out.Value) || !amountValid(p.totalOut) {
			return nil, keychainRefuse("SEAL_SPEND_AMOUNT")
		}
		p.outputs = append(p.outputs, describeScript(out.PkScript, network))
	}
	if p.totalOut > p.totalIn {
		return nil, keychainRefuse("SEAL_SPEND_AMOUNT")
	}
	hash, err := txscript.CalcSignatureHash(p.prevouts[s.InputIndex].script, txscript.SigHashAll, p.tx, int(s.InputIndex))
	if err != nil {
		return nil, keychainRefuse("SEAL_SPEND_SHAPE")
	}
	p.sighash = hash
	return p, nil
}

// prevTxOutput decodes a full previous transaction given as canonical hex and
// returns the output op names, only when the transaction hashes to op's txid.
func prevTxOutput(txHex string, op wire.OutPoint) (*wire.TxOut, bool) {
	raw, err := hex.DecodeString(txHex)
	if err != nil || hex.EncodeToString(raw) != txHex {
		return nil, false
	}
	var prev wire.MsgTx
	if prev.Deserialize(bytes.NewReader(raw)) != nil {
		return nil, false
	}
	var again bytes.Buffer
	if prev.Serialize(&again) != nil || !bytes.Equal(again.Bytes(), raw) {
		return nil, false
	}
	if prev.TxHash() != op.Hash || int(op.Index) >= len(prev.TxOut) {
		return nil, false
	}
	return prev.TxOut[op.Index], true
}

const sighashAll = byte(txscript.SigHashAll)

// verify accepts DER || SIGHASH_ALL only when the signature is strict DER,
// low-S, verifies against the stored key over the planned sighash, and the
// completed input executes under the standard script flags.
func (p *sealSpendPlan) verify(full []byte, pub *btcec.PublicKey) bool {
	if len(full) < 9 || full[len(full)-1] != byte(txscript.SigHashAll) {
		return false
	}
	der := full[:len(full)-1]
	sig, err := ecdsa.ParseDERSignature(der)
	if err != nil || !bytes.Equal(sig.Serialize(), der) {
		return false
	}
	s := sig.S()
	if s.IsOverHalfOrder() || !sig.Verify(p.sighash, pub) {
		return false
	}
	scriptSig, err := txscript.NewScriptBuilder().AddData(full).AddData(pub.SerializeCompressed()).Script()
	if err != nil {
		return false
	}
	tx := p.tx.Copy()
	tx.TxIn[p.index].SignatureScript = scriptSig
	prev := p.prevouts[p.index]
	vm, err := txscript.NewEngine(prev.script, tx, int(p.index), txscript.StandardVerifyFlags, nil, nil, prev.amount, txscript.NewCannedPrevOutputFetcher(prev.script, prev.amount))
	return err == nil && vm.Execute() == nil
}
