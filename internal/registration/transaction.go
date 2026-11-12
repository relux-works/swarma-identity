package registration

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strconv"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (p *Planner) transaction(slot string, inputs []planInput, namePath, changePath string, prefix []byte, fee uint64) (planTransaction, PreparedTransaction, error) {
	bad := func(e error) (planTransaction, PreparedTransaction, error) {
		return planTransaction{}, PreparedTransaction{}, e
	}
	if len(inputs) < 1 || len(inputs) > 2 {
		return bad(ErrInput)
	}
	if fee > p.perCap {
		return bad(ErrPolicy)
	}
	tx := wire.NewMsgTx(0x7100)
	previous := make([]*wire.MsgTx, len(inputs))
	total := uint64(0)
	seen := map[string]bool{}
	for i, in := range inputs {
		prev, e := parseTx(in.PrevTxHex)
		if e != nil || prev.TxHash().String() != in.TxID || int64(in.Vout) >= int64(len(prev.TxOut)) {
			return bad(ErrFunding)
		}
		outpoint := in.TxID + ":" + strconv.FormatUint(uint64(in.Vout), 10)
		if seen[outpoint] {
			return bad(ErrFunding)
		}
		seen[outpoint] = true
		_, owned, e := p.derive(in.Path)
		if e != nil {
			return bad(e)
		}
		output := prev.TxOut[in.Vout]
		underlying, e := spendScript(output.PkScript)
		if e != nil || !bytes.Equal(underlying, owned) || output.Value < 0 || sumOver(total, uint64(output.Value), maxMoney) {
			return bad(ErrFunding)
		}
		total += uint64(output.Value)
		previous[i] = prev
		hash := prev.TxHash()
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&hash, in.Vout), nil, nil))
	}
	_, nameScript, e := p.derive(namePath)
	if e != nil {
		return bad(e)
	}
	_, changeScript, e := p.derive(changePath)
	if e != nil {
		return bad(e)
	}
	if sumOver(nameAmount, fee, total) || total-nameAmount-fee == 0 {
		return bad(ErrFunding)
	}
	tx.AddTxOut(wire.NewTxOut(int64(nameAmount), append(append([]byte{}, prefix...), nameScript...)))
	tx.AddTxOut(wire.NewTxOut(int64(total-nameAmount-fee), changeScript))
	for _, out := range tx.TxOut {
		// Core nc28.0 GetDustThreshold uses full serialized output size plus
		// 67 witness spend bytes, including for a name-prefixed witness output.
		product, ok := mul(uint64(out.SerializeSize()+67), p.dustRate)
		if !ok {
			return bad(ErrPolicy)
		}
		threshold := product / 1000
		if product%1000 != 0 {
			threshold++
		}
		if uint64(out.Value) < threshold {
			return bad(ErrPolicy)
		}
	}
	// Strict DER low-S plus the ALL byte occupies 9..72 bytes; the compressed
	// key is fixed at33. These conservative intervals are not actual final size.
	stripped := tx.SerializeSizeStripped()
	minSize := (4*stripped + 2 + 45*len(inputs) + 3) / 4
	maxSize := (4*stripped + 2 + 108*len(inputs) + 3) / 4
	feeScaled, ok := mul(fee, 1000)
	if !ok {
		return bad(ErrPolicy)
	}
	lower, ok := mul(p.minRate, uint64(maxSize))
	if !ok || feeScaled < lower {
		return bad(ErrPolicy)
	}
	upper, ok := mul(p.maxRate, uint64(minSize))
	if !ok || feeScaled > upper {
		return bad(ErrPolicy)
	}
	hexTx := txHex(tx)
	id := tx.TxHash().String()
	model := planTransaction{slot, hexTx, id, append([]planInput(nil), inputs...), []planOutput{{0, namePath, "name"}, {1, changePath, "change"}}, strconv.FormatUint(fee, 10)}
	psbt, e := p.psbt(tx, model, previous)
	if e != nil {
		return bad(e)
	}
	return model, PreparedTransaction{Slot: slot, UnsignedTxHex: hexTx, TxID: id, PSBT: psbt, UnsignedVSize: uint32(stripped), SignedVSizeMin: uint32(minSize), SignedVSizeMax: uint32(maxSize)}, nil
}

// spendScript admits exactly the native witness scripts emitted by this builder,
// with canonical name_new or name_firstupdate prefixes. Arbitrary prefixes do
// not become owned outputs merely because their last22 bytes match a key.
func spendScript(script []byte) ([]byte, error) {
	if len(script) == 22 && script[0] == 0 && script[1] == 20 {
		return script, nil
	}
	if len(script) < 23 {
		return nil, ErrFunding
	}
	t := txscript.MakeScriptTokenizer(0, script)
	if !t.Next() {
		return nil, ErrFunding
	}
	op := t.Opcode()
	builder := txscript.NewScriptBuilder()
	switch op {
	case txscript.OP_1:
		if !t.Next() || len(t.Data()) != 20 {
			return nil, ErrFunding
		}
		builder.AddOp(op).AddData(t.Data())
		if !t.Next() || t.Opcode() != txscript.OP_2DROP {
			return nil, ErrFunding
		}
		builder.AddOp(txscript.OP_2DROP)
	case txscript.OP_2:
		builder.AddOp(op)
		for i := range 3 {
			if !t.Next() {
				return nil, ErrFunding
			}
			d := t.Data()
			if (i == 0 && (len(d) == 0 || len(d) > 255)) || (i == 1 && len(d) != 20) || (i == 2 && !valueBytes(d)) {
				return nil, ErrFunding
			}
			builder.AddData(d)
		}
		for range 2 {
			if !t.Next() || t.Opcode() != txscript.OP_2DROP {
				return nil, ErrFunding
			}
			builder.AddOp(txscript.OP_2DROP)
		}
	default:
		return nil, ErrFunding
	}
	prefix, e := builder.Script()
	if e != nil || int(t.ByteIndex()) != len(prefix) || !bytes.Equal(script[:len(prefix)], prefix) {
		return nil, ErrFunding
	}
	rest := script[len(prefix):]
	if len(rest) != 22 || rest[0] != 0 || rest[1] != 20 {
		return nil, ErrFunding
	}
	return rest, nil
}

// psbt writes only the positive BIP174 subset used by the pinned Core builder.
// It adds complete parent bodies, matching witness UTXOs and public derivations;
// it neither parses caller PSBTs nor signs, finalizes or drops unknown map data.
func (p *Planner) psbt(tx *wire.MsgTx, model planTransaction, previous []*wire.MsgTx) (string, error) {
	var b bytes.Buffer
	b.WriteString("psbt\xff")
	kv := func(key, value []byte) { _ = wire.WriteVarBytes(&b, 0, key); _ = wire.WriteVarBytes(&b, 0, value) }
	var raw bytes.Buffer
	_ = tx.SerializeNoWitness(&raw)
	kv([]byte{0}, raw.Bytes())
	b.WriteByte(0)
	fp, _ := hex.DecodeString(p.pin.MasterFingerprint)
	derivation := func(path string) []byte {
		parts := stringsParts(path)
		v := append([]byte{}, fp...)
		for _, n := range parts {
			v = binary.LittleEndian.AppendUint32(v, n)
		}
		return v
	}
	for i, in := range model.Inputs {
		prev, _ := hex.DecodeString(in.PrevTxHex)
		kv([]byte{0}, prev)
		out := previous[i].TxOut[in.Vout]
		var utxo bytes.Buffer
		_ = binary.Write(&utxo, binary.LittleEndian, out.Value)
		_ = wire.WriteVarBytes(&utxo, 0, out.PkScript)
		kv([]byte{1}, utxo.Bytes())
		pub, _, e := p.derive(in.Path)
		if e != nil {
			return "", e
		}
		kv(append([]byte{6}, pub...), derivation(in.Path))
		b.WriteByte(0)
	}
	for _, out := range model.Outputs {
		pub, _, e := p.derive(out.Path)
		if e != nil {
			return "", e
		}
		kv(append([]byte{2}, pub...), derivation(out.Path))
		b.WriteByte(0)
	}
	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// Paths have already been validated by derive before serialization.
func stringsParts(path string) []uint32 {
	parts := []uint32{84 | 1<<31, 7 | 1<<31, 1 << 31}
	start := len("m/84h/7h/0h/")
	branch := uint32(path[start] - '0')
	index, _ := strconv.ParseUint(path[start+2:], 10, 31)
	return append(parts, branch, uint32(index))
}
