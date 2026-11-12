package registration

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var (
	ErrPSBT      = errors.New("registration PSBT refused")
	ErrSignature = errors.New("registration signature refused")
)

// VerifiedTransaction reports public cryptographic facts only. It proves no
// signer identity, owner presence, protected journal state or release authority.
type VerifiedTransaction struct {
	Hex, TxID, SignedPSBTSHA256 string
	VSize, Weight               uint32
	FeeAtoms                    uint64
}

type psbtMap map[string][]byte
type psbtPacket struct {
	global          psbtMap
	inputs, outputs []psbtMap
	tx              *wire.MsgTx
	raw             []byte
}

func readPSBT(text string) (*psbtPacket, error) {
	const limit = 4 << 20
	if len(text) == 0 || len(text) > base64.StdEncoding.EncodedLen(limit) {
		return nil, ErrPSBT
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(text)
	if e != nil || len(raw) > limit || base64.StdEncoding.EncodeToString(raw) != text || len(raw) < 6 || !bytes.Equal(raw[:5], []byte("psbt\xff")) {
		return nil, ErrPSBT
	}
	r := bytes.NewReader(raw[5:])
	readMap := func() (psbtMap, error) {
		m := psbtMap{}
		for {
			k, e := wire.ReadVarBytes(r, 0, limit, "PSBT key")
			if e != nil {
				return nil, ErrPSBT
			}
			if len(k) == 0 {
				return m, nil
			}
			v, e := wire.ReadVarBytes(r, 0, limit, "PSBT value")
			if e != nil {
				return nil, ErrPSBT
			}
			if _, ok := m[string(k)]; ok {
				return nil, ErrPSBT
			}
			m[string(k)] = v
		}
	}
	g, e := readMap()
	if e != nil {
		return nil, e
	}
	body, ok := g[string([]byte{0})]
	if !ok {
		return nil, ErrPSBT
	}
	tx, e := parseTx(hex.EncodeToString(body))
	if e != nil || tx.HasWitness() || txHex(tx) != hex.EncodeToString(body) || len(tx.TxIn) > 128 || len(tx.TxOut) > 128 {
		return nil, ErrPSBT
	}
	for _, in := range tx.TxIn {
		if len(in.SignatureScript) != 0 {
			return nil, ErrPSBT
		}
	}
	p := &psbtPacket{global: g, tx: tx, raw: raw}
	for i := 0; i < len(tx.TxIn)+len(tx.TxOut); i++ {
		m, e := readMap()
		if e != nil {
			return nil, e
		}
		if i < len(tx.TxIn) {
			p.inputs = append(p.inputs, m)
		} else {
			p.outputs = append(p.outputs, m)
		}
	}
	if r.Len() != 0 {
		return nil, ErrPSBT
	}
	return p, nil
}

// selected accepts only immutable plans produced for this exact public pin and
// trusted profile. A caller-supplied manifest cannot replace construction.
func (p *Planner) selected(plan *Plan, slot string) (*psbtPacket, PreparedTransaction, error) {
	if p == nil || plan == nil {
		return nil, PreparedTransaction{}, ErrPSBT
	}
	var binding struct {
		planBase
		Policy Policy `json:"policy"`
	}
	if json.Unmarshal(plan.raw, &binding) != nil || binding.planBase != p.base(binding.Kind) || binding.Policy != p.profile.Policy {
		return nil, PreparedTransaction{}, ErrPSBT
	}
	for _, tx := range plan.transactions {
		if tx.Slot == slot {
			x, e := readPSBT(tx.PSBT)
			return x, tx, e
		}
	}
	return nil, PreparedTransaction{}, ErrPSBT
}

// pathBytes is used only for previously validated public derivation paths.
func (p *Planner) pathBytes(path string) []byte {
	b, _ := hex.DecodeString(p.pin.MasterFingerprint)
	for _, part := range strings.Split(path, "/")[1:] {
		n, _ := strconv.ParseUint(strings.TrimSuffix(part, "h"), 10, 31)
		if strings.HasSuffix(part, "h") {
			n |= 1 << 31
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(n))
	}
	return b
}

func equalMap(a, b psbtMap) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}

// unsignedMaps is a positive allowlist of required builder entries and the
// optional BIP174 forms admitted by the signing contract. It never drops maps.
func (p *Planner) unsignedMaps(base, candidate *psbtPacket, slot string) error {
	if len(base.inputs) != len(candidate.inputs) || len(base.outputs) != len(candidate.outputs) {
		return ErrPSBT
	}
	allowedGlobal := psbtMap{string([]byte{0}): base.global[string([]byte{0})], string([]byte{0xfb}): {0, 0, 0, 0}}
	xpub := base58.Decode(p.pin.AccountXPub)
	allowedGlobal[string(append([]byte{1}, xpub[:78]...))] = p.pathBytes(p.pin.AccountPath)
	for k, v := range candidate.global {
		w, ok := allowedGlobal[k]
		if !ok || !bytes.Equal(v, w) {
			return ErrPSBT
		}
	}
	if !bytes.Equal(candidate.global[string([]byte{0})], base.global[string([]byte{0})]) {
		return ErrPSBT
	}
	for i, m := range candidate.inputs {
		allowed := psbtMap{string([]byte{3}): {1, 0, 0, 0}}
		for k, v := range base.inputs[i] {
			allowed[k] = v
		}
		// The confirmed funding transaction may retain its original witness.
		// Future graph parents use the agreed stripped serialization. In both
		// cases the complete non-witness body, hence every output, is fixed.
		if slot == "A" {
			if body, ok := m[string([]byte{0})]; ok {
				previous, err := parseTx(hex.EncodeToString(body))
				if err != nil || txHex(previous) != hex.EncodeToString(base.inputs[i][string([]byte{0})]) {
					return ErrPSBT
				}
				allowed[string([]byte{0})] = body
			}
		}
		for k, v := range m {
			w, ok := allowed[k]
			if !ok || !bytes.Equal(v, w) {
				return ErrPSBT
			}
		}
		for k := range base.inputs[i] {
			v := allowed[k]
			if k != string([]byte{1}) && !bytes.Equal(m[k], v) {
				return ErrPSBT
			}
		}
	}
	for i, m := range candidate.outputs {
		if !equalMap(m, base.outputs[i]) {
			return ErrPSBT
		}
	}
	return nil
}

// ValidateUnsigned validates the complete signing input against a constructed
// plan, including mandatory full prevouts and exact public owned derivations.
func (p *Planner) ValidateUnsigned(plan *Plan, slot, unsigned string) error {
	base, _, e := p.selected(plan, slot)
	if e != nil {
		return e
	}
	candidate, e := readPSBT(unsigned)
	if e != nil {
		return e
	}
	return p.unsignedMaps(base, candidate, slot)
}

// VerifySigned permits only one new partial signature per input, retaining all
// original map values. It verifies strict DER, low-S, ALL signatures against
// the complete prevouts and assembles witnesses without invoking a signer.
func (p *Planner) VerifySigned(plan *Plan, slot, unsigned, signed string) (*VerifiedTransaction, error) {
	base, prepared, e := p.selected(plan, slot)
	if e != nil {
		return nil, e
	}
	u, e := readPSBT(unsigned)
	if e != nil {
		return nil, e
	}
	if e = p.unsignedMaps(base, u, slot); e != nil {
		return nil, e
	}
	s, e := readPSBT(signed)
	if e != nil {
		return nil, e
	}
	if !equalMap(s.global, u.global) || len(s.inputs) != len(u.inputs) || len(s.outputs) != len(u.outputs) {
		return nil, ErrPSBT
	}
	for i, m := range s.outputs {
		if !equalMap(m, u.outputs[i]) {
			return nil, ErrPSBT
		}
	}
	pubs, sigs := make([][]byte, len(s.inputs)), make([][]byte, len(s.inputs))
	prevs := make([]*wire.TxOut, len(s.inputs))
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	total := uint64(0)
	for i, m := range s.inputs {
		for k := range u.inputs[i] {
			if k[0] == 6 {
				pubs[i] = []byte(k)[1:]
			}
		}
		remaining := psbtMap{}
		for k, v := range m {
			if k[0] == 2 {
				if !bytes.Equal([]byte(k)[1:], pubs[i]) || sigs[i] != nil {
					return nil, ErrSignature
				}
				sigs[i] = v
			} else {
				remaining[k] = v
			}
		}
		if !equalMap(remaining, u.inputs[i]) {
			return nil, ErrPSBT
		}
		if len(sigs[i]) < 9 || len(sigs[i]) > 72 || sigs[i][len(sigs[i])-1] != byte(txscript.SigHashAll) {
			return nil, ErrSignature
		}
		prev, e := parseTx(hex.EncodeToString(m[string([]byte{0})]))
		outpoint := s.tx.TxIn[i].PreviousOutPoint
		if e != nil || prev.TxHash() != outpoint.Hash || uint64(outpoint.Index) >= uint64(len(prev.TxOut)) {
			return nil, ErrPSBT
		}
		out := prev.TxOut[outpoint.Index]
		if sumOver(total, uint64(out.Value), maxMoney) {
			return nil, ErrPSBT
		}
		total += uint64(out.Value)
		prevs[i] = out
		fetcher.AddPrevOut(outpoint, out)
	}
	hashes := txscript.NewTxSigHashes(s.tx, fetcher)
	for i, sigBytes := range sigs {
		script, e := spendScript(prevs[i].PkScript)
		if e != nil {
			return nil, ErrPSBT
		}
		hash, e := txscript.CalcWitnessSigHash(script, hashes, txscript.SigHashAll, s.tx, i, prevs[i].Value)
		if e != nil {
			return nil, ErrSignature
		}
		der := sigBytes[:len(sigBytes)-1]
		sig, e := ecdsa.ParseDERSignature(der)
		if e != nil || !bytes.Equal(sig.Serialize(), der) {
			return nil, ErrSignature
		}
		pub, e := btcec.ParsePubKey(pubs[i])
		if e != nil || !sig.Verify(hash, pub) {
			return nil, ErrSignature
		}
		s.tx.TxIn[i].Witness = wire.TxWitness{sigBytes, pubs[i]}
	}
	for _, out := range s.tx.TxOut {
		if uint64(out.Value) > total {
			return nil, ErrPolicy
		}
		total -= uint64(out.Value)
	}
	weight := uint32(3*s.tx.SerializeSizeStripped() + s.tx.SerializeSize())
	vsize := (weight + 3) / 4
	scaled, ok := mul(total, 1000)
	lower, lok := mul(p.minRate, uint64(vsize))
	upper, uok := mul(p.maxRate, uint64(vsize))
	if !ok || !lok || !uok || total > p.perCap || scaled < lower || scaled > upper || vsize < prepared.SignedVSizeMin || vsize > prepared.SignedVSizeMax || s.tx.TxHash().String() != prepared.TxID {
		return nil, ErrPolicy
	}
	var final bytes.Buffer
	if s.tx.Serialize(&final) != nil {
		return nil, ErrPSBT
	}
	return &VerifiedTransaction{Hex: hex.EncodeToString(final.Bytes()), TxID: prepared.TxID, SignedPSBTSHA256: digest(s.raw), VSize: vsize, Weight: weight, FeeAtoms: total}, nil
}
