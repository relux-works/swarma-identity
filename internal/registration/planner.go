package registration

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type Planner struct {
	pin                                          accountPin
	pinBytes                                     []byte
	pinHash                                      string
	key                                          *hdkeychain.ExtendedKey
	profile                                      Profile
	perCap, totalCap, minRate, maxRate, dustRate uint64
}

// NewPlanner accepts only a public account pin and separately trusted policy.
// It performs no I/O, network discovery, account lookup or private derivation.
func NewPlanner(pinBytes []byte, profile Profile) (*Planner, error) {
	fields, e := object(pinBytes, "schema", "group", "account", "account_xpub", "master_fingerprint", "account_path")
	if e != nil || len(fields) != 6 {
		return nil, ErrInput
	}
	for _, raw := range fields {
		if len(raw) == 0 || raw[0] != '"' {
			return nil, ErrInput
		}
	}
	var pin accountPin
	if json.Unmarshal(pinBytes, &pin) != nil || pin.Schema != "keyvault-namecoin-account-pin/1" || !label(pin.Group) || !label(pin.Account) || len(pin.AccountXPub) > 120 || pin.AccountPath != "m/84h/7h/0h" || !hexSize(pin.MasterFingerprint, 4) {
		return nil, ErrInput
	}
	x := base58.Decode(pin.AccountXPub)
	if len(x) != 82 || !bytes.Equal(x[:4], []byte{4, 136, 178, 30}) || x[4] != 3 || binary.BigEndian.Uint32(x[9:13]) != 1<<31 || (x[45] != 2 && x[45] != 3) {
		return nil, ErrInput
	}
	key, e := hdkeychain.NewKeyFromString(pin.AccountXPub)
	if e != nil || key.IsPrivate() {
		return nil, ErrInput
	}
	if (profile.Network != "namecoin-mainnet" || profile.Genesis != MainnetGenesis) && (profile.Network != "namecoin-regtest" || profile.Genesis != RegtestGenesis) {
		return nil, ErrPolicy
	}
	p := &Planner{pin: pin, pinBytes: append([]byte(nil), pinBytes...), pinHash: digest(pinBytes), key: key, profile: profile}
	pol := profile.Policy
	values := []string{pol.PerTxFeeCapAtoms, pol.TotalFeeCapAtoms, pol.MinFeeRateAtomsPerKVB, pol.MaxFeeRateAtomsPerKVB, pol.DustRelayFeeAtomsPerKVB}
	nums := make([]uint64, len(values))
	for i, s := range values {
		n, ok := amount(s)
		if !ok || n == 0 {
			return nil, ErrPolicy
		}
		nums[i] = n
	}
	p.perCap, p.totalCap, p.minRate, p.maxRate, p.dustRate = nums[0], nums[1], nums[2], nums[3], nums[4]
	if p.perCap > 100000 || p.totalCap > 400000 || p.minRate > p.maxRate || !label(pol.Revision) || pol.ReleaseNotAfter <= pol.CreatedAt || pol.ReleaseNotAfter-pol.CreatedAt > 86400 || pol.FinalConfirmations == 0 || (pol.ReleaseMode != "all-four-before-release" && pol.ReleaseMode != "two-stage") {
		return nil, ErrPolicy
	}
	return p, nil
}

func (p *Planner) base(kind string) planBase {
	return planBase{PlanSchema, kind, p.profile.Network, p.profile.Genesis, p.pin.Group, p.pin.Account, p.pinHash}
}
func (p *Planner) timeOK(now uint64) bool {
	return now >= p.profile.Policy.CreatedAt && now < p.profile.Policy.ReleaseNotAfter
}

func (p *Planner) Reserve(in ReservationInput, now uint64) (*Plan, error) {
	if !p.timeOK(now) {
		return nil, ErrPolicy
	}
	regs := in.Registrations
	if !validName(regs[0].Name, "id/") || !validName(regs[1].Name, "d/") || regs[0].Name[3:] != regs[1].Name[2:] || len(regs[0].FixedValue) != 0 || !valueBytes(regs[1].FixedValue) {
		return nil, ErrInput
	}
	for _, r := range regs {
		if !hexSize(r.RandHex, 20) {
			return nil, ErrInput
		}
		if _, _, e := p.derive(r.NameOutputPath); e != nil {
			return nil, e
		}
	}
	for _, path := range in.ChangePaths {
		if _, _, e := p.derive(path); e != nil {
			return nil, e
		}
	}
	prev, e := parseTx(in.Funding.TxHex)
	if e != nil || !hexSize(in.Funding.TxID, 32) || prev.TxHash().String() != in.Funding.TxID || int64(in.Funding.Vout) >= int64(len(prev.TxOut)) {
		return nil, ErrFunding
	}
	_, expected, e := p.derive(in.Funding.Path)
	if e != nil {
		return nil, e
	}
	funded := prev.TxOut[in.Funding.Vout]
	if funded.Value <= 0 || uint64(funded.Value) > maxMoney || !bytes.Equal(funded.PkScript, expected) {
		return nil, ErrFunding
	}
	full := txHex(prev)
	funding := planFunding{full, in.Funding.TxID, in.Funding.Vout}
	m := reservationManifest{planBase: p.base("reservation"), Funding: funding, Policy: p.profile.Policy}
	for i, r := range regs {
		v := futureValue{State: "pending"}
		if i == 1 {
			v = futureValue{State: "fixed", ValueHex: hex.EncodeToString(r.FixedValue), ValueSHA256: digest(r.FixedValue)}
		}
		m.Registrations = append(m.Registrations, reservedName{hex.EncodeToString([]byte(r.Name)), r.RandHex, r.NameOutputPath, string("AB"[i]), string("CD"[i]), v})
	}
	inputs := []planInput{{full, in.Funding.TxID, in.Funding.Vout, in.Funding.Path}}
	prepared := []PreparedTransaction{}
	for i, r := range regs {
		opening, _ := hex.DecodeString(r.RandHex)
		commitment := btcutil.Hash160(append(opening, []byte(r.Name)...))
		prefix, _ := txscript.NewScriptBuilder().AddOp(txscript.OP_1).AddData(commitment).AddOp(txscript.OP_2DROP).Script()
		model, tx, e := p.transaction(string("AB"[i]), inputs, r.NameOutputPath, in.ChangePaths[i], prefix, in.Fees[i])
		if e != nil {
			return nil, e
		}
		m.Transactions = append(m.Transactions, model)
		prepared = append(prepared, tx)
		inputs = []planInput{{model.UnsignedTxHex, model.UnsignedTxID, 1, in.ChangePaths[i]}}
	}
	if sumOver(in.Fees[0], in.Fees[1], p.totalCap) {
		return nil, ErrPolicy
	}
	plan, e := freeze(m, prepared)
	if e != nil {
		return nil, e
	}
	plan.reservation = &m
	return plan, nil
}

func (p *Planner) Reveal(reservation *Plan, in RevealInput, now uint64) (*Plan, error) {
	if !p.timeOK(now) {
		return nil, ErrPolicy
	}
	if reservation == nil || reservation.reservation == nil {
		return nil, ErrParents
	}
	r := reservation.reservation
	if r.planBase != p.base("reservation") || r.Policy != p.profile.Policy || len(r.Transactions) != 2 || len(r.Registrations) != 2 {
		return nil, ErrParents
	}
	for i, parent := range in.Parents {
		if parent.Slot != string("AB"[i]) || !hexSize(parent.RequestID, 32) || !hexSize(parent.SittingID, 32) || !hexSize(parent.SignedPSBTSHA256, 32) || parent.UnsignedTxID != r.Transactions[i].UnsignedTxID {
			return nil, ErrParents
		}
	}
	values, e := p.revealValues(in.ValuesPin, reservation.Hash(), r.Registrations)
	if e != nil {
		return nil, e
	}
	m := revealManifest{planBase: p.base("reveal"), ReservationPlanSHA256: reservation.Hash(), ParentResults: append([]ParentReference(nil), in.Parents[:]...), Policy: r.Policy}
	for i, n := range r.Registrations {
		m.Registrations = append(m.Registrations, concreteName{n.NameHex, hex.EncodeToString(values[i]), digest(values[i]), n.RandHex, n.NameOutputPath, n.ReservationSlot, n.RevealSlot})
	}
	priorFees := uint64(0)
	for _, tx := range r.Transactions {
		v, ok := amount(tx.FeeAtoms)
		if !ok || sumOver(priorFees, v, p.totalCap) {
			return nil, ErrPolicy
		}
		priorFees += v
	}
	if sumOver(in.Fees[0], in.Fees[1], p.totalCap) || sumOver(priorFees, in.Fees[0]+in.Fees[1], p.totalCap) {
		return nil, ErrPolicy
	}
	inputs := []planInput{{r.Transactions[0].UnsignedTxHex, r.Transactions[0].UnsignedTxID, 0, r.Registrations[0].NameOutputPath}, {r.Transactions[1].UnsignedTxHex, r.Transactions[1].UnsignedTxID, 1, r.Transactions[1].Outputs[1].Path}}
	prepared := []PreparedTransaction{}
	for i, n := range m.Registrations {
		name, _ := hex.DecodeString(n.NameHex)
		rand, _ := hex.DecodeString(n.RandHex)
		prefix, e := txscript.NewScriptBuilder().AddOp(txscript.OP_2).AddData(name).AddData(rand).AddData(values[i]).AddOp(txscript.OP_2DROP).AddOp(txscript.OP_2DROP).Script()
		if e != nil {
			return nil, ErrValue
		}
		model, tx, e := p.transaction(string("CD"[i]), inputs, n.NameOutputPath, in.ChangePaths[i], prefix, in.Fees[i])
		if e != nil {
			return nil, e
		}
		m.Transactions = append(m.Transactions, model)
		prepared = append(prepared, tx)
		inputs = []planInput{{r.Transactions[1].UnsignedTxHex, r.Transactions[1].UnsignedTxID, 0, r.Registrations[1].NameOutputPath}, {model.UnsignedTxHex, model.UnsignedTxID, 1, in.ChangePaths[i]}}
	}
	return freeze(m, prepared)
}

func (p *Planner) derive(path string) ([]byte, []byte, error) {
	parts := strings.Split(path, "/")
	if len(parts) != 6 || strings.Join(parts[:4], "/") != "m/84h/7h/0h" {
		return nil, nil, ErrInput
	}
	indices := [2]uint32{}
	for i, s := range parts[4:] {
		n, e := strconv.ParseUint(s, 10, 31)
		if e != nil || strconv.FormatUint(n, 10) != s || (i == 0 && n > 1) {
			return nil, nil, ErrInput
		}
		indices[i] = uint32(n)
	}
	branch, e := p.key.Derive(indices[0])
	if e != nil {
		return nil, nil, ErrInput
	}
	child, e := branch.Derive(indices[1])
	if e != nil {
		return nil, nil, ErrInput
	}
	pub, e := child.ECPubKey()
	if e != nil {
		return nil, nil, ErrInput
	}
	key := pub.SerializeCompressed()
	script := append([]byte{0, 20}, btcutil.Hash160(key)...)
	return key, script, nil
}

func parseTx(s string) (*wire.MsgTx, error) {
	if len(s) == 0 || len(s) > 8<<20 || len(s)%2 != 0 || strings.ToLower(s) != s {
		return nil, ErrFunding
	}
	b, e := hex.DecodeString(s)
	if e != nil {
		return nil, ErrFunding
	}
	tx := wire.NewMsgTx(1)
	rd := bytes.NewReader(b)
	if tx.Deserialize(rd) != nil || rd.Len() != 0 || len(tx.TxIn) == 0 || len(tx.TxOut) == 0 {
		return nil, ErrFunding
	}
	var canonical bytes.Buffer
	if tx.Serialize(&canonical) != nil || !bytes.Equal(canonical.Bytes(), b) {
		return nil, ErrFunding
	}
	total := uint64(0)
	for _, o := range tx.TxOut {
		if o.Value < 0 || sumOver(total, uint64(o.Value), maxMoney) {
			return nil, ErrFunding
		}
		total += uint64(o.Value)
	}
	return tx, nil
}
func txHex(tx *wire.MsgTx) string {
	var b bytes.Buffer
	_ = tx.SerializeNoWitness(&b)
	return hex.EncodeToString(b.Bytes())
}
func amount(s string) (uint64, bool) {
	if s == "" || len(s) > 16 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, e := strconv.ParseUint(s, 10, 64)
	return n, e == nil && n <= maxMoney
}
func hexSize(s string, n int) bool {
	if len(s) != 2*n || strings.ToLower(s) != s {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}
func label(s string) bool {
	if len(s) == 0 || len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func validName(s, prefix string) bool {
	return strings.HasPrefix(s, prefix) && len(s) > len(prefix) && len(s) <= 255 && label(s)
}
func valueBytes(b []byte) bool      { return len(b) > 0 && len(b) <= 520 && utf8.Valid(b) }
func sumOver(a, b, cap uint64) bool { return a > cap || b > cap-a }
func mul(a, b uint64) (uint64, bool) {
	if b != 0 && a > math.MaxUint64/b {
		return 0, false
	}
	return a * b, true
}

// object accepts unique, exact decoded member names and one bounded document.
// Struct decoding alone would accept duplicate or case-aliased members.
func object(b []byte, allowed ...string) (map[string]json.RawMessage, error) {
	if len(b) == 0 || len(b) > 1<<20 || !utf8.Valid(b) {
		return nil, ErrInput
	}
	keys := map[string]bool{}
	for _, k := range allowed {
		keys[k] = true
	}
	d := json.NewDecoder(bytes.NewReader(b))
	tok, e := d.Token()
	if e != nil || tok != json.Delim('{') {
		return nil, ErrInput
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		tok, e = d.Token()
		if e != nil {
			return nil, ErrInput
		}
		k, ok := tok.(string)
		if !ok || !keys[k] || out[k] != nil {
			return nil, ErrInput
		}
		var v json.RawMessage
		if d.Decode(&v) != nil || bytes.Equal(v, []byte("null")) {
			return nil, ErrInput
		}
		out[k] = v
	}
	if tok, e = d.Token(); e != nil || tok != json.Delim('}') {
		return nil, ErrInput
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrInput
	}
	return out, nil
}
