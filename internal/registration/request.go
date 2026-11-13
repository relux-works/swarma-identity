package registration

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
)

const RequestSchema = "keyvault-namecoin-psbt/2"

type RequestIDs struct {
	RequestID, SittingID string
	ExpiresAt            uint64
}

type requestIntent struct {
	Operation           string           `json:"operation"`
	NameHex             string           `json:"name_hex"`
	ValueHex            string           `json:"value_hex,omitempty"`
	RandHex             string           `json:"rand_hex"`
	ReservationOutpoint *requestOutpoint `json:"reservation_outpoint,omitempty"`
}
type requestOutpoint struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}
type requestData struct {
	Schema                string        `json:"schema"`
	RequestID             string        `json:"request_id"`
	SittingID             string        `json:"sitting_id"`
	Slot                  string        `json:"slot"`
	Network               string        `json:"network"`
	ExpiresAt             uint64        `json:"expires_at"`
	PSBT                  string        `json:"psbt"`
	PlanManifestUTF8      string        `json:"plan_manifest_utf8"`
	PlanSHA256            string        `json:"plan_sha256"`
	ReservationPlanSHA256 string        `json:"reservation_plan_sha256"`
	Intent                requestIntent `json:"intent"`
}

// SigningRequest retains exact public request and review bytes. Construction
// authorizes no invocation, owner approval, private operation or broadcast.
type SigningRequest struct {
	raw, frame []byte
	data       requestData
	plan       *Plan
}

func (r *SigningRequest) Bytes() []byte        { return append([]byte(nil), r.raw...) }
func (r *SigningRequest) ReviewFrame() []byte  { return append([]byte(nil), r.frame...) }
func (r *SigningRequest) ReviewSHA256() string { return digest(r.frame) }

// PrepareRequest binds a constructed phase and selected unsigned PSBT to the
// short approval window. now is supplied by the trusted caller's clock; request
// JSON cannot select that clock, public account pin or policy profile.
func (p *Planner) PrepareRequest(plan *Plan, slot, unsigned string, ids RequestIDs, now uint64) (*SigningRequest, error) {
	if e := p.ValidateUnsigned(plan, slot, unsigned); e != nil {
		return nil, e
	}
	if !hexSize(ids.RequestID, 32) || !hexSize(ids.SittingID, 32) || !p.timeOK(now) || ids.ExpiresAt <= now || ids.ExpiresAt-now > 600 {
		return nil, ErrInput
	}
	return p.buildSigningRequest(plan, slot, unsigned, ids)
}

// buildSigningRequest is deterministic public construction with no clock or I/O.
func (p *Planner) buildSigningRequest(plan *Plan, slot, unsigned string, ids RequestIDs) (*SigningRequest, error) {
	d := requestData{Schema: RequestSchema, RequestID: ids.RequestID, SittingID: ids.SittingID, Slot: slot, Network: p.profile.Network, ExpiresAt: ids.ExpiresAt, PSBT: unsigned, PlanManifestUTF8: string(plan.raw), PlanSHA256: plan.digest, ReservationPlanSHA256: plan.digest}
	var phase byte
	if slot == "A" || slot == "B" {
		var m reservationManifest
		if json.Unmarshal(plan.raw, &m) != nil || len(m.Registrations) != 2 {
			return nil, ErrInput
		}
		i := int(slot[0] - 'A')
		r := m.Registrations[i]
		d.Intent = requestIntent{Operation: "name_new", NameHex: r.NameHex, RandHex: r.RandHex}
	} else {
		var m revealManifest
		if json.Unmarshal(plan.raw, &m) != nil || len(m.Registrations) != 2 || len(m.Transactions) != 2 {
			return nil, ErrInput
		}
		phase = 1
		i := int(slot[0] - 'C')
		r := m.Registrations[i]
		if len(m.Transactions[i].Inputs) == 0 {
			return nil, ErrInput
		}
		parent := m.Transactions[i].Inputs[0]
		d.ReservationPlanSHA256 = m.ReservationPlanSHA256
		d.Intent = requestIntent{Operation: "name_firstupdate", NameHex: r.NameHex, RandHex: r.RandHex, ValueHex: r.ValueHex, ReservationOutpoint: &requestOutpoint{parent.TxID, parent.Vout}}
	}
	f := append([]byte("keyvault/namecoin-psbt-review/2"), 0)
	lp := func(b []byte) { f = binary.BigEndian.AppendUint32(f, uint32(len(b))); f = append(f, b...) }
	unhex := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	wireHash := func(s string) []byte {
		b := unhex(s)
		for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return b
	}
	psbt, _ := base64.StdEncoding.DecodeString(unsigned)
	lp(psbt)
	lp([]byte(d.Intent.Operation))
	lp(unhex(d.Intent.NameHex))
	lp(unhex(d.Intent.ValueHex))
	lp(unhex(d.Intent.RandHex))
	if out := d.Intent.ReservationOutpoint; out != nil {
		f = append(f, 1)
		f = append(f, wireHash(out.TxID)...)
		f = binary.BigEndian.AppendUint32(f, out.Vout)
	} else {
		f = append(f, 0)
	}
	f = append(f, phase)
	f = append(f, unhex(d.ReservationPlanSHA256)...)
	f = append(f, unhex(d.PlanSHA256)...)
	f = append(f, unhex(d.SittingID)...)
	f = append(f, slot[0])
	lp([]byte(p.pin.Group))
	lp([]byte(p.pin.Account))
	f = append(f, unhex(p.pinHash)...)
	lp([]byte(p.profile.Network))
	f = append(f, wireHash(p.profile.Genesis)...)
	lp([]byte(p.profile.Policy.Revision))
	f = binary.BigEndian.AppendUint64(f, p.perCap)
	f = append(f, unhex(d.RequestID)...)
	f = binary.BigEndian.AppendUint64(f, d.ExpiresAt)
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, ErrInput
	}
	return &SigningRequest{raw: raw, frame: f, data: d, plan: plan}, nil
}
