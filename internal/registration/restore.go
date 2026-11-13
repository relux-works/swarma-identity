package registration

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"unicode/utf8"
)

// RetainedRequest supplies original public preparation facts. They do not prove
// native activity, preparation time, presence, journal authenticity or release.
type RetainedRequest struct {
	Slot                 string
	PreparedAt           uint64
	IDs                  RequestIDs
	Request, ReviewFrame []byte
}

// RestoreReservation rebuilds public construction and compares every retained
// output. It validates the recorded window, without applying today's clock.
func (p *Planner) RestoreReservation(in ReservationInput, preparedAt uint64, manifest []byte, transactions [2]PreparedTransaction) (*Plan, error) {
	if !p.timeOK(preparedAt) {
		return nil, ErrParents
	}
	plan, e := p.reserve(in)
	return matchRestoredPlan(plan, e, manifest, transactions)
}

// RestoreReveal requires public parents already verified by the caller against
// their retained original requests; it grants no protected-history authority.
func (p *Planner) RestoreReveal(reservation *Plan, in RevealInput, preparedAt uint64, manifest []byte, transactions [2]PreparedTransaction) (*Plan, error) {
	if !p.timeOK(preparedAt) {
		return nil, ErrParents
	}
	plan, e := p.reveal(reservation, in)
	return matchRestoredPlan(plan, e, manifest, transactions)
}

func matchRestoredPlan(plan *Plan, e error, manifest []byte, transactions [2]PreparedTransaction) (*Plan, error) {
	if e != nil || plan == nil || !bytes.Equal(plan.raw, manifest) || len(plan.transactions) != 2 || plan.transactions[0] != transactions[0] || plan.transactions[1] != transactions[1] {
		return nil, ErrParents
	}
	return plan, nil
}

// RestoreSigningRequest retains the original serialization only after checking
// its closed wire, selected Plan/PSBT, original IDs/window and complete frame.
// It never refreshes IDs or expiry and does not consult a historical clock.
func (p *Planner) RestoreSigningRequest(plan *Plan, retained RetainedRequest) (*SigningRequest, error) {
	ids := retained.IDs
	if !p.timeOK(retained.PreparedAt) || !hexSize(ids.RequestID, 32) || !hexSize(ids.SittingID, 32) || ids.ExpiresAt <= retained.PreparedAt || ids.ExpiresAt-retained.PreparedAt > 600 {
		return nil, ErrParents
	}
	if !retainedUnicode(retained.Request) {
		return nil, ErrParents
	}
	fields, e := closedObject(retained.Request, 8<<20, "schema", "request_id", "sitting_id", "slot", "network", "expires_at", "psbt", "plan_manifest_utf8", "plan_sha256", "reservation_plan_sha256", "intent")
	if e != nil || len(fields) != 11 {
		return nil, ErrParents
	}
	var d requestData
	if json.Unmarshal(retained.Request, &d) != nil || d.Slot != retained.Slot {
		return nil, ErrParents
	}
	intentKeys := []string{"operation", "name_hex", "rand_hex"}
	if retained.Slot == "C" || retained.Slot == "D" {
		intentKeys = append(intentKeys, "value_hex", "reservation_outpoint")
	}
	intent, e := object(fields["intent"], intentKeys...)
	if e != nil || len(intent) != len(intentKeys) {
		return nil, ErrParents
	}
	if out, ok := intent["reservation_outpoint"]; ok {
		m, e := object(out, "txid", "vout")
		if e != nil || len(m) != 2 {
			return nil, ErrParents
		}
	}
	if p.ValidateUnsigned(plan, retained.Slot, d.PSBT) != nil {
		return nil, ErrParents
	}
	expected, e := p.buildSigningRequest(plan, retained.Slot, d.PSBT, ids)
	if e != nil || !reflect.DeepEqual(expected.data, d) || !bytes.Equal(expected.frame, retained.ReviewFrame) {
		return nil, ErrParents
	}
	expected.raw = append([]byte(nil), retained.Request...)
	expected.frame = append([]byte(nil), retained.ReviewFrame...)
	return expected, nil
}

// retainedUnicode prevents encoding/json replacement of malformed UTF-16
// escape pairs from silently changing original public request strings.
func retainedUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		u, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if u >= 0xdc00 && u <= 0xdfff {
			return false
		}
		if u < 0xd800 || u > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if e != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
