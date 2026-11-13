package registration

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

type Value struct {
	Bytes               []byte
	SocialKey, GrantKey string
}

// ParseValue is used on the actual reveal-building path. It accepts exact
// canonical root-social values or combined social/landlord values and preserves
// those bytes; social and grant keys are independent, even when equal.
func ParseValue(raw []byte) (Value, error) {
	if !valueBytes(raw) {
		return Value{}, ErrValue
	}
	if binding, social, e := rental.ParseLandlordIdentity(string(raw)); e == nil && social != nil {
		canonical, e := rental.CombinedLandlordValue(binding, *social)
		if e == nil && bytes.Equal(raw, []byte(canonical)) {
			return Value{append([]byte(nil), raw...), social.Names.Root, binding.Grant}, nil
		}
	}
	var socialOnly struct {
		Nostr *rental.NostrDescriptor `json:"nostr"`
	}
	if json.Unmarshal(raw, &socialOnly) != nil || socialOnly.Nostr == nil {
		return Value{}, ErrValue
	}
	d := socialOnly.Nostr
	canonical, e := json.Marshal(socialOnly)
	if e != nil || !bytes.Equal(raw, canonical) || !validXOnly(d.Names.Root) {
		return Value{}, ErrValue
	}
	if d.Relays != nil {
		if len(d.Relays) != 1 || len(d.Relays[d.Names.Root]) == 0 {
			return Value{}, ErrValue
		}
		seen := map[string]bool{}
		for _, relay := range d.Relays[d.Names.Root] {
			u, e := url.Parse(relay)
			if e != nil || !u.IsAbs() || (u.Scheme != "ws" && u.Scheme != "wss") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || seen[relay] {
				return Value{}, ErrValue
			}
			seen[relay] = true
		}
	}
	return Value{append([]byte(nil), raw...), d.Names.Root, ""}, nil
}
func validXOnly(s string) bool {
	if !hexSize(s, 32) {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, e := schnorr.ParsePubKey(b)
	return e == nil
}

func (p *Planner) revealValues(raw []byte, reservationHash string, names []reservedName) ([2][]byte, error) {
	bad := func() ([2][]byte, error) { return [2][]byte{}, ErrValue }
	fields, e := object(raw, "schema", "reservation_plan_sha256", "registrations")
	if e != nil || len(fields) != 3 {
		return bad()
	}
	var schema, hash string
	if json.Unmarshal(fields["schema"], &schema) != nil || schema != "keyvault-namecoin-reveal-values/1" || json.Unmarshal(fields["reservation_plan_sha256"], &hash) != nil || hash != reservationHash {
		return bad()
	}
	var rows []json.RawMessage
	if json.Unmarshal(fields["registrations"], &rows) != nil || len(rows) != 2 {
		return bad()
	}
	values := [2][]byte{}
	for i, row := range rows {
		f, e := object(row, "name_hex", "value_hex", "value_sha256")
		if e != nil || len(f) != 3 {
			return bad()
		}
		var name, value, hash string
		if json.Unmarshal(f["name_hex"], &name) != nil || json.Unmarshal(f["value_hex"], &value) != nil || json.Unmarshal(f["value_sha256"], &hash) != nil || name != names[i].NameHex || !hexSize(hash, 32) || len(value) > 1040 || !hexSize(value, len(value)/2) {
			return bad()
		}
		b, e := hex.DecodeString(value)
		if e != nil || !valueBytes(b) || digest(b) != hash {
			return bad()
		}
		values[i] = b
		if _, e := ParseValue(b); e != nil {
			return bad()
		}
		if i == 1 && (names[i].FutureValue.State != "fixed" || value != names[i].FutureValue.ValueHex || hash != names[i].FutureValue.ValueSHA256) {
			return bad()
		}
	}
	return values, nil
}
