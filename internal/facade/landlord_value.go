package facade

import (
	"encoding/hex"
	"encoding/json"
	"net/url"
	"reflect"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// value build renders the LIP-0004 landlord value for a name_update: the new
// grant key plus the unchanged root-only Nostr descriptor. The renderer is a
// port of chain-lab rental.CombinedLandlordValue (experiments/rental
// landlord_value.go at 7ea1800). Its output is accepted only when the repo's
// v3 reader (classifyV3), the chain-lab parser and the chain-lab renderer all
// agree on it exactly.

type valueNostrNames struct {
	Root string `json:"_"`
}

// ValueNostrDescriptor is the --social-descriptor file: exactly the "nostr"
// member of the current landlord value.
type ValueNostrDescriptor struct {
	Names  valueNostrNames     `json:"names"`
	Relays map[string][]string `json:"relays,omitempty"`
}

type valueLandlord struct {
	Grant string `json:"grant"`
}

type valueSwarma struct {
	Landlord valueLandlord `json:"landlord"`
}

type landlordValueWire struct {
	Nostr  *ValueNostrDescriptor `json:"nostr,omitempty"`
	Swarma valueSwarma           `json:"swarma"`
}

type LandlordValueResult struct {
	Value    string `json:"value"`
	ValueHex string `json:"value_hex"`
	Bytes    int    `json:"bytes"`
	GrantKey string `json:"grant_key"`
	Social   Social `json:"social"`
}

func valueRefuse(code string) *Failure {
	return &Failure{Code: code, Message: "The landlord value is refused by the v3 value contract.", Exit: 3}
}

// validDescriptor is the port of chain-lab validateNostr for a present
// descriptor: a valid root key and, when present, exactly one relay list keyed
// by the root with unique absolute ws/wss URLs.
func validDescriptor(d ValueNostrDescriptor) string {
	if !xOnlyKey(d.Names.Root) {
		return "NOSTR_KEY"
	}
	if d.Relays == nil {
		return ""
	}
	relays, ok := d.Relays[d.Names.Root]
	if len(d.Relays) != 1 || !ok || len(relays) == 0 {
		return "NOSTR_RELAYS"
	}
	seen := map[string]bool{}
	for _, raw := range relays {
		u, e := url.Parse(raw)
		if e != nil || !u.IsAbs() || (u.Scheme != "ws" && u.Scheme != "wss") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || seen[raw] {
			return "NOSTR_RELAY_URL"
		}
		seen[raw] = true
	}
	return ""
}

// renderLandlordValue is the port of CombinedLandlordValue.
func renderLandlordValue(grant string, d ValueNostrDescriptor) (string, *Failure) {
	if !xOnlyKey(grant) {
		return "", valueRefuse("LANDLORD_KEY")
	}
	if code := validDescriptor(d); code != "" {
		return "", valueRefuse(code)
	}
	v := landlordValueWire{Nostr: &d, Swarma: valueSwarma{valueLandlord{grant}}}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fail("INTERNAL")
	}
	if len(b) > 520 {
		return "", valueRefuse("LANDLORD_VALUE")
	}
	return string(b), nil
}

// checkLandlordValue re-parses value and refuses any difference from the
// intended grant key and descriptor, and any member beyond them.
func checkLandlordValue(value, grant string, d ValueNostrDescriptor) *Failure {
	v := classifyV3([]byte(value))
	want := d.Relays[d.Names.Root]
	if v.role != "landlord" || v.grantKey != grant || v.social == nil || v.social.Key != d.Names.Root || len(v.social.Relays) != len(want) {
		return valueRefuse("VALUE_MISMATCH")
	}
	for i := range want {
		if v.social.Relays[i] != want[i] {
			return valueRefuse("VALUE_MISMATCH")
		}
	}
	b, parsed, err := rental.ParseLandlordIdentity(value)
	if err != nil || b.Grant != grant || parsed == nil || parsed.Names.Root != d.Names.Root || !reflect.DeepEqual(parsed.Relays, d.Relays) {
		return valueRefuse("VALUE_MISMATCH")
	}
	var wire landlordValueWire
	if DecodeStrict([]byte(value), &wire) != nil || wire.Nostr == nil {
		return valueRefuse("VALUE_MISMATCH")
	}
	if again, err := json.Marshal(wire); err != nil || string(again) != value {
		return valueRefuse("VALUE_MISMATCH")
	}
	reference, err := rental.CombinedLandlordValue(rental.LandlordBinding{Grant: grant}, rental.NostrDescriptor{Names: rental.NostrNames{Root: d.Names.Root}, Relays: d.Relays})
	if err != nil || reference != value {
		return valueRefuse("VALUE_MISMATCH")
	}
	return nil
}

// BuildLandlordValue renders, re-parses and returns the name_update value.
func BuildLandlordValue(grant string, d ValueNostrDescriptor) (*LandlordValueResult, *Failure) {
	value, f := renderLandlordValue(grant, d)
	if f != nil {
		return nil, f
	}
	if f := checkLandlordValue(value, grant, d); f != nil {
		return nil, f
	}
	relays := append([]string{}, d.Relays[d.Names.Root]...)
	return &LandlordValueResult{value, hex.EncodeToString([]byte(value)), len(value), grant, Social{d.Names.Root, relays}}, nil
}
