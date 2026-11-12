package facade

import (
	"context"
	"encoding/hex"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// Result reasons. They describe an observed value; they are not refusals.
const (
	ReasonValueNotV3    = "VALUE_NOT_V3"
	ReasonLandlordNotV3 = "LANDLORD_NOT_V3"
)

// Social is the optional root-only Nostr descriptor carried beside a v3
// binding. Relays are those listed for the root key, in value order.
type Social struct {
	Key    string   `json:"key"`
	Relays []string `json:"relays"`
}

// ResolvedLandlord is the landlord record an agent points to, read under the
// same tip observation as the agent record.
type ResolvedLandlord struct {
	Name      string  `json:"name"`
	GrantKey  string  `json:"grant_key"`
	Social    *Social `json:"social,omitempty"`
	ValueHex  string  `json:"value_hex"`
	TxID      string  `json:"txid"`
	Vout      uint32  `json:"vout"`
	Height    int64   `json:"height"`
	ExpiresIn int64   `json:"expires_in"`
}

// IdentityResult is the v3 projection of one active name. Role-specific
// members are omitted when they do not apply. A present reason means the
// record is not a usable v3 identity, even when role is "agent".
type IdentityResult struct {
	Name             string            `json:"name"`
	Role             string            `json:"role"`
	Reason           string            `json:"reason,omitempty"`
	GrantKey         string            `json:"grant_key,omitempty"`
	NostrKey         string            `json:"nostr_key,omitempty"`
	Landlord         string            `json:"landlord,omitempty"`
	Social           *Social           `json:"social,omitempty"`
	LandlordResolved *ResolvedLandlord `json:"landlord_resolved,omitempty"`
	ValueHex         string            `json:"value_hex"`
	TxID             string            `json:"txid"`
	Vout             uint32            `json:"vout"`
	Height           int64             `json:"height"`
	ExpiresIn        int64             `json:"expires_in"`
	ObservedTip      Tip               `json:"observed_tip"`
}

type v3Value struct {
	role     string
	grantKey string
	nostrKey string
	landlord string
	social   *Social
}

func socialOf(d *rental.NostrDescriptor) *Social {
	if d == nil {
		return nil
	}
	s := &Social{Key: d.Names.Root, Relays: []string{}}
	s.Relays = append(s.Relays, d.Relays[d.Names.Root]...)
	return s
}

// classifyV3 applies the published chain-lab v3 parsers to exact value bytes.
// The parsers require canonical compact JSON of at most 520 bytes; any other
// byte string, including invalid UTF-8, is role "none".
func classifyV3(value []byte) v3Value {
	if len(value) == 0 || len(value) > 520 || !utf8.Valid(value) {
		return v3Value{role: "none"}
	}
	if b, d, err := rental.ParseLandlordIdentity(string(value)); err == nil {
		return v3Value{role: "landlord", grantKey: b.Grant, social: socialOf(d)}
	}
	if b, d, err := rental.ParseAgentIdentity(string(value)); err == nil {
		return v3Value{role: "agent", nostrKey: b.Nostr, landlord: b.Landlord, social: socialOf(d)}
	}
	return v3Value{role: "none"}
}

// Identity reads one name and, for an agent, its landlord between one tip
// observation and one closing tip comparison. It sends no other RPC.
func (c *Client) Identity(ctx context.Context, name string) (*IdentityResult, *Failure) {
	if name == "" || len(name) > 255 || !utf8.ValidString(name) {
		return nil, fail("BAD_INPUT")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	h, f := c.Health(ctx)
	if f != nil {
		return nil, f
	}
	if h.InitialBlockDownload {
		return nil, fail("NODE_UNSYNCED")
	}
	n, f := c.readName(ctx, name)
	if f != nil {
		return nil, f
	}
	value, err := hex.DecodeString(n.ValueHex)
	if err != nil {
		return nil, fail("INTERNAL")
	}
	v := classifyV3(value)
	var landlord *NameResult
	if v.role == "agent" && !n.Expired {
		landlord, f = c.readName(ctx, v.landlord)
		if f != nil && f.Code != "NAME_NOT_FOUND" {
			return nil, f
		}
	}
	if f := c.sameTip(ctx, h.BlockHash); f != nil {
		return nil, f
	}
	if n.Height > h.Blocks || (landlord != nil && landlord.Height > h.Blocks) {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	if n.Expired {
		return nil, fail("NAME_EXPIRED")
	}
	r := &IdentityResult{Name: n.Name, Role: v.role, ValueHex: n.ValueHex, TxID: n.TxID, Vout: n.Vout, Height: n.Height, ExpiresIn: n.ExpiresIn, ObservedTip: Tip{Hash: h.BlockHash, Height: h.Blocks}, Social: v.social}
	switch v.role {
	case "none":
		r.Reason = ReasonValueNotV3
	case "landlord":
		r.GrantKey = v.grantKey
	case "agent":
		r.NostrKey = v.nostrKey
		r.Landlord = v.landlord
		r.Reason = ReasonLandlordNotV3
		if landlord != nil && !landlord.Expired {
			lb, err := hex.DecodeString(landlord.ValueHex)
			if err != nil {
				return nil, fail("INTERNAL")
			}
			if lv := classifyV3(lb); lv.role == "landlord" {
				r.Reason = ""
				r.LandlordResolved = &ResolvedLandlord{Name: landlord.Name, GrantKey: lv.grantKey, Social: lv.social, ValueHex: landlord.ValueHex, TxID: landlord.TxID, Vout: landlord.Vout, Height: landlord.Height, ExpiresIn: landlord.ExpiresIn}
			}
		}
	}
	return r, nil
}
