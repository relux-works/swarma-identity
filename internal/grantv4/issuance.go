package grantv4

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

const AssentType = "swarma-contract-assent/1"
const IssuanceType = "swarma-issuance/1"

// AssentPayload constructs the root issuer's typed assent. The pin explicitly
// leaves the assenting party of a child open; do not substitute its delegation
// key, which is forbidden to sign anything but child grants (J4.2).
func AssentPayload(g *Grant) ([]byte, string, error) {
	if g.Child() {
		return nil, "", Refusal("UNSUPPORTED_CAPABILITY")
	}
	p := object{"type": AssentType, "contract": g.Contract(), "genesis": g.Genesis(), "party": g.Signer()}
	raw := encode(p)
	return raw, typed(AssentType, raw), nil
}
func checkAssent(raw []byte, g *Grant) (party, signature string, err error) {
	defer guard(&err)
	doc := parseDocument(raw, 1024).(object)
	if len(doc) != 2 || doc["payload"] == nil || doc["signature"] == nil {
		reject("WIRE_MEMBER")
	}
	p, ok := doc["payload"].(object)
	if !ok || str(p, "type") != AssentType {
		reject("WIRE_TYPE")
	}
	checkSchema(p, record(map[string]*schema{"type": leaf("string"), "genesis": hashSchema, "contract": hashSchema, "party": signingKey}, ""))
	signature, ok = doc["signature"].(string)
	if !ok || !isHex(signature, 128) {
		reject("WIRE_SIGNATURE_FORM")
	}
	party = str(p, "party")
	if !Verify(party, typed(AssentType, encode(p)), signature) {
		reject("WIRE_SIGNATURE")
	}
	if str(p, "genesis") != g.Genesis() || str(p, "contract") != g.Contract() {
		reject("ASSENT_BINDING")
	}
	if party != g.Signer() {
		reject("ASSENT_PARTY")
	}
	return party, signature, nil
}

type Event struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

func eventID(e Event) string {
	b, _ := json.Marshal([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content})
	return hash(b)
}

// ConsentTemplate binds a by-key root to its chain, contract and issuer. A
// template is unsigned; its event time is never compared with a block height.
func ConsentTemplate(g *Grant, createdAt int64) (Event, error) {
	if g.Child() || obj(g.payload, "recipient")["key"] == nil {
		return Event{}, Refusal("UNSUPPORTED_CAPABILITY")
	}
	if createdAt < 0 || uint64(createdAt) > MaxNumber {
		return Event{}, Refusal("CONSENT_SHAPE")
	}
	e := Event{Pubkey: str(obj(g.payload, "recipient"), "key"), CreatedAt: createdAt, Kind: 8181, Tags: [][]string{{"t", "swarma-contract-consent/1"}, {"genesis", g.Genesis()}, {"contract", g.Contract()}, {"issuer", g.Signer()}}, Content: ""}
	e.ID = eventID(e)
	return e, nil
}
func checkConsent(raw []byte, g *Grant, now int64) (e Event, err error) {
	defer guard(&err)
	bad := func() { reject("CONSENT_SHAPE") }
	if len(raw) > 2048 || !json.Valid(raw) {
		bad()
	}
	// The NIP-01 event has the fixed printable-ASCII wire form of LIP-0013,
	// not JCS. Re-encoding also refuses duplicates, aliases and unknown names.
	if json.Unmarshal(raw, &e) != nil {
		bad()
	}
	for _, c := range raw {
		if c < 0x20 || c > 0x7e {
			bad()
		}
	}
	again, _ := json.Marshal(e)
	if !bytes.Equal(again, raw) {
		bad()
	}
	if !isHex(e.ID, 64) || !isHex(e.Sig, 128) || !isHex(e.Pubkey, 64) || e.CreatedAt < 0 || uint64(e.CreatedAt) > MaxNumber || e.Kind != 8181 || e.Content != "" || (len(e.Tags) != 4 && len(e.Tags) != 5) {
		bad()
	}
	for i, name := range []string{"t", "genesis", "contract", "issuer", "name"} {
		if i == len(e.Tags) {
			break
		}
		if len(e.Tags[i]) != 2 || e.Tags[i][0] != name {
			bad()
		}
	}
	if e.Tags[0][1] != "swarma-contract-consent/1" || !isHex(e.Tags[1][1], 64) || !isHex(e.Tags[2][1], 64) || !isHex(e.Tags[3][1], 64) || e.ID != eventID(e) {
		bad()
	}
	// Key membership is part of event shape, before binding or signature.
	for _, key := range []string{e.Pubkey, e.Tags[3][1]} {
		func() {
			defer func() {
				if p := recover(); p != nil {
					if _, ok := p.(Refusal); ok {
						bad()
					}
					panic(p)
				}
			}()
			checkSchema(key, signingKey)
		}()
	}
	r := obj(g.payload, "recipient")
	_, byKey := r["key"]
	if e.Tags[1][1] != g.Genesis() || e.Tags[2][1] != g.Contract() || e.Tags[3][1] != g.Signer() || (byKey && len(e.Tags) != 4) || (!byKey && (len(e.Tags) != 5 || e.Tags[4][1] != str(r, "name"))) {
		reject("CONSENT_BINDING")
	}
	if !byKey {
		reject("UNSUPPORTED_CAPABILITY")
	} // evidence must come from an own-node snapshot, never a caller's assertion
	if e.Pubkey != str(r, "key") {
		reject("CONSENT_KEY")
	}
	if !Verify(e.Pubkey, e.ID, e.Sig) {
		reject("CONSENT_SIGNATURE")
	}
	if e.CreatedAt > now {
		reject("CONSENT_TIME")
	}
	return e, nil
}

// Preparation verifies the defined root/by-key octet stages in W9.4 order.
// It is NOT an issuer service: it reads no node, consumes no consent, checks
// no issuer clock age, and does not authorize a signature or a transaction.
// Child assent and by-name evidence integration remain unsupported.
func Preparation(signed, assent, consent, parent []byte, nameOutput *Outpoint, now int64) (raw []byte, commitment, frame string, err error) {
	var p *Grant
	if len(parent) > 0 {
		p, err = Read(parent, nil, nil)
		if err != nil {
			return
		}
	}
	g, e := Read(signed, p, nil)
	if e != nil {
		err = e
		return
	}
	byKey := obj(g.payload, "recipient")["key"] != nil
	if byKey != (nameOutput == nil) {
		err = Refusal("ISSUANCE_MODE")
		return
	}
	if g.Child() {
		err = Refusal("UNSUPPORTED_CAPABILITY")
		return
	}
	party, sig, e := checkAssent(assent, g)
	if e != nil {
		err = e
		return
	}
	event, e := checkConsent(consent, g, now)
	if e != nil {
		err = e
		return
	}
	r := object{"event_id": event.ID, "signature": event.Sig}
	if nameOutput != nil {
		r["name_output"] = object{"txid": nameOutput.TxID, "vout": json.Number(strconv.FormatUint(uint64(nameOutput.Vout), 10))}
	}
	prep := object{"type": IssuanceType, "genesis": g.Genesis(), "contract": g.Contract(), "grant_id": g.ID(), "grant_signature": g.Signature(), "issuer_assent": object{"party": party, "signature": sig}, "recipient_consent": r}
	raw = encode(prep)
	commitment = typed(IssuanceType, raw)
	frame = "6a03534c014202" + commitment + "01" + g.ContentAddress()
	return
}

type Outpoint struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}

// CheckFrame never accepts a v3 payload version or a payload identifier in
// place of the signed-form content address. Frame defects precede commitment.
func CheckFrame(candidate, expected string) error {
	b, e := hex.DecodeString(candidate)
	want, w := hex.DecodeString(expected)
	if e != nil || w != nil || hex.EncodeToString(b) != candidate || len(b) != 72 || len(want) != 72 || !bytes.Equal(b[:7], want[:7]) || b[39] != 1 || !bytes.Equal(b[40:], want[40:]) {
		return Refusal("ISSUANCE_FRAME")
	}
	if !bytes.Equal(b[7:39], want[7:39]) {
		return Refusal("ISSUANCE_COMMITMENT")
	}
	return nil
}
