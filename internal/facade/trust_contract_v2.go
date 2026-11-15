package facade

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strconv"
)

const TrustContractV2Profile = "swarma-trust-contract/2"

// TrustContractV2 follows the fifteen-member order of LIP-0014 section 3.
// Members 2..10 and note retain LIP-0013 sections 2.1..2.3 unchanged.
type TrustContractV2 struct {
	Profile         string        `json:"profile"`           // LIP-0014 section 3, member 1
	Network         string        `json:"network"`           // LIP-0014 section 3, member 2
	LandlordName    string        `json:"landlord_name"`     // LIP-0014 section 3, member 3
	AgentName       string        `json:"agent_name"`        // LIP-0014 section 3, member 4
	GranteeKey      string        `json:"grantee_key"`       // LIP-0014 section 3, member 5
	Actions         []string      `json:"actions"`           // LIP-0014 section 3, member 6
	Repos           []string      `json:"repos"`             // LIP-0014 section 3, member 7
	SpendBudget     int64         `json:"spend_budget"`      // LIP-0014 section 3, member 8
	NotBefore       int64         `json:"not_before"`        // LIP-0014 section 3, member 9
	NotAfter        int64         `json:"not_after"`         // LIP-0014 section 3, member 10
	ScopeTextSHA256 string        `json:"scope_text_sha256"` // LIP-0014 sections 3 (member 11), 3.3
	ParentGrantID   string        `json:"parent_grant_id"`   // LIP-0014 sections 3 (member 12), 3.1 rule 8
	Ordinal         int64         `json:"ordinal"`           // LIP-0014 sections 3 (member 13), 3.1 rule 8
	Delegate        TrustDelegate `json:"delegate"`          // LIP-0014 sections 3 (member 14), 2
	Note            string        `json:"note"`              // LIP-0014 section 3, member 15
}

// TrustDelegate is exactly the six-member right of LIP-0014 section 2.
// This implementation admits only its single empty, depth-zero value.
type TrustDelegate struct {
	Depth      int64         `json:"depth"`
	Actions    []string      `json:"actions"`
	Budget     int64         `json:"budget"`
	Slots      []TrustSlot   `json:"slots"`
	Notaries   []TrustNotary `json:"notaries"`
	Checkpoint string        `json:"checkpoint"`
}

// TrustSlot describes only the closed wire shape of a section 2 row;
// nonempty slots are never admitted by this depth-zero implementation.
type TrustSlot struct {
	Executor string `json:"executor"`
	Grantee  string `json:"grantee"`
	Cap      int64  `json:"cap"`
	Notary   string `json:"notary"`
}

// TrustNotary and TrustRegistration describe section 2's closed wire shapes;
// nonempty notaries are never admitted or consulted at depth zero.
type TrustNotary struct {
	Name         string            `json:"name"`
	Registration TrustRegistration `json:"registration"`
	Owner        string            `json:"owner"`
}

type TrustRegistration struct {
	TxID string `json:"txid"`
	Vout int64  `json:"vout"`
}

// EmptyTrustDelegate returns a fresh canonical depth-zero right (section 2).
func EmptyTrustDelegate() TrustDelegate {
	return TrustDelegate{Actions: []string{}, Slots: []TrustSlot{}, Notaries: []TrustNotary{}}
}

var contractV2Members = []string{"profile", "network", "landlord_name", "agent_name", "grantee_key", "actions", "repos", "spend_budget", "not_before", "not_after", "scope_text_sha256", "parent_grant_id", "ordinal", "delegate", "note"}
var delegateV2Members = []string{"depth", "actions", "budget", "slots", "notaries", "checkpoint"}

// canonicalV2Value checks rule 1 at every nesting level, preserving member
// order. Reconstructing token bytes detects all forbidden string/number
// spellings and whitespace; unlike map encoding it cannot sort an object.
func canonicalV2Value(d *json.Decoder, depth int) ([]byte, string) {
	if depth > 32 {
		return nil, "CONTRACT_ENCODING"
	}
	t, err := d.Token()
	if err != nil {
		return nil, "CONTRACT_ENCODING"
	}
	switch v := t.(type) {
	case string:
		if !printableASCII(v) {
			return nil, "CONTRACT_ENCODING"
		}
		b, _ := compactJSON(v)
		return b, ""
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil || n < 0 || strconv.FormatInt(n, 10) != string(v) {
			return nil, "CONTRACT_ENCODING"
		}
		return []byte(v), ""
	case json.Delim:
		if v != '{' && v != '[' {
			return nil, "CONTRACT_ENCODING"
		}
		out := []byte{byte(v)}
		seen := map[string]bool{}
		for d.More() {
			if len(out) > 1 {
				out = append(out, ',')
			}
			if v == '{' {
				t, err := d.Token()
				key, ok := t.(string)
				if err != nil || !ok || !printableASCII(key) {
					return nil, "CONTRACT_ENCODING"
				}
				// Rule 1 owns the top-level member set. Nested duplicates are
				// structure owned by rule 9, after rules 2–8 (LIP-0014 3.1).
				if depth == 0 && seen[key] {
					return nil, "CONTRACT_FIELD"
				}
				seen[key] = true
				b, _ := compactJSON(key)
				out = append(out, b...)
				out = append(out, ':')
			}
			b, code := canonicalV2Value(d, depth+1)
			if code != "" {
				return nil, code
			}
			out = append(out, b...)
		}
		end, err := d.Token()
		want := json.Delim('}')
		if v == '[' {
			want = ']'
		}
		if err != nil || end != want {
			return nil, "CONTRACT_ENCODING"
		}
		return append(out, byte(want)), ""
	}
	return nil, "CONTRACT_ENCODING"
}

// v2Members checks exact names before decoding, so encoding/json's field-name
// case folding cannot admit aliases. The task requires CONTRACT_FIELD for
// unknown/duplicate members, overriding the draft's shape codes for those cases.
func v2Members(raw []byte, names []string, shapeCode string) string {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return shapeCode
	}
	var got []string
	for d.More() {
		t, err := d.Token()
		name, ok := t.(string)
		if err != nil || !ok {
			return shapeCode
		}
		if !slices.Contains(names, name) || slices.Contains(got, name) {
			return "CONTRACT_FIELD"
		}
		got = append(got, name)
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return shapeCode
		}
	}
	if !slices.Equal(got, names) {
		return shapeCode
	}
	return ""
}

func v2DelegateShape(raw json.RawMessage) string {
	if code := v2Members(raw, delegateV2Members, "CONTRACT_DELEGATE"); code != "" {
		return code
	}
	var right struct {
		Slots    []json.RawMessage `json:"slots"`
		Notaries []json.RawMessage `json:"notaries"`
	}
	if json.Unmarshal(raw, &right) != nil {
		return "CONTRACT_DELEGATE"
	}
	for _, row := range right.Slots {
		if code := v2Members(row, []string{"executor", "grantee", "cap", "notary"}, "CONTRACT_DELEGATE"); code != "" {
			return code
		}
	}
	for _, entry := range right.Notaries {
		if code := v2Members(entry, []string{"name", "registration", "owner"}, "CONTRACT_DELEGATE"); code != "" {
			return code
		}
		var n struct {
			Registration json.RawMessage `json:"registration"`
		}
		if json.Unmarshal(entry, &n) != nil {
			return "CONTRACT_DELEGATE"
		}
		if code := v2Members(n.Registration, []string{"txid", "vout"}, "CONTRACT_DELEGATE"); code != "" {
			return code
		}
	}
	return ""
}

// ParseTrustContractV2 reads only profile /2 and never normalizes its bytes.
// It enforces LIP-0014 sections 2, 3 and 3.1, narrowed to depth zero by this
// task. /1's reader and refusal order are deliberately left unchanged.
func ParseTrustContractV2(raw []byte) (TrustContractV2, string) {
	var c TrustContractV2
	bad := func(code string) (TrustContractV2, string) { return TrustContractV2{}, code }
	if len(raw) == 0 || len(raw) > trustMaxBytes {
		return bad("CONTRACT_ENCODING")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	canonical, code := canonicalV2Value(d, 0)
	if code != "" {
		return bad(code)
	}
	if _, err := d.Token(); err != io.EOF || !bytes.Equal(raw, canonical) {
		return bad("CONTRACT_ENCODING")
	}
	if code := v2Members(raw, contractV2Members, "CONTRACT_ENCODING"); code != "" {
		return bad(code)
	}
	// Isolate delegate decoding from top-level rule 1 type errors.
	var members map[string]json.RawMessage
	_ = json.Unmarshal(raw, &members)
	right := members["delegate"]
	members["delegate"], _ = compactJSON(EmptyTrustDelegate())
	top, _ := compactJSON(members)
	if json.Unmarshal(top, &c) != nil || c.Actions == nil || c.Repos == nil {
		return bad("CONTRACT_ENCODING")
	}
	if c.Profile != TrustContractV2Profile {
		return bad("CONTRACT_PROFILE")
	}
	if (c.Network != "main" && c.Network != "regtest") || !v3Name(c.LandlordName) || !v3Name(c.AgentName) || c.LandlordName == c.AgentName || !xOnlyKey(c.GranteeKey) || c.NotAfter <= c.NotBefore || c.NotAfter > trustMaxTime || (c.ScopeTextSHA256 != "" && !lowerHex(c.ScopeTextSHA256, 32)) {
		return bad("CONTRACT_FIELD")
	}
	if len(c.Actions) == 0 || !strictlyAscending(c.Actions) {
		return bad("CONTRACT_ACTIONS")
	}
	for _, a := range c.Actions {
		if _, ok := trustActionScope[a]; !ok {
			return bad("CONTRACT_ACTIONS")
		}
	}
	if slices.Contains(c.Actions, "land") != (len(c.Repos) > 0) || len(c.Repos) > trustMaxRepos || !strictlyAscending(c.Repos) {
		return bad("CONTRACT_REPOS")
	}
	for _, r := range c.Repos {
		if !repoURL(r) {
			return bad("CONTRACT_REPOS")
		}
	}
	if slices.Contains(c.Actions, "spend") != (c.SpendBudget > 0) || c.SpendBudget > trustMaxMoney {
		return bad("CONTRACT_BUDGET")
	}
	if len(c.Note) > trustMaxNote {
		return bad("CONTRACT_NOTE")
	}
	if c.Ordinal > 16 || (c.ParentGrantID != "" && !lowerHex(c.ParentGrantID, 32)) || (c.ParentGrantID == "") != (c.Ordinal == 0) {
		return bad("CONTRACT_PARENT")
	}
	if code := v2DelegateShape(right); code != "" {
		return bad(code)
	}
	if json.Unmarshal(right, &c.Delegate) != nil || c.Delegate.Actions == nil || c.Delegate.Slots == nil || c.Delegate.Notaries == nil {
		return bad("CONTRACT_DELEGATE")
	}
	r := c.Delegate
	if r.Depth != 0 || len(r.Actions) != 0 || r.Budget != 0 || len(r.Slots) != 0 || len(r.Notaries) != 0 || r.Checkpoint != "" {
		return bad("CONTRACT_DEPTH")
	}
	return c, ""
}

// EncodeTrustContractV2 builds canonical unsigned bytes from typed inputs and
// re-reads them before release. Nil arrays are refused, never filled implicitly.
func EncodeTrustContractV2(c TrustContractV2) ([]byte, string) {
	raw, ok := compactJSON(c)
	if !ok {
		return nil, "CONTRACT_ENCODING"
	}
	if _, code := ParseTrustContractV2(raw); code != "" {
		return nil, code
	}
	return raw, ""
}

// verifyScopeTextV2 binds the separate document's exact octets (section 3.3).
// An empty hash denotes no document; SHA256(empty) denotes a present empty one.
func verifyScopeTextV2(c TrustContractV2, text []byte) string {
	if c.ScopeTextSHA256 == "" {
		if text != nil {
			return "SCOPE_TEXT_HASH"
		}
	} else if text == nil || sha256Hex(text) != c.ScopeTextSHA256 {
		return "SCOPE_TEXT_HASH"
	}
	return ""
}
