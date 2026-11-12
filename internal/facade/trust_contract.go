package facade

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Constants of the swarma-trust-contract/1 profile (LIP-0013 section 2).
const (
	TrustContractProfile = "swarma-trust-contract/1"
	trustConsentTag      = "swarma-rental-consent-v1"
	trustPrivacyLabel    = "swarma-trust-privacy-v1"
	trustBookingSuffix   = "booking"
	trustMaxBytes        = 8192
	trustMaxNote         = 280
	trustMaxRepos        = 16
	trustMaxRepoBytes    = 200
	trustMaxMoney        = int64(21000000) * 100000000
	trustMaxTime         = int64(253402300799)
)

// TrustContract is the preimage of a trust grant's contract_sha256. The field
// order is the canonical member order of LIP-0013 section 2.1.
type TrustContract struct {
	Profile      string   `json:"profile"`
	Network      string   `json:"network"`
	LandlordName string   `json:"landlord_name"`
	AgentName    string   `json:"agent_name"`
	GranteeKey   string   `json:"grantee_key"`
	Actions      []string `json:"actions"`
	Repos        []string `json:"repos"`
	SpendBudget  int64    `json:"spend_budget"`
	NotBefore    int64    `json:"not_before"`
	NotAfter     int64    `json:"not_after"`
	Note         string   `json:"note"`
}

// trustActionScope maps each profile action to its v3 scope entry; "" means
// the action has no v3 carrier.
var trustActionScope = map[string]string{"instruct": "", "land": "repository.push", "review": "", "spend": "pay"}

// compactJSON is Go's encoding/json without HTML escaping and without the
// trailing newline: the encoder chain-lab uses for event and contract bytes.
func compactJSON(v any) ([]byte, bool) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return nil, false
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), true
}

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func xOnlyKey(s string) bool {
	if !lowerHex(s, 32) {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, err := schnorr.ParsePubKey(b)
	return err == nil
}

// v3Name is the v3 name syntax: "id/" and 1..252 bytes of [a-z0-9._-].
func v3Name(s string) bool {
	if !strings.HasPrefix(s, "id/") || len(s) <= 3 || len(s) > 255 {
		return false
	}
	for _, c := range []byte(s[3:]) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func printableASCII(s string) bool {
	for _, c := range []byte(s) {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func strictlyAscending(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			return false
		}
	}
	return true
}

// repoURL is the LIP-0013 repository grammar: https, two or more lowercase
// DNS labels, one or more path segments, nothing else, at most 200 bytes.
func repoURL(s string) bool {
	rest, ok := strings.CutPrefix(s, "https://")
	if len(s) > trustMaxRepoBytes || !ok {
		return false
	}
	host, path, ok := strings.Cut(rest, "/")
	labels := strings.Split(host, ".")
	if !ok || len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range []byte(l) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for _, c := range []byte(seg) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ParseTrustContract applies LIP-0013 section 2.3 in its fixed order and
// returns the first refusal code, or "" for a valid contract. The reader never
// normalizes: re-encoding the parsed value must give the identical octets.
func ParseTrustContract(raw []byte) (TrustContract, string) {
	var c TrustContract
	if len(raw) == 0 || len(raw) > trustMaxBytes {
		return c, "CONTRACT_ENCODING"
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || c.Actions == nil || c.Repos == nil {
		return c, "CONTRACT_ENCODING"
	}
	// Re-encoding equality decides member set and order, duplicates, spacing
	// and number/string spelling; the sign and character rules close the rest.
	again, ok := compactJSON(c)
	if !ok || !bytes.Equal(again, raw) || c.SpendBudget < 0 || c.NotBefore < 0 || c.NotAfter < 0 {
		return c, "CONTRACT_ENCODING"
	}
	for _, s := range append(append([]string{c.Profile, c.Network, c.LandlordName, c.AgentName, c.GranteeKey, c.Note}, c.Actions...), c.Repos...) {
		if !printableASCII(s) {
			return c, "CONTRACT_ENCODING"
		}
	}
	if c.Profile != TrustContractProfile {
		return c, "CONTRACT_PROFILE"
	}
	if (c.Network != "main" && c.Network != "regtest") || !v3Name(c.LandlordName) || !v3Name(c.AgentName) || c.LandlordName == c.AgentName || !xOnlyKey(c.GranteeKey) || c.NotAfter <= c.NotBefore || c.NotAfter > trustMaxTime {
		return c, "CONTRACT_FIELD"
	}
	if len(c.Actions) == 0 || !strictlyAscending(c.Actions) {
		return c, "CONTRACT_ACTIONS"
	}
	for _, a := range c.Actions {
		if _, ok := trustActionScope[a]; !ok {
			return c, "CONTRACT_ACTIONS"
		}
	}
	if slices.Contains(c.Actions, "land") != (len(c.Repos) > 0) || len(c.Repos) > trustMaxRepos || !strictlyAscending(c.Repos) {
		return c, "CONTRACT_REPOS"
	}
	for _, r := range c.Repos {
		if !repoURL(r) {
			return c, "CONTRACT_REPOS"
		}
	}
	if slices.Contains(c.Actions, "spend") != (c.SpendBudget > 0) || c.SpendBudget > trustMaxMoney {
		return c, "CONTRACT_BUDGET"
	}
	if len(c.Note) > trustMaxNote {
		return c, "CONTRACT_NOTE"
	}
	return c, ""
}

// EncodeTrustContract returns the canonical bytes of c, refusing any value the
// reader would refuse. The bytes are always re-read before they are returned.
func EncodeTrustContract(c TrustContract) ([]byte, string) {
	raw, ok := compactJSON(c)
	if !ok {
		return nil, "CONTRACT_ENCODING"
	}
	if _, code := ParseTrustContract(raw); code != "" {
		return nil, code
	}
	return raw, ""
}

// trustScope derives the v3 scope: sorted, never nil.
func trustScope(actions []string) []string {
	scope := []string{}
	for _, a := range actions {
		if s := trustActionScope[a]; s != "" {
			scope = append(scope, s)
		}
	}
	slices.Sort(scope)
	return scope
}

// trustConsentTags returns the four kind-8181 tags of a trust grant in the v3
// order (LIP-0013 section 2.4).
func trustConsentTags(raw []byte) [][]string {
	return [][]string{
		{"t", trustConsentTag},
		{"contract", sha256Hex(raw)},
		{"booking", sha256Hex(append(append([]byte{}, raw...), trustBookingSuffix...))},
		{"privacy", sha256Hex([]byte(trustPrivacyLabel))},
	}
}

// trustGrantView is the projection of a v3 grant that the profile binds to.
// Budget is the v3 budget value with an absent budget meaning 0.
type trustGrantView struct {
	Network, AgentName, LandlordName, GranteeKey, ContractSHA256 string
	Scope                                                        []string
	Budget, NotBefore, NotAfter                                  int64
	ConsentTags                                                  [][]string
}

// bindTrustContract applies LIP-0013 section 2.5 in its order.
func bindTrustContract(raw []byte, g trustGrantView) string {
	if sha256Hex(raw) != g.ContractSHA256 {
		return "CONTRACT_HASH"
	}
	c, code := ParseTrustContract(raw)
	if code != "" {
		return code
	}
	if c.Network != g.Network || c.LandlordName != g.LandlordName || c.AgentName != g.AgentName || c.GranteeKey != g.GranteeKey || c.NotBefore != g.NotBefore || c.NotAfter != g.NotAfter {
		return "CONTRACT_MISMATCH"
	}
	if g.Scope == nil || !slices.Equal(trustScope(c.Actions), g.Scope) {
		return "SCOPE_MISMATCH"
	}
	if c.SpendBudget != g.Budget {
		return "BUDGET_MISMATCH"
	}
	want, _ := compactJSON(trustConsentTags(raw))
	got, ok := compactJSON(g.ConsentTags)
	if !ok || !bytes.Equal(want, got) {
		return "CONSENT_TAGS"
	}
	return ""
}
