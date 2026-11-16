package facade

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/relux-works/swarma-identity/internal/keypolicy"
)

// keychain sign for the depth-zero swarma-trust-contract/2 draft record that
// grant draft-v2 emits (LIP-0014 sections 2 and 3). The request names its own
// schema; nothing here guesses a profile from the content. Custody, the
// confirmation, the digest binding (bindDigests) and the signing loop are the
// ones of sign/1. This file adds only what the /2 terms need before the
// display: its own admission gate, the fifteen members read from the signed
// bytes, a scope text worded from those members alone, and the refusal of a
// landlord value that is not the legacy one.
const KeychainSignV2Schema = "swarma-keychain/sign/2"

// contractMember is one top-level member of the signed contract: its name
// and the exact octets of its value.
type contractMember struct{ name, value string }

// signV2 is what the /2 display shows beyond the common grant fields. Every
// part is checked against the contract bytes before anything is shown.
type signV2 struct {
	contract TrustContractV2
	members  []contractMember
	value    []byte // the landlord value, exact octets
	scopeDoc []byte // the separate scope text; nil when the contract binds none
}

// contractMembersV2 reads the top-level members of the contract from its own
// bytes, in their order, and admits only the fifteen of LIP-0014 section 3
// whose joined spans rebuild those bytes exactly. The display therefore shows
// octets that are hashed, never a value re-rendered from a decoded struct.
func contractMembersV2(raw []byte) ([]contractMember, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, false
	}
	var out []contractMember
	rebuilt := []byte{'{'}
	for d.More() {
		t, err := d.Token()
		name, ok := t.(string)
		var value json.RawMessage
		if err != nil || !ok || d.Decode(&value) != nil {
			return nil, false
		}
		key, ok := compactJSON(name)
		if !ok {
			return nil, false
		}
		if len(out) > 0 {
			rebuilt = append(rebuilt, ',')
		}
		rebuilt = append(append(append(rebuilt, key...), ':'), value...)
		out = append(out, contractMember{name, string(value)})
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF || !bytes.Equal(append(rebuilt, '}'), raw) {
		return nil, false
	}
	names := make([]string, len(out))
	for i, m := range out {
		names[i] = m.name
	}
	if !slices.Equal(names, contractV2Members) {
		return nil, false
	}
	return out, true
}

// depthZeroRoot reports the single right of LIP-0014 section 2 that carries
// no re-delegation, on a contract without a parent.
func depthZeroRoot(c TrustContractV2) bool {
	r := c.Delegate
	return r.Depth == 0 && len(r.Actions) == 0 && r.Budget == 0 && len(r.Slots) == 0 && len(r.Notaries) == 0 && r.Checkpoint == "" && c.ParentGrantID == "" && c.Ordinal == 0
}

// admitV2Display is the signer's own gate between a parsed contract and the
// display. It does not rely on the parser having refused: the typed contract
// must re-encode to exactly the signed bytes (so the scope text, worded from
// the typed members, describes those bytes), the profile string must be /2,
// and the right must be the depth-zero one, because the scope text states
// "cannot delegate" without condition.
func admitV2Display(raw []byte, c TrustContractV2) ([]contractMember, string) {
	again, ok := compactJSON(c)
	if !ok || !bytes.Equal(again, raw) {
		return nil, "CONTRACT_ENCODING"
	}
	if c.Profile != TrustContractV2Profile {
		return nil, "CONTRACT_PROFILE"
	}
	if !depthZeroRoot(c) {
		return nil, "CONTRACT_DEPTH"
	}
	members, ok := contractMembersV2(raw)
	if !ok {
		return nil, "CONTRACT_ENCODING"
	}
	return members, ""
}

// legacyLandlordValue admits only the landlord value that every v3 reader
// accepts: the LIP-0004 shape, whose landlord binding has the single member
// grant. A value with holders (LIP-0010 section 10) is refused: a reader that
// does not know that member refuses the value, and with it every v3 grant of
// the landlord, so a v3 grant must not be signed under it. The value is what
// the request states; this command reads no chain, and grant sign compares
// the on-chain value.
func legacyLandlordValue(valueHex, issuer string) ([]byte, *Failure) {
	value, err := hex.DecodeString(valueHex)
	if err != nil || len(value) == 0 || hex.EncodeToString(value) != valueHex {
		return nil, fail("BAD_INPUT")
	}
	v := classifyV3(value)
	if v.role != "landlord" {
		return nil, keychainRefuse("LANDLORD_NOT_V3")
	}
	if v.grantKey != issuer {
		return nil, keychainRefuse("LANDLORD_KEY_MISMATCH")
	}
	return value, nil
}

// checkSignV2 is the /2 counterpart of checkDraft for keychain sign. It
// accepts only the /2 draft record, rebinds every draft field to the contract
// with the checker that grant consent and grant sign use, and then applies
// the signer's own gate and the landlord value rule.
func checkSignV2(r KeychainSignRequest) ([]byte, *signV2, *Failure) {
	d := r.Draft
	if d.Schema != GrantRecordV2Schema || r.LandlordValueHex == nil {
		return nil, nil, fail("BAD_INPUT")
	}
	raw, checked, f := checkDraftForGrant(d)
	if f != nil {
		return nil, nil, f
	}
	c, ok := checked.(TrustContractV2)
	if !ok {
		return nil, nil, fail("INTERNAL")
	}
	members, code := admitV2Display(raw, c)
	if code != "" {
		return nil, nil, refuse(code)
	}
	doc, code := decodeScopeTextV2(d.ScopeTextB64)
	if code != "" || verifyScopeTextV2(c, doc) != "" {
		return nil, nil, refuse("SCOPE_TEXT_HASH")
	}
	value, f := legacyLandlordValue(*r.LandlordValueHex, d.IssuerKey)
	if f != nil {
		return nil, nil, f
	}
	return raw, &signV2{c, members, value, doc}, nil
}

// escapeBytes shows octets on the terminal. Printable ASCII passes; every
// other byte is \xNN. With backslash set, a backslash is \x5c as well, so
// free text cannot spell an escape of its own.
func escapeBytes(b []byte, backslash bool) string {
	var s strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f && !(backslash && c == '\\') {
			s.WriteByte(c)
		} else {
			fmt.Fprintf(&s, "\\x%02x", c)
		}
	}
	return s.String()
}

// The wording of each action follows the table of LIP-0013 section 2.2,
// which LIP-0014 section 3 keeps for profile /2.
var scopeActionsV2 = []struct{ name, granted, withheld string }{
	{"instruct", "the grantee may assign the agent work: tasks, requests, priorities.", "the grantee may not assign the agent work."},
	{"land", "the grantee may authorize a landing into the default branch of each repository listed below.", "the grantee may not authorize a landing into any repository."},
	{"review", "the grantee's review verdicts count as reviews for the agent's landing gates, within each repository's reviewer policy.", "the grantee's review verdicts do not count for the agent's landing gates."},
	{"spend", "the grantee may request NMC payments up to the spend budget below in total, fees included.", "the grantee may not request any payment."},
}

// scopeTextV2 words the terms in plain language. Its only input is the typed
// contract that admitV2Display bound to the signed bytes: no member of the
// request, no draft field and no free text enters it. The note is counted
// and never quoted; the separate scope document is named by its hash only.
func scopeTextV2(c TrustContractV2) []string {
	out := []string{fmt.Sprintf("The landlord %s lets the holder of the key %s direct its agent %s on network %s.", c.LandlordName, c.GranteeKey, c.AgentName, c.Network)}
	for _, a := range scopeActionsV2 {
		if slices.Contains(c.Actions, a.name) {
			out = append(out, fmt.Sprintf("GRANTED %s: %s", a.name, a.granted))
		} else {
			out = append(out, fmt.Sprintf("NOT GRANTED %s: %s", a.name, a.withheld))
		}
	}
	if len(c.Repos) == 0 {
		out = append(out, "Repositories: none.")
	} else {
		out = append(out, fmt.Sprintf("Repositories (%d), for landing only:", len(c.Repos)))
		for _, r := range c.Repos {
			out = append(out, "  - "+r)
		}
	}
	if c.SpendBudget == 0 {
		out = append(out, "Spend budget: 0 atoms; no payment may be requested.")
	} else {
		out = append(out, fmt.Sprintf("Spend budget: %d atoms in total, fees included.", c.SpendBudget))
	}
	out = append(out, fmt.Sprintf("Window: not before %d (%s), not after %d (%s).", c.NotBefore, utc(c.NotBefore), c.NotAfter, utc(c.NotAfter)))
	out = append(out, "Delegation: depth 0; the grantee cannot delegate: no child grant may be issued under this grant.")
	out = append(out, "Parent: none; this is a root grant (ordinal 0).")
	if c.ScopeTextSHA256 == "" {
		out = append(out, "Scope document: none is bound.")
	} else {
		out = append(out, fmt.Sprintf("Scope document: one separate text is bound by its SHA-256 %s; it can only narrow the terms above.", c.ScopeTextSHA256))
	}
	if c.Note == "" {
		out = append(out, "Note: empty.")
	} else {
		out = append(out, fmt.Sprintf("Note: %d bytes, shown as member 15; a note grants nothing and limits nothing.", len(c.Note)))
	}
	return out
}

// renderSignRequestV2 is every field the human approves for a /2 request.
// The confirmation covers exactly this text. The signature and seal-spend
// sections are those of sign/1.
func renderSignRequestV2(r KeychainSignRequest, v2 *signV2, key KeychainPublic, items []signItem, spend *sealSpendPlan, inspectable bool) string {
	d := r.Draft
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("\n=== SWARMA GRANT KEY: SIGNING REQUEST ===\n")
	w("Request schema     : %s (draft record %s)\n", KeychainSignV2Schema, d.Schema)
	w("Keychain label     : %s\n", key.Label)
	w("Access policy      : %s (this-device-only)\n", key.AccessPolicy)
	if !inspectable {
		w("Native ACL flags   : unavailable through public Security APIs; authenticated policy metadata is checked before signing.\n")
	}
	w("Signing key x-only : %s\n", key.XOnlyKey)
	w("Signing key P2PKH  : %s\n", key.P2PKHAddress)
	w("Network            : %s (genesis %s)\n", d.Network, d.Genesis)
	w("Landlord value     : %d bytes as stated by the request, not read from the chain; legacy form, no holders; its grant key is the signing key\n", len(v2.value))
	w("  %s\n", escapeBytes(v2.value, false))
	w("Landlord           : %s\n", d.LandlordName)
	w("Agent              : %s\n", d.AgentName)
	w("Grantee key        : %s\n", d.GranteeKey)
	if d.GranteeName != "" {
		w("Grantee name       : %s\n", d.GranteeName)
	}
	scope := "(none)"
	if len(d.Scope) > 0 {
		scope = strings.Join(d.Scope, ", ")
	}
	w("Grant v3 scope     : %s\n", scope)
	w("Grant v3 budget    : %d sat\n", d.Budget)
	w("Window             : %d (%s) .. %d (%s)\n", d.NotBefore, utc(d.NotBefore), d.NotAfter, utc(d.NotAfter))
	w("Contract SHA-256   : %s\n", d.ContractSHA256)
	w("Seal outpoint      : %s:%d\n", d.Seal.TxID, d.Seal.Vout)
	w("Trust contract     : %s, all %d members in the order of LIP-0014 section 3, each value as it stands in the signed bytes\n", v2.contract.Profile, len(v2.members))
	for i, m := range v2.members {
		w("  %2d %-17s = %s\n", i+1, m.name, escapeBytes([]byte(m.value), false))
	}
	w("SCOPE TEXT         : worded by this signer from the members above only; no wording comes from the request\n")
	for _, line := range scopeTextV2(v2.contract) {
		w("  %s\n", line)
	}
	if v2.scopeDoc == nil {
		w("Scope document     : none\n")
	} else {
		w("Scope document     : %d bytes of free text supplied with the draft; its SHA-256 %s equals member 11. Each line below ends at a line feed (\\x0a); other bytes outside printable ASCII, and the backslash, are \\xNN\n", len(v2.scopeDoc), sha256Hex(v2.scopeDoc))
		for _, line := range bytes.SplitAfter(v2.scopeDoc, []byte("\n")) {
			if len(line) > 0 {
				w("    | %s\n", escapeBytes(line, true))
			}
		}
	}
	for i, it := range items {
		w("Signature %d        : BIP-340, purpose %s\n", i+1, it.purpose)
		w("  digest           : %x\n", it.digest)
		renderPreimage(w, it, d)
	}
	if spend != nil {
		renderSealSpend(w, spend)
	}
	n := len(items)
	if spend != nil {
		n++
	}
	if key.AccessPolicy == keypolicy.OrPasscode {
		w("Each of the %d signature(s) asks for biometry or the device passcode/password separately.\n", n)
	} else {
		w("Each of the %d signature(s) asks for Touch ID separately.\n", n)
	}
	return b.String()
}
