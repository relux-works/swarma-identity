package facade

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/relux-works/swarma-identity/internal/grantv4"
)

const KeychainV4Schema = "swarma-keychain/v4/1"

type KeychainV4Request struct {
	Schema           string `json:"schema"`
	PayloadHex       string `json:"payload_hex"`
	ParentHex        string `json:"parent_hex,omitempty"`
	LandlordValueHex string `json:"landlord_value_hex"`
}

// The signer never treats a stated landlord value as chain evidence. Its raw
// bytes are bounded and escaped, and its stated grant key must match the root
// of the reviewed path. Pinned holders outside swarma are not grant authority.
func statedValueV4(s string, root *grantv4.Grant) ([]byte, *Failure) {
	raw, f := decodeV4(s, false)
	if f != nil {
		return nil, f
	}
	if len(raw) > 520 {
		return nil, fail("BAD_INPUT")
	}
	if validateJSON(raw) != nil {
		return nil, fail("BAD_INPUT")
	}
	var value, swarma, landlord map[string]json.RawMessage
	var grantKey string
	// Exact map lookups avoid encoding/json's case-insensitive struct-field
	// matching. No alias is interpreted as the stated grant-key member.
	if json.Unmarshal(raw, &value) != nil || json.Unmarshal(value["swarma"], &swarma) != nil || json.Unmarshal(swarma["landlord"], &landlord) != nil || json.Unmarshal(landlord["grant"], &grantKey) != nil || grantKey != root.Signer() {
		return nil, statedValueRefuse("STATED_LANDLORD_VALUE_KEY_MISMATCH")
	}
	return raw, nil
}

// scopeTextV4 states only what the signed members say. Action and limit
// registries are open at this pin, so the signer assigns no invented meaning
// to an action, unit or period. It makes no liveness or landlord assertion.
func scopeTextV4(g *grantv4.Grant) []string {
	var p struct {
		Actions  []string          `json:"actions"`
		Limits   []json.RawMessage `json:"limits"`
		Before   uint64            `json:"not_before_height"`
		After    uint64            `json:"not_after_height"`
		Parent   string            `json:"parent"`
		Ordinal  uint64            `json:"ordinal"`
		Delegate *struct {
			Groups []struct {
				Ranges []struct {
					Count uint64 `json:"count"`
				} `json:"ranges"`
				Template struct {
					NoCertifier bool `json:"no_certifier"`
				} `json:"template"`
			} `json:"groups"`
		} `json:"delegate"`
	}
	if json.Unmarshal(g.Payload(), &p) != nil {
		panic("checked grant decoding")
	}
	lines := []string{
		"This is a statement of the document, not chain admission or proof of authority.",
		"Chain genesis: " + g.Genesis() + "; contract identifier: " + g.Contract() + ".",
		"Recipient constraint as signed: " + string(g.Recipient()) + ".",
		fmt.Sprintf("Window: heights [%d, %d), half-open; no calendar or clock is signed.", p.Before, p.After),
		fmt.Sprintf("Own action identifiers: %d; own limits: %d. All values are shown above; unknown registries give no inferred permission.", len(p.Actions), len(p.Limits)),
	}
	if g.Child() {
		lines = append(lines, fmt.Sprintf("Child: parent payload identifier %s, row ordinal %d; its delegation key must sign the child, never its messaging key.", p.Parent, p.Ordinal))
	} else {
		lines = append(lines, "Root issuer as signed: "+string(g.Issuer())+".")
	}
	if p.Delegate == nil {
		lines = append(lines, "No right of re-delegation is present.")
	} else {
		rows, ranges, uncertified := uint64(0), 0, 0
		for _, group := range p.Delegate.Groups {
			ranges += len(group.Ranges)
			if group.Template.NoCertifier {
				uncertified++
			}
			for _, r := range group.Ranges {
				rows += r.Count
			}
		}
		lines = append(lines, fmt.Sprintf("Delegation: %d groups, %d ranges, %d rows; %d groups explicitly state no_certifier. Every template, range, pool and pin is shown above.", len(p.Delegate.Groups), ranges, rows, uncertified))
	}
	return lines
}

func renderV4(g *grantv4.Grant, value []byte, key KeychainPublic, assent []byte, assentDigest string) (string, *Failure) {
	var b strings.Builder
	fmt.Fprintf(&b, "\n=== SWARMA V4 DOCUMENT REVIEW ===\nKeychain label: %s\nSigning key x-only: %s\nAccess policy: %s (this-device-only)\n", key.Label, key.XOnlyKey, key.AccessPolicy)
	fmt.Fprintf(&b, "Landlord value: NOT VERIFIED BY THIS SIGNER. These %d bytes are stated by the request; no chain was read.\n  %s\n", len(value), escapeBytes(value, true))
	// A complete canonical payload and every leaf are both shown. Empty arrays
	// count as fields, so an omitted action or limit list cannot hide in prose.
	preimage := func(name string, raw []byte, digest string) bool {
		fields, ok := jsonLeaves(raw)
		if !ok || len(fields) > 8192 {
			return false
		}
		fmt.Fprintf(&b, "%s: tagged BIP-340 application digest %s\n", name, digest)
		var typed struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &typed) != nil {
			return false
		}
		fmt.Fprintf(&b, "  preimage: SHA256(tag) || SHA256(tag) || payload; tag = %q\n  committed fields (%d):\n", typed.Type, len(fields))
		for _, field := range fields {
			fmt.Fprintf(&b, "    %s\n", field)
		}
		fmt.Fprintf(&b, "  exact payload (%d bytes):\n", len(raw))
		for off := 0; off < len(raw); off += 64 {
			fmt.Fprintf(&b, "    %05d %s\n", off, escapeBytes(raw[off:min(off+64, len(raw))], true))
		}
		return true
	}
	if !preimage("Grant document (not signed by this command)", g.Payload(), g.Digest()) {
		return "", keychainRefuse("SCOPE_TEXT_SIZE")
	}
	if assent != nil && !preimage("ONLY SIGNATURE: root contract assent", assent, assentDigest) {
		return "", keychainRefuse("SCOPE_TEXT_SIZE")
	}
	fmt.Fprintf(&b, "Payload identifier: %s; this is not its typed digest or signed content address.\n", g.ID())
	// Derived scope is last, bounded, with no caller-provided text appended.
	b.WriteString("SCOPE TEXT: derived only from the checked members above\n")
	for _, line := range scopeTextV4(g) {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	if assent != nil {
		fmt.Fprintf(&b, "Approval covers ONLY the root contract assent digest %s. No grant signature or transaction will be made.\n", assentDigest)
	} else {
		b.WriteString("Review only: no confirmation and no signature will be requested.\n")
	}
	if b.Len() > 1048576 {
		return "", keychainRefuse("SCOPE_TEXT_SIZE")
	}
	return b.String(), nil
}

// signApprovedV4 is the ONE private-key call of the v4 path. A future issuer
// service can wrap this seam with its durable reservation/consent transaction.
// Today it signs root assents ONLY. It deliberately cannot issue a grant:
// W7.9 consumption and own-node issuer checks are not implemented here, and
// J4.4 child signing additionally needs authenticated callers and live rows.
func (deps keychainDeps) signApprovedV4(label string, key KeychainPublic, digest string) (string, *Failure) {
	d, e := hex.DecodeString(digest)
	if e != nil || len(d) != 32 {
		return "", fail("INTERNAL")
	}
	sig, e := deps.signer.SignSchnorr(label, "sign root contract assent [access: "+string(key.AccessPolicy)+"]", d, key.AccessPolicy)
	if e != nil {
		return "", keychainFailure(e)
	}
	signature := hex.EncodeToString(sig)
	if !grantv4.Verify(key.XOnlyKey, digest, signature) {
		return "", keychainRefuse("SIGNATURE_VERIFY")
	}
	return signature, nil
}

func executeKeychainV4(command string, args []string, deps keychainDeps) (string, any, *Failure) {
	o, f := keychainOptions(args, "request", "label")
	if f != nil {
		return "", nil, f
	}
	var r KeychainV4Request
	if f = inputV4(o["request"], &r); f != nil {
		return "", nil, f
	}
	if r.Schema != KeychainV4Schema || !validLabel(o["label"]) {
		return "", nil, fail("BAD_INPUT")
	}
	g, parent, f := draftV4(GrantV4Request{PayloadHex: r.PayloadHex, ParentHex: r.ParentHex})
	if f != nil {
		return "", nil, f
	}
	root := g
	if g.Child() {
		root = parent
	}
	value, f := statedValueV4(r.LandlordValueHex, root)
	if f != nil {
		return "", nil, f
	}
	var assent []byte
	var digest string
	if command == "keychain sign-v4" {
		var e error
		assent, digest, e = grantv4.AssentPayload(g)
		if e != nil {
			return "", nil, rentalRefusal(e)
		}
	}
	network := ""
	for _, n := range []string{"main", "regtest"} {
		if g.Genesis() == pinnedGenesis(n) {
			network = n
		}
	}
	if network == "" {
		return "", nil, refuse("NETWORK_PIN")
	}
	if deps.signer == nil {
		return network, nil, fail("UNSUPPORTED_CAPABILITY")
	}
	stored, e := deps.signer.Public(o["label"])
	if e != nil {
		return network, nil, keychainFailure(e)
	}
	pub, e := btcec.ParsePubKey(stored)
	if e != nil || len(stored) != 33 {
		return network, nil, keychainRefuse("KEY_ITEM_INVALID")
	}
	access, _, e := deps.signer.Access(o["label"])
	if e != nil {
		return network, nil, keychainFailure(e)
	}
	key, f := publicOf(o["label"], network, pub, access)
	if f != nil {
		return network, nil, f
	}
	if key.XOnlyKey != g.Signer() {
		return network, nil, keychainRefuse("KEY_MISMATCH")
	}
	shown, f := renderV4(g, value, key, assent, digest)
	if f != nil {
		return network, nil, f
	}
	term, e := deps.terminal()
	if e != nil {
		return network, nil, keychainRefuse("NO_TERMINAL")
	}
	if e = term.Show(shown); e != nil {
		return network, nil, keychainRefuse("NO_TERMINAL")
	}
	if command == "keychain review-v4" {
		return network, struct {
			Reviewed              bool `json:"reviewed"`
			GrantSignatureCreated bool `json:"grant_signature_created"`
		}{true, false}, nil
	}
	ok, e := term.Confirm("Type " + confirmWord + " to sign exactly the above, anything else declines: ")
	if e != nil || !ok {
		return network, nil, keychainRefuse("CONFIRMATION_DECLINED")
	}
	// Retain the exact approved bytes and verify the digest again at the seam.
	again, d, e := grantv4.AssentPayload(g)
	if e != nil || !bytes.Equal(again, assent) || d != digest {
		return network, nil, keychainRefuse("DIGEST_BINDING")
	}
	signature, f := deps.signApprovedV4(o["label"], key, digest)
	if f != nil {
		return network, nil, f
	}
	return network, struct {
		PayloadHex      string `json:"payload_hex"`
		TypedDigest     string `json:"typed_digest"`
		Signature       string `json:"signature"`
		SignedAssentHex string `json:"signed_assent_hex"`
	}{hex.EncodeToString(assent), digest, signature, hex.EncodeToString(signedAssentV4(g, signature))}, nil
}
