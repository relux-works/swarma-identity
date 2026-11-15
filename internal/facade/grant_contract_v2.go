package facade

import (
	"context"
	"encoding/base64"
	"slices"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

const (
	GrantDraftV2Schema     = "swarma-trust/draft/2"
	GrantRecordV2Schema    = "swarma-trust/draft-record/2"
	ContractVerifyV2Schema = "swarma-trust/contract-verify/2"
)

// GrantDraftV2Request keeps the separate scope document out of the closed
// contract. Omission means no text; a present empty base64 string is an empty
// document, whose hash is SHA256(empty), not the empty hash sentinel.
type GrantDraftV2Request struct {
	Schema           string          `json:"schema"`
	Contract         TrustContractV2 `json:"contract"`
	ScopeTextB64     *string         `json:"scope_text_b64,omitempty"`
	GranteeName      string          `json:"grantee_name,omitempty"`
	Seal             rental.Point    `json:"seal"`
	ConsentCreatedAt int64           `json:"consent_created_at"`
}

type GrantDraftV2Result struct {
	Draft       GrantDraft      `json:"draft"`
	Contract    TrustContractV2 `json:"contract"`
	ToSign      []SigningDigest `json:"to_sign"`
	ObservedTip Tip             `json:"observed_tip"`
}

// ContractVerifyV2Request pins the expected public grant key explicitly.
// This offline signature check establishes no on-chain identity or liveness.
type ContractVerifyV2Request struct {
	Schema       string  `json:"schema"`
	ContractB64  string  `json:"contract_b64"`
	ScopeTextB64 *string `json:"scope_text_b64,omitempty"`
	IssuerKey    string  `json:"issuer_key"`
	LandlordSig  string  `json:"landlord_sig"`
}

type ContractVerifyV2Result struct {
	Contract       TrustContractV2 `json:"contract"`
	ContractSHA256 string          `json:"contract_sha256"`
	SignatureValid bool            `json:"signature_valid"`
	ScopeTextB64   *string         `json:"scope_text_b64,omitempty"`
}

func decodeContractV2B64(s string) ([]byte, string) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, "CONTRACT_ENCODING"
	}
	return b, ""
}

func decodeScopeTextV2(s *string) ([]byte, string) {
	if s == nil {
		return nil, ""
	}
	b, err := base64.StdEncoding.Strict().DecodeString(*s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != *s {
		return nil, "SCOPE_TEXT_HASH"
	}
	// Preserve present empty documents, independently of decoder allocation.
	return append([]byte{}, b...), ""
}

// IssueTrustContractV2 returns only canonical unsigned bytes. The caller
// supplies every typed member, including the hash of the separate exact-octet
// text (LIP-0014 sections 3, 3.3); no member or permission is synthesized.
func IssueTrustContractV2(c TrustContractV2, text []byte) ([]byte, string) {
	raw, code := EncodeTrustContractV2(c)
	if code != "" {
		return nil, code
	}
	// A child needs the depth-one parent and certification checks of section 8.
	// They are not implemented here, so issuance and verification refuse it.
	if c.ParentGrantID != "" {
		return nil, "CONTRACT_DEPTH"
	}
	if code := verifyScopeTextV2(c, text); code != "" {
		return nil, code
	}
	return raw, ""
}

// VerifyTrustContractV2 verifies the canonical contract, exact scope octets and
// public landlord countersignature. LIP-0014 section 3.2 retains LIP-0004
// section 3: BIP-340 over the raw contract SHA256, with no new prefix.
// Success is an offline check under the supplied key, never a live grant.
func VerifyTrustContractV2(raw, text []byte, issuerKey, landlordSig string) (TrustContractV2, string) {
	c, code := ParseTrustContractV2(raw)
	if code != "" {
		return TrustContractV2{}, code
	}
	if c.ParentGrantID != "" {
		return TrustContractV2{}, "CONTRACT_DEPTH"
	}
	if code := verifyScopeTextV2(c, text); code != "" {
		return TrustContractV2{}, code
	}
	if !sigValid(issuerKey, sha256Hex(raw), landlordSig) {
		return TrustContractV2{}, "LANDLORD_SIGNATURE"
	}
	return c, ""
}

// bindTrustContractV2 retains all six checks of LIP-0013 section 2.5, with
// the section 3.1 /2 parser substituted as LIP-0014 section 3.2 requires.
func bindTrustContractV2(raw []byte, g trustGrantView) (TrustContractV2, string) {
	if sha256Hex(raw) != g.ContractSHA256 {
		return TrustContractV2{}, "CONTRACT_HASH"
	}
	c, code := ParseTrustContractV2(raw)
	if code != "" {
		return TrustContractV2{}, code
	}
	if c.Network != g.Network || c.LandlordName != g.LandlordName || c.AgentName != g.AgentName || c.GranteeKey != g.GranteeKey || c.NotBefore != g.NotBefore || c.NotAfter != g.NotAfter {
		return TrustContractV2{}, "CONTRACT_MISMATCH"
	}
	if g.Scope == nil || !slices.Equal(trustScope(c.Actions), g.Scope) {
		return TrustContractV2{}, "SCOPE_MISMATCH"
	}
	if c.SpendBudget != g.Budget {
		return TrustContractV2{}, "BUDGET_MISMATCH"
	}
	if !slices.EqualFunc(trustConsentTags(raw), g.ConsentTags, slices.Equal[[]string]) {
		return TrustContractV2{}, "CONSENT_TAGS"
	}
	return c, ""
}

// checkDraftForGrant leaves /1's checker intact (including the Keychain's
// /1-only display). Only the explicit /2 record enters the new path.
func checkDraftForGrant(d GrantDraft) ([]byte, any, *Failure) {
	if d.Schema != GrantRecordV2Schema {
		return checkDraft(d)
	}
	if pinnedGenesis(d.Network) == "" || d.Genesis != pinnedGenesis(d.Network) {
		return nil, nil, refuse("NETWORK_PIN")
	}
	raw, code := decodeContractV2B64(d.ContractB64)
	if code != "" {
		return nil, nil, refuse(code)
	}
	t := d.ConsentTemplate
	c, code := bindTrustContractV2(raw, trustGrantView{d.Network, d.AgentName, d.LandlordName, d.GranteeKey, d.ContractSHA256, d.Scope, d.Budget, d.NotBefore, d.NotAfter, t.Tags})
	if code != "" {
		return nil, nil, refuse(code)
	}
	if c.ParentGrantID != "" {
		return nil, nil, refuse("CONTRACT_DEPTH")
	}
	text, code := decodeScopeTextV2(d.ScopeTextB64)
	if code != "" {
		return nil, nil, refuse(code)
	}
	if code := verifyScopeTextV2(c, text); code != "" {
		return nil, nil, refuse(code)
	}
	if !xOnlyKey(d.IssuerKey) || (d.GranteeName != "" && !v3Name(d.GranteeName)) || !lowerHex(d.Seal.TxID, 32) {
		return nil, nil, refuse("GRANT_FIELD")
	}
	if t.Pubkey != d.GranteeKey || t.Kind != consentKind || t.Content != "" {
		return nil, nil, refuse("CONSENT_BINDING")
	}
	if t.CreatedAt < 1 || t.CreatedAt >= d.NotAfter {
		return nil, nil, refuse("CONSENT_TIME")
	}
	if t.ID != consentEventID(t.Pubkey, t.CreatedAt, t.Kind, t.Tags, t.Content) {
		return nil, nil, refuse("CONSENT_ID")
	}
	return raw, c, nil
}

// DraftGrantV2 builds a root /2 contract and unsigned v3 fields, reusing the
// existing node read fence, seal ledger and public-signature flow. No key is
// opened, nothing is signed and no file is created by draft.
func (c *Client) DraftGrantV2(ctx context.Context, r GrantDraftV2Request, ledgerPath string) (*GrantDraftV2Result, *Failure) {
	if r.Schema != GrantDraftV2Schema {
		return nil, fail("BAD_INPUT")
	}
	tc := r.Contract
	genesis := pinnedGenesis(tc.Network)
	if genesis == "" || tc.Network != c.config.Network || c.config.Node.GenesisHash != genesis {
		return nil, refuse("NETWORK_PIN")
	}
	text, code := decodeScopeTextV2(r.ScopeTextB64)
	if code != "" {
		return nil, refuse(code)
	}
	raw, code := IssueTrustContractV2(tc, text)
	if code != "" {
		return nil, refuse(code)
	}
	if (r.GranteeName != "" && !v3Name(r.GranteeName)) || !lowerHex(r.Seal.TxID, 32) {
		return nil, refuse("GRANT_FIELD")
	}
	if r.ConsentCreatedAt < 1 || r.ConsentCreatedAt >= tc.NotAfter {
		return nil, refuse("CONSENT_TIME")
	}
	lockCtx, cancel := context.WithTimeout(ctx, grantSignBound)
	ledger, f := openSealLedger(lockCtx, ledgerPath, false)
	cancel()
	if f != nil {
		return nil, f
	}
	reused := ledger.lookup(r.Seal.TxID, r.Seal.Vout) != ""
	ledger.close()
	if reused {
		return nil, refuse("SEAL_REUSED")
	}
	issuer, tip, f := c.grantIssuer(ctx, tc.LandlordName, tc.AgentName)
	if f != nil {
		return nil, f
	}
	tags := trustConsentTags(raw)
	t := ConsentTemplate{consentEventID(tc.GranteeKey, r.ConsentCreatedAt, consentKind, tags, ""), tc.GranteeKey, r.ConsentCreatedAt, consentKind, tags, ""}
	d := GrantDraft{
		Schema: GrantRecordV2Schema, Network: tc.Network, Genesis: genesis,
		LandlordName: tc.LandlordName, AgentName: tc.AgentName, IssuerKey: issuer,
		GranteeKey: tc.GranteeKey, GranteeName: r.GranteeName,
		ContractB64: base64.StdEncoding.EncodeToString(raw), ContractSHA256: sha256Hex(raw),
		Scope: trustScope(tc.Actions), Budget: tc.SpendBudget, NotBefore: tc.NotBefore, NotAfter: tc.NotAfter,
		Seal: r.Seal, ConsentTemplate: t, ScopeTextB64: r.ScopeTextB64,
	}
	if _, _, f := checkDraftForGrant(d); f != nil {
		return nil, fail("INTERNAL")
	}
	return &GrantDraftV2Result{d, tc, []SigningDigest{
		digestSigner("grantee", tc.GranteeKey, PurposeConsent, t.ID),
		digestSigner("landlord", issuer, PurposeContract, d.ContractSHA256),
	}, tip}, nil
}

// bindDraftContract selects /2 only for an explicit /2 draft record. It is
// shared with assembly, while the Keychain's own input gate stays /1-only.
func bindDraftContract(raw []byte, g trustGrantView, schema string) string {
	if schema == GrantRecordV2Schema {
		_, code := bindTrustContractV2(raw, g)
		return code
	}
	return bindTrustContract(raw, g)
}
