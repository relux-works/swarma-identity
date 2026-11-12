package facade

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// Grant issuance is two-phase: this CLI builds the exact bytes and the digests
// that each party signs with its own external signer, then verifies and
// assembles the returned signatures. It never reads, holds or asks for a
// private key; every signature arrives as public hex.
const (
	GrantDraftSchema   = "swarma-trust/draft/1"
	GrantRecordSchema  = "swarma-trust/draft-record/1"
	GrantConsentSchema = "swarma-trust/consent/1"
	GrantSignSchema    = "swarma-trust/sign/1"

	regtestGenesis = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
	consentKind    = 8181

	// grantSignBound is the total time grant sign may take, ledger lock wait
	// included.
	grantSignBound = 15 * time.Second
)

// Signing purposes. Each names one exact 32-byte BIP-340 message.
const (
	PurposeConsent  = "consent_event_id"   // NIP-01 id of the kind-8181 consent event
	PurposeContract = "contract_sha256"    // landlord_sig: the raw contract hash
	PurposeGrant    = "grant_signing_hash" // SHA-256("swarma-grant-v3" || canonical grant)
)

type GrantDraftRequest struct {
	Schema           string       `json:"schema"`
	Network          string       `json:"network"`
	LandlordName     string       `json:"landlord_name"`
	AgentName        string       `json:"agent_name"`
	GranteeKey       string       `json:"grantee_key"`
	GranteeName      string       `json:"grantee_name,omitempty"`
	Actions          []string     `json:"actions"`
	Repos            []string     `json:"repos"`
	SpendBudget      int64        `json:"spend_budget"`
	NotBefore        int64        `json:"not_before"`
	NotAfter         int64        `json:"not_after"`
	Note             string       `json:"note"`
	Seal             rental.Point `json:"seal"`
	ConsentCreatedAt int64        `json:"consent_created_at"`
}

// ConsentTemplate is the unsigned kind-8181 consent event with its NIP-01 id.
type ConsentTemplate struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
}

// GrantDraft is the record passed from draft to consent to sign. Every later
// step re-derives and re-checks it; nothing in it is trusted as given.
type GrantDraft struct {
	Schema          string          `json:"schema"`
	Network         string          `json:"network"`
	Genesis         string          `json:"genesis"`
	LandlordName    string          `json:"landlord_name"`
	AgentName       string          `json:"agent_name"`
	IssuerKey       string          `json:"issuer_key"`
	GranteeKey      string          `json:"grantee_key"`
	GranteeName     string          `json:"grantee_name,omitempty"`
	ContractB64     string          `json:"contract_b64"`
	ContractSHA256  string          `json:"contract_sha256"`
	Scope           []string        `json:"scope"`
	Budget          int64           `json:"budget"`
	NotBefore       int64           `json:"not_before"`
	NotAfter        int64           `json:"not_after"`
	Seal            rental.Point    `json:"seal"`
	ConsentTemplate ConsentTemplate `json:"consent_template"`
}

// SigningDigest names who signs which 32-byte message with which public key.
type SigningDigest struct {
	Signer  string `json:"signer"`
	Key     string `json:"key"`
	Purpose string `json:"purpose"`
	Digest  string `json:"digest"`
}

type GrantDraftResult struct {
	Draft       GrantDraft      `json:"draft"`
	Contract    TrustContract   `json:"contract"`
	ToSign      []SigningDigest `json:"to_sign"`
	ObservedTip Tip             `json:"observed_tip"`
}

type GrantConsentRequest struct {
	Schema       string        `json:"schema"`
	Draft        GrantDraft    `json:"draft"`
	ConsentEvent *rental.Event `json:"consent_event,omitempty"`
	ConsentSig   string        `json:"consent_sig,omitempty"`
}

type GrantConsentResult struct {
	ConsentEvent rental.Event    `json:"consent_event"`
	Contract     TrustContract   `json:"contract"`
	ToSign       []SigningDigest `json:"to_sign"`
}

type GrantSignRequest struct {
	Schema       string       `json:"schema"`
	Draft        GrantDraft   `json:"draft"`
	ConsentEvent rental.Event `json:"consent_event"`
	LandlordSig  string       `json:"landlord_sig"`
	GrantSig     string       `json:"grant_sig,omitempty"`
}

// GrantSignResult has stage "grant_hash" (no grant_sig was supplied: the
// landlord must now sign grant_signing_hash) or "signed".
type GrantSignResult struct {
	Stage            string              `json:"stage"`
	GrantSigningHash string              `json:"grant_signing_hash"`
	GrantB64         string              `json:"grant_b64,omitempty"`
	ToSign           []SigningDigest     `json:"to_sign,omitempty"`
	SignedGrant      *rental.SignedGrant `json:"signed_grant,omitempty"`
	SignedGrantB64   string              `json:"signed_grant_b64,omitempty"`
	GrantID          string              `json:"grant_id,omitempty"`
	Commitment       string              `json:"commitment,omitempty"`
	ContractB64      string              `json:"contract_b64"`
	ObservedTip      Tip                 `json:"observed_tip"`
}

// refuse is a named grant-contract refusal (exit 3, not retryable).
func refuse(code string) *Failure {
	return &Failure{Code: code, Message: "The grant input is refused by the trust-grant contract.", Exit: 3}
}

func pinnedGenesis(network string) string {
	switch network {
	case "main":
		return MainGenesis
	case "regtest":
		return regtestGenesis
	}
	return ""
}

// consentEventID is the NIP-01 id over [0,pubkey,created_at,kind,tags,content]
// with the encoder chain-lab uses for event bytes.
func consentEventID(pubkey string, createdAt int64, kind int, tags [][]string, content string) string {
	b, _ := compactJSON([]any{0, pubkey, createdAt, kind, tags, content})
	return sha256Hex(b)
}

func digestSigner(signer, key, purpose, digest string) SigningDigest {
	return SigningDigest{signer, key, purpose, digest}
}

// sigValid verifies one BIP-340 signature given as 128 lowercase hex.
func sigValid(key, digest, sig string) bool {
	return lowerHex(sig, 64) && rental.VerifySignature(key, digest, sig)
}

// checkDraft re-derives every draft member from the contract bytes and refuses
// a record whose grant fields disagree with its contract.
func checkDraft(d GrantDraft) ([]byte, TrustContract, *Failure) {
	if d.Schema != GrantRecordSchema {
		return nil, TrustContract{}, fail("BAD_INPUT")
	}
	if pinnedGenesis(d.Network) == "" || d.Genesis != pinnedGenesis(d.Network) {
		return nil, TrustContract{}, refuse("NETWORK_PIN")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(d.ContractB64)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != d.ContractB64 {
		return nil, TrustContract{}, refuse("CONTRACT_ENCODING")
	}
	t := d.ConsentTemplate
	if code := bindTrustContract(raw, trustGrantView{d.Network, d.AgentName, d.LandlordName, d.GranteeKey, d.ContractSHA256, d.Scope, d.Budget, d.NotBefore, d.NotAfter, t.Tags}); code != "" {
		return nil, TrustContract{}, refuse(code)
	}
	c, _ := ParseTrustContract(raw)
	if !xOnlyKey(d.IssuerKey) || (d.GranteeName != "" && !v3Name(d.GranteeName)) || !lowerHex(d.Seal.TxID, 32) {
		return nil, TrustContract{}, refuse("GRANT_FIELD")
	}
	if t.Pubkey != d.GranteeKey || t.Kind != consentKind || t.Content != "" {
		return nil, TrustContract{}, refuse("CONSENT_BINDING")
	}
	if t.CreatedAt < 1 || t.CreatedAt >= d.NotAfter {
		return nil, TrustContract{}, refuse("CONSENT_TIME")
	}
	if t.ID != consentEventID(t.Pubkey, t.CreatedAt, t.Kind, t.Tags, t.Content) {
		return nil, TrustContract{}, refuse("CONSENT_ID")
	}
	return raw, c, nil
}

// checkConsent verifies a signed consent event against the draft: the grantee
// is its signer, it carries exactly the trust consent fields, and its id and
// BIP-340 signature verify. Its created_at may differ from the template.
func checkConsent(d GrantDraft, raw []byte, e rental.Event) *Failure {
	if e.Pubkey != d.GranteeKey {
		return refuse("CONSENT_SIGNER")
	}
	tags, _ := compactJSON(e.Tags)
	want, _ := compactJSON(trustConsentTags(raw))
	if e.Kind != consentKind || e.Content != "" || string(tags) != string(want) {
		return refuse("CONSENT_BINDING")
	}
	if e.CreatedAt < 1 || e.CreatedAt >= d.NotAfter {
		return refuse("CONSENT_TIME")
	}
	if e.ID != consentEventID(e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content) {
		return refuse("CONSENT_ID")
	}
	if !sigValid(d.GranteeKey, e.ID, e.Sig) {
		return refuse("CONSENT_SIGNATURE")
	}
	return nil
}

// grantIssuer reads the agent and its landlord under one tip observation and
// returns the landlord's current on-chain grant key.
func (c *Client) grantIssuer(ctx context.Context, landlordName, agentName string) (string, Tip, *Failure) {
	id, f := c.Identity(ctx, agentName)
	if f != nil {
		return "", Tip{}, f
	}
	if id.Role != "agent" {
		return "", Tip{}, refuse("AGENT_NOT_V3")
	}
	if id.Landlord != landlordName {
		return "", Tip{}, refuse("AGENT_LANDLORD_MISMATCH")
	}
	if id.Reason != "" || id.LandlordResolved == nil || id.LandlordResolved.Name != landlordName || !xOnlyKey(id.LandlordResolved.GrantKey) {
		return "", Tip{}, refuse("LANDLORD_NOT_V3")
	}
	return id.LandlordResolved.GrantKey, id.ObservedTip, nil
}

// DraftGrant builds the trust contract and the unsigned v3 grant fields for one
// issuance. It signs nothing and creates no file.
func (c *Client) DraftGrant(ctx context.Context, r GrantDraftRequest, ledgerPath string) (*GrantDraftResult, *Failure) {
	if r.Schema != GrantDraftSchema || r.Actions == nil || r.Repos == nil {
		return nil, fail("BAD_INPUT")
	}
	genesis := pinnedGenesis(r.Network)
	if genesis == "" || r.Network != c.config.Network || c.config.Node.GenesisHash != genesis {
		return nil, refuse("NETWORK_PIN")
	}
	tc := TrustContract{TrustContractProfile, r.Network, r.LandlordName, r.AgentName, r.GranteeKey, r.Actions, r.Repos, r.SpendBudget, r.NotBefore, r.NotAfter, r.Note}
	raw, code := EncodeTrustContract(tc)
	if code != "" {
		return nil, refuse(code)
	}
	if (r.GranteeName != "" && !v3Name(r.GranteeName)) || !lowerHex(r.Seal.TxID, 32) {
		return nil, refuse("GRANT_FIELD")
	}
	if r.ConsentCreatedAt < 1 || r.ConsentCreatedAt >= r.NotAfter {
		return nil, refuse("CONSENT_TIME")
	}
	// The shared ledger lock is held only for the read, bounded like a sign.
	lockCtx, lockCancel := context.WithTimeout(ctx, grantSignBound)
	ledger, f := openSealLedger(lockCtx, ledgerPath, false)
	lockCancel()
	if f != nil {
		return nil, f
	}
	if ledger.lookup(r.Seal.TxID, r.Seal.Vout) != "" {
		ledger.close()
		return nil, refuse("SEAL_REUSED")
	}
	ledger.close()
	issuer, tip, f := c.grantIssuer(ctx, r.LandlordName, r.AgentName)
	if f != nil {
		return nil, f
	}
	tags := trustConsentTags(raw)
	t := ConsentTemplate{consentEventID(r.GranteeKey, r.ConsentCreatedAt, consentKind, tags, ""), r.GranteeKey, r.ConsentCreatedAt, consentKind, tags, ""}
	d := GrantDraft{GrantRecordSchema, r.Network, genesis, r.LandlordName, r.AgentName, issuer, r.GranteeKey, r.GranteeName, base64.StdEncoding.EncodeToString(raw), sha256Hex(raw), trustScope(r.Actions), r.SpendBudget, r.NotBefore, r.NotAfter, r.Seal, t}
	if _, _, f := checkDraft(d); f != nil {
		return nil, fail("INTERNAL")
	}
	return &GrantDraftResult{d, tc, []SigningDigest{
		digestSigner("grantee", d.GranteeKey, PurposeConsent, t.ID),
		digestSigner("landlord", issuer, PurposeContract, d.ContractSHA256),
	}, tip}, nil
}

// ConsentGrant verifies the grantee's externally signed consent offline: either
// a complete kind-8181 event or a bare BIP-340 signature over the drafted id.
func ConsentGrant(r GrantConsentRequest) (*GrantConsentResult, *Failure) {
	if r.Schema != GrantConsentSchema || (r.ConsentEvent == nil) == (r.ConsentSig == "") {
		return nil, fail("BAD_INPUT")
	}
	raw, tc, f := checkDraft(r.Draft)
	if f != nil {
		return nil, f
	}
	var e rental.Event
	if r.ConsentEvent != nil {
		e = *r.ConsentEvent
	} else {
		t := r.Draft.ConsentTemplate
		e = rental.Event{ID: t.ID, Pubkey: t.Pubkey, CreatedAt: t.CreatedAt, Kind: t.Kind, Tags: t.Tags, Content: t.Content, Sig: r.ConsentSig}
	}
	if f := checkConsent(r.Draft, raw, e); f != nil {
		return nil, f
	}
	return &GrantConsentResult{e, tc, []SigningDigest{digestSigner("landlord", r.Draft.IssuerKey, PurposeContract, r.Draft.ContractSHA256)}}, nil
}

// SignGrant verifies the landlord's external signatures against the landlord's
// current on-chain grant key and assembles the signed v3 grant. Without
// grant_sig it returns the grant signing hash, which exists only once the
// consent and landlord_sig it covers are known.
func (c *Client) SignGrant(ctx context.Context, r GrantSignRequest, ledgerPath string) (*GrantSignResult, *Failure) {
	if r.Schema != GrantSignSchema {
		return nil, fail("BAD_INPUT")
	}
	// One total bound covers the ledger lock wait and the node reads; an
	// earlier caller deadline or cancellation ends both sooner.
	ctx, cancel := context.WithTimeout(ctx, grantSignBound)
	defer cancel()
	d := r.Draft
	if d.Network != c.config.Network || c.config.Node.GenesisHash != pinnedGenesis(d.Network) {
		return nil, refuse("NETWORK_PIN")
	}
	raw, _, f := checkDraft(d)
	if f != nil {
		return nil, f
	}
	if f := checkConsent(d, raw, r.ConsentEvent); f != nil {
		return nil, f
	}
	final := r.GrantSig != ""
	ledger, f := openSealLedger(ctx, ledgerPath, final)
	if f != nil {
		return nil, f
	}
	defer ledger.close()
	recorded := ledger.lookup(d.Seal.TxID, d.Seal.Vout)
	if recorded != "" && !final {
		return nil, refuse("SEAL_REUSED")
	}
	onChain, tip, f := c.grantIssuer(ctx, d.LandlordName, d.AgentName)
	if f != nil {
		return nil, f
	}
	if onChain != d.IssuerKey {
		return nil, refuse("LANDLORD_KEY_MISMATCH")
	}
	if !sigValid(onChain, d.ContractSHA256, r.LandlordSig) {
		return nil, refuse("LANDLORD_SIGNATURE")
	}
	g, f := assembleGrant(d, raw, r.ConsentEvent, r.LandlordSig, onChain)
	if f != nil {
		return nil, f
	}
	unsigned, err := g.Canonical()
	if err != nil {
		return nil, rentalRefusal(err)
	}
	hash, err := g.SigningHash()
	if err != nil {
		return nil, rentalRefusal(err)
	}
	result := &GrantSignResult{Stage: "grant_hash", GrantSigningHash: hash, ContractB64: d.ContractB64, ObservedTip: tip}
	if !final {
		result.GrantB64 = base64.StdEncoding.EncodeToString(unsigned)
		result.ToSign = []SigningDigest{digestSigner("landlord", onChain, PurposeGrant, hash)}
		return result, nil
	}
	if !sigValid(onChain, hash, r.GrantSig) {
		return nil, refuse("GRANT_SIGNATURE")
	}
	signed := rental.SignedGrant{Grant: g, Signature: r.GrantSig}
	signedRaw, err := json.Marshal(signed)
	if err != nil {
		return nil, fail("INTERNAL")
	}
	parsed, err := rental.ParseSignedGrant(signedRaw)
	if err != nil {
		return nil, rentalRefusal(err)
	}
	commitment, err := rental.IssuanceCommitment(parsed)
	if err != nil {
		return nil, rentalRefusal(err)
	}
	id := parsed.ID()
	if recorded != "" && recorded != id {
		return nil, refuse("SEAL_REUSED")
	}
	if recorded == "" {
		if f := ledger.record(SealEntry{d.Seal.TxID, d.Seal.Vout, id}); f != nil {
			return nil, f
		}
	}
	result.Stage = "signed"
	result.SignedGrant = &parsed
	result.SignedGrantB64 = base64.StdEncoding.EncodeToString(signedRaw)
	result.GrantID = id
	result.Commitment = commitment
	return result, nil
}

// rentalRefusal passes a chain-lab refusal code through unchanged. Codes are
// fixed upper-case identifiers; anything else is reported as INTERNAL.
func rentalRefusal(err error) *Failure {
	code := err.Error()
	if code == "" || len(code) > 64 || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_") != "" {
		return fail("INTERNAL")
	}
	return refuse(code)
}

// pinnedNetwork returns the network when it is a grant network, else "".
func pinnedNetwork(network string) string {
	if pinnedGenesis(network) == "" {
		return ""
	}
	return network
}
