package facade

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-identity/internal/testsigner"
)

// Published BIP-340 test vector secret keys 0 to 3. They are public test
// data, never anyone's key; the test signer refuses every other key.
var bip340Secrets = []string{
	"0000000000000000000000000000000000000000000000000000000000000003",
	"b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
	"c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
	"0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
}

const (
	keyGrantee  = 0 // f9308a…36f9, the LIP-0013 vector grantee
	keyLandlord = 1 // dff1d77f…a659, the on-chain landlord grant key
	keyOther    = 2 // dd308afe…4eb8, a key that is neither
	keyRotated  = 3 // 25d1dff9…f517, a later landlord grant key

	sealA = "5555555555555555555555555555555555555555555555555555555555555555"
	sealB = "6666666666666666666666666666666666666666666666666666666666666666"
)

// canonicalTemp returns a fresh test directory with every symlink resolved.
// The key-file and ledger rules refuse any symlink path component, and on
// macOS the default temporary directory is under /var, a symlink to
// /private/var. Without this, every custody negative there would refuse for
// the wrong reason and every positive control would fail.
func canonicalTemp(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func testSigner(t *testing.T, index int) *testsigner.Signer {
	t.Helper()
	raw, _ := hex.DecodeString(bip340Secrets[index])
	p := filepath.Join(canonicalTemp(t), "test-key")
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := testsigner.Open(p)
	if err != nil {
		t.Fatalf("test signer %d: %v", index, err)
	}
	t.Cleanup(s.Close)
	return s
}

func sign(t *testing.T, s *testsigner.Signer, digest string) string {
	t.Helper()
	sig, err := s.Sign(digest)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func landlordValue(key string) string { return `{"swarma":{"landlord":{"grant":"` + key + `"}}}` }
func agentValue(landlord string) string {
	return `{"swarma":{"agent":{"nostr":"` + cedarKey + `","landlord":"` + landlord + `"}}}`
}

// grantNode is a loopback fake node on main or regtest that answers the
// read fence only. Records may change between commands (key rotation).
type grantNode struct {
	mu      sync.Mutex
	records map[string]idRecord
	methods []string
	config  string
}

func newGrantNode(t *testing.T, network string, records map[string]idRecord) *grantNode {
	t.Helper()
	return newGrantNodeGenesis(t, network, pinnedGenesis(network), records)
}

// newGrantNodeGenesis answers and configures an explicit genesis hash.
func newGrantNodeGenesis(t *testing.T, network, genesis string, records map[string]idRecord) *grantNode {
	t.Helper()
	n := &grantNode{records: records}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		defer n.mu.Unlock()
		var q struct {
			ID     int               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		n.methods = append(n.methods, q.Method)
		var value, rpcError any
		switch q.Method {
		case "getnetworkinfo":
			value = map[string]any{"version": 280000, "connections": 10}
		case "getblockchaininfo":
			value = map[string]any{"chain": network, "bestblockhash": fixtureTip, "blocks": 100, "headers": 100, "initialblockdownload": false, "verificationprogress": 1}
		case "getblockhash":
			value = genesis
		case "getbestblockhash":
			value = fixtureTip
		case "name_show":
			var name string
			json.Unmarshal(q.Params[0], &name)
			rec, ok := n.records[name]
			if !ok {
				rpcError = map[string]any{"code": -4, "message": "name never existed"}
				break
			}
			value = map[string]any{"name": name, "value": rec.value, "expired": rec.expiresIn <= 0, "expires_in": rec.expiresIn, "txid": strings.Repeat("3", 64), "vout": 0, "height": rec.height}
		default:
			t.Errorf("forbidden grant fixture method %s", q.Method)
			http.Error(w, "forbidden method", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": q.ID, "result": value, "error": rpcError})
	}))
	t.Cleanup(s.Close)
	c := testConfig(t, s.URL)
	c.Network, c.Node.GenesisHash = network, genesis
	n.config = writeInput(t, c)
	return n
}

func (n *grantNode) calls() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.methods)
}

func (n *grantNode) set(name, value string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.records[name] = activeRecord(value)
}

func resultAs[T any](t *testing.T, e Envelope) T {
	t.Helper()
	var v T
	b, _ := json.Marshal(e.Result)
	if err := DecodeStrict(b, &v); err != nil {
		t.Fatalf("result does not match its closed type: %s", b)
	}
	return v
}

// flow drives one issuance through the CLI and keeps every byte the CLI wrote.
type flow struct {
	t                  *testing.T
	node               *grantNode
	ledger             string
	grantee, landlord  *testsigner.Signer
	outputs            [][]byte
	draft              GrantDraftResult
	consent            GrantConsentResult
	landlordSig        string
	stage1, signed     GrantSignResult
	draftReq           GrantDraftRequest
	consentEventSigned rental.Event
}

func (f *flow) run(args ...string) (Envelope, int) {
	f.t.Helper()
	e, code, out := runCLI(f.t, append(args, "--json")...)
	f.outputs = append(f.outputs, out)
	return e, code
}

func (f *flow) draftCmd(r GrantDraftRequest) (Envelope, int) {
	return f.run("grant", "draft", "--config", f.node.config, "--request", writeInput(f.t, r), "--seal-ledger", f.ledger)
}

func (f *flow) consentCmd(r GrantConsentRequest) (Envelope, int) {
	return f.run("grant", "consent", "--request", writeInput(f.t, r))
}

func (f *flow) signCmd(r GrantSignRequest) (Envelope, int) {
	return f.run("grant", "sign", "--config", f.node.config, "--request", writeInput(f.t, r), "--seal-ledger", f.ledger)
}

func mustOK(t *testing.T, e Envelope, code int) {
	t.Helper()
	if code != 0 || !e.OK {
		t.Fatalf("command refused: exit %d %+v", code, e.Error)
	}
}

func mustRefuse(t *testing.T, e Envelope, code int, want string) {
	t.Helper()
	if code == 0 || e.OK || e.Error == nil || e.Error.Code != want || e.Result != nil {
		got := "none"
		if e.Error != nil {
			got = e.Error.Code
		}
		t.Fatalf("refusal %s (exit %d), want %s", got, code, want)
	}
}

// issue runs draft, consent (bare signature over the drafted id), sign stage
// grant_hash and sign stage signed, with the external test signers.
func (f *flow) issue(r GrantDraftRequest) {
	f.t.Helper()
	f.prepare(r)
	e, code := f.signCmd(f.finalRequest())
	mustOK(f.t, e, code)
	f.signed = resultAs[GrantSignResult](f.t, e)
}

// prepare runs every step before the final grant signature.
func (f *flow) prepare(r GrantDraftRequest) {
	t := f.t
	t.Helper()
	f.draftReq = r
	e, code := f.draftCmd(r)
	mustOK(t, e, code)
	f.draft = resultAs[GrantDraftResult](t, e)
	e, code = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: f.draft.Draft, ConsentSig: sign(t, f.grantee, f.draft.Draft.ConsentTemplate.ID)})
	mustOK(t, e, code)
	f.consent = resultAs[GrantConsentResult](t, e)
	f.landlordSig = sign(t, f.landlord, f.draft.Draft.ContractSHA256)
	e, code = f.signCmd(GrantSignRequest{Schema: GrantSignSchema, Draft: f.draft.Draft, ConsentEvent: f.consent.ConsentEvent, LandlordSig: f.landlordSig})
	mustOK(t, e, code)
	f.stage1 = resultAs[GrantSignResult](t, e)
}

func (f *flow) finalRequest() GrantSignRequest {
	return GrantSignRequest{Schema: GrantSignSchema, Draft: f.draft.Draft, ConsentEvent: f.consent.ConsentEvent, LandlordSig: f.landlordSig, GrantSig: sign(f.t, f.landlord, f.stage1.GrantSigningHash)}
}

func newFlow(t *testing.T, network, landlord, agent string) *flow {
	node := newGrantNode(t, network, map[string]idRecord{
		landlord: activeRecord(landlordValue(testsigner_public(t, keyLandlord))),
		agent:    activeRecord(agentValue(landlord)),
	})
	return &flow{t: t, node: node, ledger: filepath.Join(canonicalTemp(t), "seal-ledger.json"), grantee: testSigner(t, keyGrantee), landlord: testSigner(t, keyLandlord)}
}

func testsigner_public(t *testing.T, index int) string { return testSigner(t, index).PublicKey() }

func regtestRequest(actions, repos []string, budget int64) GrantDraftRequest {
	return GrantDraftRequest{Schema: GrantDraftSchema, Network: "regtest", LandlordName: "id/landlord-a", AgentName: "id/landlord-a-agent",
		GranteeKey: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", Actions: actions, Repos: repos, SpendBudget: budget,
		NotBefore: 1794528000, NotAfter: 1797120000, Note: "", Seal: rental.Point{TxID: sealA, Vout: 1}, ConsentCreatedAt: 1794527000}
}

// independentCommitment recomputes SHA-256("swarma-issue-v1" || contract ||
// consent id || consent sig || landlord_sig || grant_id) from LIP-0004 alone.
func independentCommitment(t *testing.T, raw []byte, s rental.SignedGrant) string {
	t.Helper()
	data := []byte("swarma-issue-v1")
	id := sha256.Sum256(raw)
	for _, v := range []string{s.Grant.ContractSHA256, s.Grant.Consent.ConsentEvent.ID, s.Grant.Consent.ConsentEvent.Sig, s.Grant.Consent.LandlordSig, hex.EncodeToString(id[:])} {
		b, err := hex.DecodeString(v)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, b...)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Claim (issuance acceptance): on a regtest-pinned node, draft → consent → sign with
// external signers yields a signed grant that rental.ParseSignedGrant accepts
// byte for byte, whose grant_id is SHA-256 of those bytes, whose commitment
// equals rental.IssuanceCommitment and an independent recomputation, whose
// presentation parses, and whose fields bind to the LIP-0013 contract.
// Limit: the node is a loopback fixture, not a Namecoin Core regtest daemon.
func TestGrantIssueRegtest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		actions []string
		repos   []string
		budget  int64
		scope   []string
	}{
		{"instruct-review", []string{"instruct", "review"}, []string{}, 0, []string{}},
		{"all-actions", []string{"instruct", "land", "review", "spend"}, []string{"https://github.com/relux-works/swarma-identity"}, 1000000, []string{"pay", "repository.push"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
			f.issue(regtestRequest(tc.actions, tc.repos, tc.budget))
			raw, err := base64.StdEncoding.DecodeString(f.signed.SignedGrantB64)
			if err != nil || f.signed.Stage != "signed" {
				t.Fatal("no signed grant bytes")
			}
			parsed, err := rental.ParseSignedGrant(raw)
			if err != nil {
				t.Fatalf("ParseSignedGrant refused: %v", err)
			}
			again, _ := json.Marshal(parsed)
			if !bytes.Equal(again, raw) || !reflect.DeepEqual(*f.signed.SignedGrant, parsed) {
				t.Fatal("signed grant object and bytes differ")
			}
			if sum := sha256.Sum256(raw); f.signed.GrantID != hex.EncodeToString(sum[:]) || f.signed.GrantID != parsed.ID() {
				t.Fatal("grant_id is not SHA-256 of the signed grant bytes")
			}
			commitment, err := rental.IssuanceCommitment(parsed)
			if err != nil || f.signed.Commitment != commitment || commitment != independentCommitment(t, raw, parsed) {
				t.Fatal("commitment differs from rental.IssuanceCommitment or the independent recomputation")
			}
			presentation, err := rental.PresentIssuedGrant(raw, strings.Repeat("7", 64))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rental.ParseGrantPresentation(presentation); err != nil {
				t.Fatalf("presentation refused: %v", err)
			}
			g := parsed.Grant
			if g.Network != "regtest" || g.Genesis != regtestGenesis || g.IssuerKey != f.landlord.PublicKey() || g.GranteeKey != f.grantee.PublicKey() || !reflect.DeepEqual(g.Scope, tc.scope) || g.BudgetSat() != tc.budget || (tc.budget == 0) != (g.Budget == nil) || g.Seal != (rental.Point{TxID: sealA, Vout: 1}) {
				t.Fatal("grant fields differ from the request")
			}
			contract, _ := base64.StdEncoding.DecodeString(f.signed.ContractB64)
			if code := bindTrustContract(contract, trustGrantView{g.Network, g.AgentName, g.LandlordName, g.GranteeKey, g.ContractSHA256, g.Scope, g.BudgetSat(), g.NotBefore, g.NotAfter, g.Consent.ConsentEvent.Tags}); code != "" {
				t.Fatalf("signed grant does not bind to its contract: %s", code)
			}
			// The stage-1 digest is the one rental signs over, and the
			// stage-1 bytes are the canonical unsigned grant.
			unsigned, _ := base64.StdEncoding.DecodeString(f.stage1.GrantB64)
			canonical, _ := g.Canonical()
			if hash, _ := g.SigningHash(); hash != f.stage1.GrantSigningHash || !bytes.Equal(unsigned, canonical) {
				t.Fatal("stage-1 grant bytes or signing hash differ from rental")
			}
			ledger, _ := os.ReadFile(f.ledger)
			if !bytes.Contains(ledger, []byte(`"grant_id":"`+f.signed.GrantID+`"`)) {
				t.Fatal("seal not recorded in the ledger")
			}
			assertNoSecrets(t, append(f.outputs, ledger))
		})
	}
}

// Claim: with the mainnet names of the LIP-0013 vectors, draft builds exactly
// each valid vector contract (bytes, hash, scope, budget, consent tags) and
// lists the two digests the parties sign. Limit: draft only; the landlord
// grant key in the fixture is a published test key, not id/ivanopcode's.
func TestGrantDraftReproducesLIP0013Vectors(t *testing.T) {
	for _, vc := range loadLIP0013(t).ValidContracts {
		t.Run(vc.ID, func(t *testing.T) {
			c, _ := ParseTrustContract([]byte(vc.Contract))
			f := newFlow(t, "main", c.LandlordName, c.AgentName)
			r := GrantDraftRequest{Schema: GrantDraftSchema, Network: c.Network, LandlordName: c.LandlordName, AgentName: c.AgentName, GranteeKey: c.GranteeKey, Actions: c.Actions, Repos: c.Repos, SpendBudget: c.SpendBudget, NotBefore: c.NotBefore, NotAfter: c.NotAfter, Note: c.Note, Seal: rental.Point{TxID: sealA}, ConsentCreatedAt: c.NotBefore}
			e, code := f.draftCmd(r)
			mustOK(t, e, code)
			d := resultAs[GrantDraftResult](t, e)
			raw, _ := base64.StdEncoding.DecodeString(d.Draft.ContractB64)
			if string(raw) != vc.Contract || d.Draft.ContractSHA256 != vc.SHA256 || !reflect.DeepEqual(d.Draft.Scope, vc.V3Scope) || d.Draft.Budget != vc.V3Budget || !reflect.DeepEqual(d.Draft.ConsentTemplate.Tags, vc.ConsentTags) {
				t.Fatal("draft differs from the LIP-0013 vector")
			}
			want := []SigningDigest{{"grantee", c.GranteeKey, PurposeConsent, d.Draft.ConsentTemplate.ID}, {"landlord", f.landlord.PublicKey(), PurposeContract, vc.SHA256}}
			if !reflect.DeepEqual(d.ToSign, want) || d.Draft.IssuerKey != f.landlord.PublicKey() {
				t.Fatal("digests to sign differ")
			}
			if _, err := os.Stat(f.ledger); !os.IsNotExist(err) {
				t.Fatal("draft created the seal ledger")
			}
		})
	}
}

// Claim: a consent signed by any key other than the grantee is refused, both as
// a bare signature over the drafted id and as a complete event that names the
// other key; the grantee's own bare signature and its own complete event with
// a different created_at are accepted. Nothing is assembled on a refusal.
func TestGrantConsentSignerNegatives(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	e, code := f.draftCmd(regtestRequest([]string{"instruct"}, []string{}, 0))
	mustOK(t, e, code)
	d := resultAs[GrantDraftResult](t, e).Draft
	other := testSigner(t, keyOther)
	tpl := d.ConsentTemplate

	e, code = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: d, ConsentSig: sign(t, f.grantee, tpl.ID)})
	mustOK(t, e, code) // neighbour: the grantee's bare signature

	e, code = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: d, ConsentSig: sign(t, other, tpl.ID)})
	mustRefuse(t, e, code, "CONSENT_SIGNATURE")

	own := rental.Event{Pubkey: f.grantee.PublicKey(), CreatedAt: tpl.CreatedAt + 60, Kind: 8181, Tags: tpl.Tags, Content: ""}
	own.ID = consentEventID(own.Pubkey, own.CreatedAt, own.Kind, own.Tags, own.Content)
	own.Sig = sign(t, f.grantee, own.ID)
	e, code = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: d, ConsentEvent: &own})
	mustOK(t, e, code) // neighbour: the grantee's own complete event
	if got := resultAs[GrantConsentResult](t, e).ConsentEvent; !reflect.DeepEqual(got, own) {
		t.Fatal("consent record differs from the signed event")
	}

	foreign := own
	foreign.Pubkey = other.PublicKey()
	foreign.ID = consentEventID(foreign.Pubkey, foreign.CreatedAt, foreign.Kind, foreign.Tags, foreign.Content)
	foreign.Sig = sign(t, other, foreign.ID)
	e, code = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: d, ConsentEvent: &foreign})
	mustRefuse(t, e, code, "CONSENT_SIGNER")

	forged := own
	forged.Sig = sign(t, other, own.ID)
	e, code = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: d, ConsentEvent: &forged})
	mustRefuse(t, e, code, "CONSENT_SIGNATURE")

	// The sign step re-checks the consent: a forged consent never reaches
	// the landlord's signatures.
	e, code = f.signCmd(GrantSignRequest{Schema: GrantSignSchema, Draft: d, ConsentEvent: forged, LandlordSig: sign(t, f.landlord, d.ContractSHA256)})
	mustRefuse(t, e, code, "CONSENT_SIGNATURE")

	tampered := own
	tampered.Tags = [][]string{tpl.Tags[0], tpl.Tags[1], {"booking", strings.Repeat("0", 64)}, tpl.Tags[3]}
	tampered.ID = consentEventID(tampered.Pubkey, tampered.CreatedAt, tampered.Kind, tampered.Tags, tampered.Content)
	tampered.Sig = sign(t, f.grantee, tampered.ID)
	e, code = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: d, ConsentEvent: &tampered})
	mustRefuse(t, e, code, "CONSENT_BINDING")

	late := own
	late.CreatedAt = d.NotAfter
	late.ID = consentEventID(late.Pubkey, late.CreatedAt, late.Kind, late.Tags, late.Content)
	late.Sig = sign(t, f.grantee, late.ID)
	e, code = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: d, ConsentEvent: &late})
	mustRefuse(t, e, code, "CONSENT_TIME")
	assertNoSecrets(t, f.outputs)
}

// Claim: a draft record whose contract hash, contract bytes or any grant field
// (agent, landlord, grantee, window, budget, scope mapping) disagrees with its
// contract is refused by consent with the LIP-0013 section 2.5 code, while the
// unmodified record is accepted. Each case changes exactly one member.
func TestGrantFieldsBindToContract(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	e, code := f.draftCmd(regtestRequest([]string{"instruct", "land", "spend"}, []string{"https://github.com/relux-works/swarma-identity"}, 5000))
	mustOK(t, e, code)
	base := resultAs[GrantDraftResult](t, e).Draft
	otherContract, _ := EncodeTrustContract(TrustContract{TrustContractProfile, "regtest", "id/landlord-a", "id/landlord-a-agent", base.GranteeKey, []string{"instruct"}, []string{}, 0, base.NotBefore, base.NotAfter, ""})
	for _, tc := range []struct {
		name, want string
		edit       func(*GrantDraft)
	}{
		{"unmodified", "", func(*GrantDraft) {}},
		{"contract-hash", "CONTRACT_HASH", func(d *GrantDraft) { d.ContractSHA256 = strings.Repeat("ab", 32) }},
		{"contract-bytes", "CONTRACT_HASH", func(d *GrantDraft) { d.ContractB64 = base64.StdEncoding.EncodeToString(otherContract) }},
		{"agent", "CONTRACT_MISMATCH", func(d *GrantDraft) { d.AgentName = "id/landlord-a-other" }},
		{"landlord", "CONTRACT_MISMATCH", func(d *GrantDraft) { d.LandlordName = "id/landlord-b" }},
		{"grantee", "CONTRACT_MISMATCH", func(d *GrantDraft) { d.GranteeKey = testsigner_public(t, keyOther) }},
		{"not-before", "CONTRACT_MISMATCH", func(d *GrantDraft) { d.NotBefore-- }},
		{"not-after", "CONTRACT_MISMATCH", func(d *GrantDraft) { d.NotAfter++ }},
		{"budget", "BUDGET_MISMATCH", func(d *GrantDraft) { d.Budget = 4999 }},
		{"budget-absent", "BUDGET_MISMATCH", func(d *GrantDraft) { d.Budget = 0 }},
		{"scope-missing-pay", "SCOPE_MISMATCH", func(d *GrantDraft) { d.Scope = []string{"repository.push"} }},
		{"scope-extra", "SCOPE_MISMATCH", func(d *GrantDraft) { d.Scope = []string{"deliver", "pay", "repository.push"} }},
		{"consent-tags", "CONSENT_TAGS", func(d *GrantDraft) {
			d.ConsentTemplate.Tags = [][]string{d.ConsentTemplate.Tags[0], d.ConsentTemplate.Tags[1], d.ConsentTemplate.Tags[2], {"privacy", strings.Repeat("0", 64)}}
		}},
		{"network", "NETWORK_PIN", func(d *GrantDraft) { d.Network = "main" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			d.Scope = append([]string(nil), base.Scope...)
			tc.edit(&d)
			e, code := f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: d, ConsentSig: sign(t, f.grantee, d.ConsentTemplate.ID)})
			if tc.want == "" {
				mustOK(t, e, code)
				return
			}
			mustRefuse(t, e, code, tc.want)
		})
	}
}

// Claim: the landlord's signatures verify only against the landlord's current
// on-chain grant key. A contract or grant signature by another key, a draft
// whose issuer key was replaced (even when consistently signed by that key)
// and a key rotated on chain after the draft are all refused; the on-chain
// key's signatures produce the signed grant.
func TestGrantLandlordKeyNegatives(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	other := testSigner(t, keyOther)
	f.prepare(regtestRequest([]string{"review"}, []string{}, 0))
	d, consent := f.draft.Draft, f.consent.ConsentEvent

	// A signature over the contract hash by a key that is not on chain.
	e, code := f.signCmd(GrantSignRequest{Schema: GrantSignSchema, Draft: d, ConsentEvent: consent, LandlordSig: sign(t, other, d.ContractSHA256)})
	mustRefuse(t, e, code, "LANDLORD_SIGNATURE")
	// A landlord signature over a different contract hash.
	e, code = f.signCmd(GrantSignRequest{Schema: GrantSignSchema, Draft: d, ConsentEvent: consent, LandlordSig: sign(t, f.landlord, strings.Repeat("ab", 32))})
	mustRefuse(t, e, code, "LANDLORD_SIGNATURE")
	// A grant signature by another key over the right hash.
	final := f.finalRequest()
	final.GrantSig = sign(t, other, f.stage1.GrantSigningHash)
	e, code = f.signCmd(final)
	mustRefuse(t, e, code, "GRANT_SIGNATURE")
	// The draft's issuer key replaced, with both signatures by that key.
	swapped := d
	swapped.IssuerKey = other.PublicKey()
	e, code = f.signCmd(GrantSignRequest{Schema: GrantSignSchema, Draft: swapped, ConsentEvent: consent, LandlordSig: sign(t, other, d.ContractSHA256)})
	mustRefuse(t, e, code, "LANDLORD_KEY_MISMATCH")

	// A rotation on chain after the draft: the old key no longer issues.
	f2 := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	r := regtestRequest([]string{"review"}, []string{}, 0)
	r.Seal.TxID = sealB
	e, code = f2.draftCmd(r)
	mustOK(t, e, code)
	d2 := resultAs[GrantDraftResult](t, e).Draft
	f2.node.set("id/landlord-a", landlordValue(testsigner_public(t, keyRotated)))
	e, code = f2.signCmd(GrantSignRequest{Schema: GrantSignSchema, Draft: d2, ConsentEvent: rental.Event{ID: d2.ConsentTemplate.ID, Pubkey: d2.GranteeKey, CreatedAt: d2.ConsentTemplate.CreatedAt, Kind: 8181, Tags: d2.ConsentTemplate.Tags, Content: "", Sig: sign(t, f2.grantee, d2.ConsentTemplate.ID)}, LandlordSig: sign(t, f2.landlord, d2.ContractSHA256)})
	mustRefuse(t, e, code, "LANDLORD_KEY_MISMATCH")

	// A refused final stage may leave the lock file; it never creates the
	// ledger or records a seal.
	if _, err := os.Lstat(f.ledger); !os.IsNotExist(err) {
		t.Fatal("a refused sign created the seal ledger")
	}
	e, code = f.signCmd(f.finalRequest()) // neighbour: the on-chain key's signatures
	mustOK(t, e, code)
	if resultAs[GrantSignResult](t, e).Stage != "signed" {
		t.Fatal("neighbour not signed")
	}
	assertNoSecrets(t, append(f.outputs, f2.outputs...))
}

// Claim: the agent must be a v3 agent whose landlord pointer names the draft's
// landlord, and that landlord must be an active v3 landlord; otherwise draft
// refuses before any digest is produced.
func TestGrantDraftPartyNegatives(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	f.node.set("id/landlord-b", landlordValue(testsigner_public(t, keyOther)))
	f.node.set("id/agent-of-b", agentValue("id/landlord-b"))
	f.node.set("id/agent-of-agent", agentValue("id/landlord-a-agent"))
	for _, tc := range []struct{ landlord, agent, want string }{
		{"id/landlord-a", "id/landlord-a-agent", ""},
		{"id/landlord-a", "id/agent-of-b", "AGENT_LANDLORD_MISMATCH"},
		{"id/landlord-a", "id/landlord-b", "AGENT_NOT_V3"},
		{"id/landlord-a-agent", "id/agent-of-agent", "LANDLORD_NOT_V3"},
		{"id/landlord-a", "id/missing-agent", "NAME_NOT_FOUND"},
	} {
		r := regtestRequest([]string{"instruct"}, []string{}, 0)
		r.LandlordName, r.AgentName = tc.landlord, tc.agent
		e, code := f.draftCmd(r)
		if tc.want == "" {
			mustOK(t, e, code)
			continue
		}
		mustRefuse(t, e, code, tc.want)
	}
	r := regtestRequest([]string{"instruct"}, []string{}, 0)
	r.Network = "main"
	e, code := f.draftCmd(r)
	mustRefuse(t, e, code, "NETWORK_PIN")

	// A regtest node whose genesis is not the pinned regtest genesis: the
	// node agrees with its config, so only the grant pin refuses.
	foreign := newGrantNodeGenesis(t, "regtest", strings.Repeat("0e", 32), f.node.records)
	f.prepare(regtestRequest([]string{"instruct"}, []string{}, 0))
	node := f.node
	f.node = foreign
	e, code = f.draftCmd(regtestRequest([]string{"instruct"}, []string{}, 0))
	mustRefuse(t, e, code, "NETWORK_PIN")
	e, code = f.signCmd(f.finalRequest())
	mustRefuse(t, e, code, "NETWORK_PIN")
	f.node = node
	e, code = f.signCmd(f.finalRequest()) // neighbour: the pinned node
	mustOK(t, e, code)
}

// Claim: a seal backs at most one signed grant. After grant A is signed on a
// seal, drafting or signing a different grant B on that seal refuses as
// SEAL_REUSED and leaves the ledger unchanged; re-running A's final sign is
// idempotent, and B on a fresh seal is issued.
func TestGrantSealReuse(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	reqB := regtestRequest([]string{"instruct", "review"}, []string{}, 0)
	reqB.Note = "grant B"
	e, code := f.draftCmd(reqB)
	mustOK(t, e, code)
	draftB := resultAs[GrantDraftResult](t, e).Draft // drafted before A consumed the seal

	f.issue(regtestRequest([]string{"instruct"}, []string{}, 0)) // grant A on sealA
	ledger, _ := os.ReadFile(f.ledger)

	e, code = f.draftCmd(reqB)
	mustRefuse(t, e, code, "SEAL_REUSED")

	consentB := rental.Event{ID: draftB.ConsentTemplate.ID, Pubkey: draftB.GranteeKey, CreatedAt: draftB.ConsentTemplate.CreatedAt, Kind: 8181, Tags: draftB.ConsentTemplate.Tags, Content: "", Sig: sign(t, f.grantee, draftB.ConsentTemplate.ID)}
	signB := GrantSignRequest{Schema: GrantSignSchema, Draft: draftB, ConsentEvent: consentB, LandlordSig: sign(t, f.landlord, draftB.ContractSHA256)}
	e, code = f.signCmd(signB)
	mustRefuse(t, e, code, "SEAL_REUSED")

	// B's final stage, with a valid grant signature computed offline.
	g := rental.Grant{Version: 3, Network: "regtest", Genesis: regtestGenesis, AgentName: draftB.AgentName, LandlordName: draftB.LandlordName, IssuerKey: draftB.IssuerKey, GranteeKey: draftB.GranteeKey, ContractSHA256: draftB.ContractSHA256, Scope: draftB.Scope, NotBefore: draftB.NotBefore, NotAfter: draftB.NotAfter, Seal: draftB.Seal, Consent: rental.GrantConsent{ContractSHA256: draftB.ContractSHA256, ConsentEvent: consentB, LandlordSig: signB.LandlordSig}}
	hash, err := g.SigningHash()
	if err != nil {
		t.Fatal(err)
	}
	signB.GrantSig = sign(t, f.landlord, hash)
	e, code = f.signCmd(signB)
	mustRefuse(t, e, code, "SEAL_REUSED")
	if after, _ := os.ReadFile(f.ledger); !bytes.Equal(after, ledger) {
		t.Fatal("a refused grant changed the seal ledger")
	}

	e, code = f.signCmd(f.finalRequest()) // neighbour: A again, idempotent
	mustOK(t, e, code)
	if resultAs[GrantSignResult](t, e).GrantID != f.signed.GrantID {
		t.Fatal("idempotent re-sign changed the grant id")
	}
	if after, _ := os.ReadFile(f.ledger); !bytes.Equal(after, ledger) {
		t.Fatal("idempotent re-sign changed the seal ledger")
	}

	reqB.Seal.TxID = sealB
	e, code = f.draftCmd(reqB) // neighbour: B on a fresh seal
	mustOK(t, e, code)
}

// Claim: the seal ledger is refused when it is group/world accessible, a
// symlink, behind a symlinked directory, relative, or not a ledger document;
// a fresh ledger is created owner-only. No signed grant is released then.
func TestGrantSealLedgerCustody(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	e, code := f.draftCmd(regtestRequest([]string{"instruct"}, []string{}, 0))
	mustOK(t, e, code)
	f.draft = resultAs[GrantDraftResult](t, e)
	f.consent.ConsentEvent = rental.Event{ID: f.draft.Draft.ConsentTemplate.ID, Pubkey: f.draft.Draft.GranteeKey, CreatedAt: f.draft.Draft.ConsentTemplate.CreatedAt, Kind: 8181, Tags: f.draft.Draft.ConsentTemplate.Tags, Content: "", Sig: sign(t, f.grantee, f.draft.Draft.ConsentTemplate.ID)}
	f.landlordSig = sign(t, f.landlord, f.draft.Draft.ContractSHA256)
	e, code = f.signCmd(GrantSignRequest{Schema: GrantSignSchema, Draft: f.draft.Draft, ConsentEvent: f.consent.ConsentEvent, LandlordSig: f.landlordSig})
	mustOK(t, e, code)
	f.stage1 = resultAs[GrantSignResult](t, e)
	final := f.finalRequest()

	dir := canonicalTemp(t)
	loose := filepath.Join(dir, "loose.json")
	os.WriteFile(loose, nil, 0644)
	os.Chmod(loose, 0644)
	target := filepath.Join(dir, "target.json")
	os.WriteFile(target, nil, 0600)
	link := filepath.Join(dir, "link.json")
	os.Symlink(target, link)
	realDir := filepath.Join(dir, "real")
	os.Mkdir(realDir, 0700)
	os.Symlink(realDir, filepath.Join(dir, "linkdir"))
	junk := filepath.Join(dir, "junk.json")
	os.WriteFile(junk, []byte(`{"schema":"other","seals":[]}`), 0600)
	for _, path := range []string{loose, link, filepath.Join(dir, "linkdir", "ledger.json"), "relative-ledger.json", junk} {
		f.ledger = path
		e, code = f.signCmd(final)
		mustRefuse(t, e, code, "LEDGER_FILE")
	}
	f.ledger = filepath.Join(dir, "fresh.json")
	e, code = f.signCmd(final)
	mustOK(t, e, code)
	if st, err := os.Lstat(f.ledger); err != nil || st.Mode().Perm() != 0600 || !st.Mode().IsRegular() {
		t.Fatal("fresh ledger is not an owner-only regular file")
	}
}

// secretEncodings lists every spelling of a 32-byte secret this repository's
// outputs could carry: raw bytes, hex in both cases and both base64 alphabets.
func secretEncodings(secret []byte) [][]byte {
	return [][]byte{secret, []byte(hex.EncodeToString(secret)), []byte(strings.ToUpper(hex.EncodeToString(secret))),
		[]byte(base64.StdEncoding.EncodeToString(secret)), []byte(base64.RawStdEncoding.EncodeToString(secret)),
		[]byte(base64.URLEncoding.EncodeToString(secret)), []byte(base64.RawURLEncoding.EncodeToString(secret))}
}

// leakedSecret reports whether any blob contains any encoding of any test key.
func leakedSecret(blobs [][]byte) bool {
	for _, s := range bip340Secrets {
		raw, _ := hex.DecodeString(s)
		for _, enc := range secretEncodings(raw) {
			for _, b := range blobs {
				if bytes.Contains(b, enc) {
					return true
				}
			}
		}
	}
	return false
}

func assertNoSecrets(t *testing.T, blobs [][]byte) {
	t.Helper()
	if len(blobs) == 0 || leakedSecret(blobs) {
		t.Fatal("private key bytes appear in a CLI output or the ledger")
	}
}

// Claim: the secret-key grep control detects every listed encoding of every
// test key when it is planted inside otherwise clean CLI output, and passes
// the clean output itself. Limit: the listed encodings, not arbitrary ones.
func TestSecretGrepControl(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	f.issue(regtestRequest([]string{"instruct"}, []string{}, 0))
	if leakedSecret(f.outputs) {
		t.Fatal("clean outputs flagged")
	}
	clean := f.outputs[len(f.outputs)-1]
	for _, s := range bip340Secrets {
		raw, _ := hex.DecodeString(s)
		for i, enc := range secretEncodings(raw) {
			planted := append(append(append([]byte{}, clean[:40]...), enc...), clean[40:]...)
			if !leakedSecret([][]byte{planted}) {
				t.Fatalf("planted encoding %d of a test key not detected", i)
			}
		}
	}
}

// Claim: the grant commands accept exactly one consent form, closed request
// members and their own options only; malformed requests refuse as BAD_INPUT
// before any node read, and a missing ledger option refuses as LEDGER_FILE.
func TestGrantInputShape(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	e, code := f.draftCmd(regtestRequest([]string{"instruct"}, []string{}, 0))
	mustOK(t, e, code)
	d := resultAs[GrantDraftResult](t, e).Draft
	sig := sign(t, f.grantee, d.ConsentTemplate.ID)
	event := rental.Event{ID: d.ConsentTemplate.ID, Pubkey: d.GranteeKey, CreatedAt: d.ConsentTemplate.CreatedAt, Kind: 8181, Tags: d.ConsentTemplate.Tags, Content: "", Sig: sig}
	e, code = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: d})
	mustRefuse(t, e, code, "BAD_INPUT")
	e, code = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: d, ConsentEvent: &event, ConsentSig: sig})
	mustRefuse(t, e, code, "BAD_INPUT")
	e, code = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: d, ConsentEvent: &event})
	mustOK(t, e, code) // neighbour
	if e.Network != "regtest" {
		t.Fatal("consent envelope network is not the draft network")
	}
	extra := map[string]any{"schema": GrantConsentSchema, "draft": d, "consent_sig": sig, "key": map[string]string{"source": "file", "path": "/x"}}
	e, code = f.run("grant", "consent", "--request", writeInput(t, extra))
	mustRefuse(t, e, code, "BAD_INPUT")
	e, code = f.run("grant", "consent", "--config", f.node.config, "--request", writeInput(t, GrantConsentRequest{Schema: GrantConsentSchema, Draft: d, ConsentSig: sig}))
	mustRefuse(t, e, code, "BAD_INPUT")
	r := regtestRequest([]string{"instruct"}, []string{}, 0)
	r.Schema = "swarma-trust/draft/2"
	e, code = f.draftCmd(r)
	mustRefuse(t, e, code, "BAD_INPUT")
	before := f.node.calls()
	e, code = f.run("grant", "draft", "--config", f.node.config, "--request", writeInput(t, map[string]any{"schema": GrantDraftSchema}), "--seal-ledger", f.ledger)
	mustRefuse(t, e, code, "BAD_INPUT")
	if f.node.calls() != before {
		t.Fatal("a malformed draft request reached the node")
	}
	e, code = f.run("grant", "draft", "--config", f.node.config, "--request", writeInput(t, regtestRequest([]string{"instruct"}, []string{}, 0)))
	mustRefuse(t, e, code, "LEDGER_FILE")
}
