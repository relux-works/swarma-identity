package facade

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

func v2CLI(t *testing.T, args ...string) (Envelope, int) {
	t.Helper()
	e, exit, _ := runCLI(t, append(args, "--json")...)
	return e, exit
}

func v2DraftFixture(t *testing.T, network string, text *string) (*flow, GrantDraftV2Request, GrantDraftV2Result) {
	t.Helper()
	c := baseV2Contract(t)
	c.Network = network
	c.Actions = []string{"instruct", "land", "review", "spend"}
	c.Repos = []string{"https://git.example/project/repo"}
	c.SpendBudget = 1000
	f := newFlow(t, network, c.LandlordName, c.AgentName)
	r := GrantDraftV2Request{Schema: GrantDraftV2Schema, Contract: c, Seal: rental.Point{TxID: sealA, Vout: 1}, ConsentCreatedAt: c.NotBefore - 1}
	if text != nil {
		b64 := base64.StdEncoding.EncodeToString([]byte(*text))
		r.ScopeTextB64 = &b64
		r.Contract.ScopeTextSHA256 = sha256Hex([]byte(*text))
	}
	e, exit := v2CLI(t, "grant", "draft-v2", "--request", writeInput(t, r), "--config", f.node.config, "--seal-ledger", f.ledger)
	mustOK(t, e, exit)
	d := resultAs[GrantDraftV2Result](t, e)
	return f, r, d
}

// Claim: /2 draft, consent, countersign, signed-grant parsing and offline verification round-trip on main/regtest fixtures with exact scope bytes.
func TestTrustContractV2CLIRoundTrip(t *testing.T) {
	for _, network := range []string{"main", "regtest"} {
		for _, scope := range []string{"absent", "empty", "utf8"} {
			t.Run(network+"/"+scope, func(t *testing.T) {
				var text *string
				if scope != "absent" {
					s := ""
					if scope == "utf8" {
						s = "Only documentation.\r\nExact UTF-8: café\n"
					}
					text = &s
				}
				f, r, d := v2DraftFixture(t, network, text)
				if _, err := os.Stat(f.ledger); !os.IsNotExist(err) {
					t.Fatal("draft wrote the seal ledger", err)
				}
				raw, code := IssueTrustContractV2(r.Contract, func() []byte {
					if text == nil {
						return nil
					}
					return []byte(*text)
				}())
				if code != "" || d.Draft.ContractB64 != base64.StdEncoding.EncodeToString(raw) || d.Draft.ContractSHA256 != sha256Hex(raw) {
					t.Fatal("draft changed issuer bytes", code)
				}
				if len(d.ToSign) != 2 || d.ToSign[0].Purpose != PurposeConsent || d.ToSign[1].Purpose != PurposeContract || d.ToSign[1].Digest != sha256Hex(raw) {
					t.Fatal("wrong signing seam")
				}
				e, exit := f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: d.Draft, ConsentSig: sign(t, f.grantee, d.Draft.ConsentTemplate.ID)})
				mustOK(t, e, exit)
				consent := resultAs[GrantConsentResult](t, e)
				cbytes, _ := compactJSON(consent.Contract)
				var consentContract TrustContractV2
				if err := json.Unmarshal(cbytes, &consentContract); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(consentContract, r.Contract) || !reflect.DeepEqual(consent.ScopeTextB64, r.ScopeTextB64) {
					t.Fatal("consent dropped /2 members/text")
				}
				sig := sign(t, f.landlord, d.Draft.ContractSHA256)
				sr := GrantSignRequest{Schema: GrantSignSchema, Draft: d.Draft, ConsentEvent: consent.ConsentEvent, LandlordSig: sig}
				e, exit = f.signCmd(sr)
				mustOK(t, e, exit)
				stage := resultAs[GrantSignResult](t, e)
				unsigned, err := base64.StdEncoding.DecodeString(stage.GrantB64)
				if err != nil || sha256Hex(append([]byte("swarma-grant-v3"), unsigned...)) != stage.GrantSigningHash {
					t.Fatal("v3 signing domain changed")
				}
				sr.GrantSig = sign(t, f.landlord, stage.GrantSigningHash)
				e, exit = f.signCmd(sr)
				mustOK(t, e, exit)
				signed := resultAs[GrantSignResult](t, e)
				if signed.Stage != "signed" || signed.SignedGrant == nil || !reflect.DeepEqual(signed.ScopeTextB64, r.ScopeTextB64) {
					t.Fatal("final bundle dropped text")
				}
				b, _ := base64.StdEncoding.DecodeString(signed.SignedGrantB64)
				parsed, err := rental.ParseSignedGrant(b)
				if err != nil || parsed.ID() != signed.GrantID || independentCommitment(t, b, parsed) != signed.Commitment {
					t.Fatal("invalid v3 grant", err)
				}
				vr := ContractVerifyV2Request{Schema: ContractVerifyV2Schema, ContractB64: d.Draft.ContractB64, ScopeTextB64: r.ScopeTextB64, IssuerKey: f.landlord.PublicKey(), LandlordSig: sig}
				e, exit = v2CLI(t, "grant", "contract-verify", "--request", writeInput(t, vr))
				mustOK(t, e, exit)
				verified := resultAs[ContractVerifyV2Result](t, e)
				if !verified.SignatureValid || !reflect.DeepEqual(verified.Contract, r.Contract) || !reflect.DeepEqual(verified.ScopeTextB64, r.ScopeTextB64) {
					t.Fatal("offline verification changed contract/text")
				}
				// Claim: replay of the identical signed /2 head preserves its id; a different contract cannot reuse the seal.
				e, exit = f.signCmd(sr)
				mustOK(t, e, exit)
				if resultAs[GrantSignResult](t, e).GrantID != signed.GrantID {
					t.Fatal("replay changed grant")
				}
				e, exit = v2CLI(t, "grant", "draft-v2", "--request", writeInput(t, r), "--config", f.node.config, "--seal-ledger", f.ledger)
				mustRefuse(t, e, exit, "SEAL_REUSED")
			})
		}
	}
}

// Claim: each offline verifier refusal has a valid CLI neighbour, returns no partial result and never reads a node or ledger.
func TestTrustContractV2CLIVerifierNegatives(t *testing.T) {
	landlord := testSigner(t, keyLandlord)
	c := baseV2Contract(t)
	text := base64.StdEncoding.EncodeToString([]byte("scope\n"))
	c.ScopeTextSHA256 = sha256Hex([]byte("scope\n"))
	raw := rawV2(t, c)
	base := ContractVerifyV2Request{ContractVerifyV2Schema, base64.StdEncoding.EncodeToString(raw), &text, landlord.PublicKey(), sign(t, landlord, sha256Hex(raw))}
	cases := []struct {
		name, code string
		mutate     func(*ContractVerifyV2Request)
	}{
		{"depth", "CONTRACT_DEPTH", func(r *ContractVerifyV2Request) {
			r.ContractB64 = base64.StdEncoding.EncodeToString(bytes.Replace(raw, []byte(`"depth":0`), []byte(`"depth":1`), 1))
		}},
		{"unknown", "CONTRACT_FIELD", func(r *ContractVerifyV2Request) {
			r.ContractB64 = base64.StdEncoding.EncodeToString(bytes.Replace(raw, []byte(`"note":""`), []byte(`"extra":0,"note":""`), 1))
		}},
		{"duplicate", "CONTRACT_FIELD", func(r *ContractVerifyV2Request) {
			r.ContractB64 = base64.StdEncoding.EncodeToString(bytes.Replace(raw, []byte(`"note":""`), []byte(`"note":"","note":""`), 1))
		}},
		{"scope-mismatch", "SCOPE_TEXT_HASH", func(r *ContractVerifyV2Request) {
			b := base64.StdEncoding.EncodeToString([]byte("scope"))
			r.ScopeTextB64 = &b
		}},
		{"scope-missing", "SCOPE_TEXT_HASH", func(r *ContractVerifyV2Request) { r.ScopeTextB64 = nil }},
		{"scope-base64", "SCOPE_TEXT_HASH", func(r *ContractVerifyV2Request) { b := "!"; r.ScopeTextB64 = &b }},
		{"contract-base64", "CONTRACT_ENCODING", func(r *ContractVerifyV2Request) { r.ContractB64 = "!" }},
		{"contract-base64-newline", "CONTRACT_ENCODING", func(r *ContractVerifyV2Request) { r.ContractB64 += "\n" }},
		{"signature", "LANDLORD_SIGNATURE", func(r *ContractVerifyV2Request) { r.LandlordSig = strings.Repeat("00", 64) }},
		{"schema", "BAD_INPUT", func(r *ContractVerifyV2Request) { r.Schema = "swarma-trust/contract-verify/1" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, exit := v2CLI(t, "grant", "contract-verify", "--request", writeInput(t, base))
			mustOK(t, e, exit)
			r := base
			tc.mutate(&r)
			e, exit = v2CLI(t, "grant", "contract-verify", "--request", writeInput(t, r))
			mustRefuse(t, e, exit, tc.code)
			wantExit := 3
			if tc.code == "BAD_INPUT" {
				wantExit = 2
			}
			if exit != wantExit {
				t.Fatalf("exit %d, want %d", exit, wantExit)
			}
		})
	}
	// Claim: verifier options reject ambient config/key/ledger inputs, duplicate options and absent --json beside the valid request.
	for _, extra := range [][]string{{"--config", "forbidden"}, {"--seal-ledger", "forbidden"}, {"--key", "forbidden"}, {"--json"}, {"--request", "duplicate"}} {
		e, exit := v2CLI(t, "grant", "contract-verify", "--request", writeInput(t, base))
		mustOK(t, e, exit)
		e, exit = v2CLI(t, append([]string{"grant", "contract-verify", "--request", writeInput(t, base)}, extra...)...)
		mustRefuse(t, e, exit, "BAD_INPUT")
	}
	e, exit, _ := runCLI(t, "grant", "contract-verify", "--request", writeInput(t, base))
	mustRefuse(t, e, exit, "BAD_INPUT")
}

// Claim: all /2 draft fields rebind to the contract and exact text before consent/signing, beside a valid unchanged draft.
func TestTrustContractV2DraftBindingNegatives(t *testing.T) {
	text := "scope\n"
	f, _, d := v2DraftFixture(t, "regtest", &text)
	base := d.Draft
	cases := []struct {
		name, code string
		mutate     func(*GrantDraft)
	}{
		{"hash", "CONTRACT_HASH", func(d *GrantDraft) { d.ContractSHA256 = strings.Repeat("ab", 32) }},
		{"network-genesis", "NETWORK_PIN", func(d *GrantDraft) { d.Genesis = strings.Repeat("ab", 32) }},
		{"agent", "CONTRACT_MISMATCH", func(d *GrantDraft) { d.AgentName = "id/other" }},
		{"landlord", "CONTRACT_MISMATCH", func(d *GrantDraft) { d.LandlordName = "id/other" }},
		{"grantee", "CONTRACT_MISMATCH", func(d *GrantDraft) { d.GranteeKey = f.landlord.PublicKey() }},
		{"window", "CONTRACT_MISMATCH", func(d *GrantDraft) { d.NotAfter++ }},
		{"scope", "SCOPE_MISMATCH", func(d *GrantDraft) { d.Scope = []string{"pay"} }},
		{"budget", "BUDGET_MISMATCH", func(d *GrantDraft) { d.Budget++ }},
		{"tags", "CONSENT_TAGS", func(d *GrantDraft) { d.ConsentTemplate.Tags = [][]string{{"t", "wrong"}} }},
		{"text", "SCOPE_TEXT_HASH", func(d *GrantDraft) { b := base64.StdEncoding.EncodeToString([]byte("changed")); d.ScopeTextB64 = &b }},
		{"text-missing", "SCOPE_TEXT_HASH", func(d *GrantDraft) { d.ScopeTextB64 = nil }},
		{"issuer", "GRANT_FIELD", func(d *GrantDraft) { d.IssuerKey = "bad" }},
		{"seal", "GRANT_FIELD", func(d *GrantDraft) { d.Seal.TxID = "bad" }},
		{"consent-pubkey", "CONSENT_BINDING", func(d *GrantDraft) { d.ConsentTemplate.Pubkey = f.landlord.PublicKey() }},
		{"consent-time", "CONSENT_TIME", func(d *GrantDraft) { d.ConsentTemplate.CreatedAt = 0 }},
		{"consent-id", "CONSENT_ID", func(d *GrantDraft) { d.ConsentTemplate.ID = strings.Repeat("ab", 32) }},
		{"schema", "BAD_INPUT", func(d *GrantDraft) { d.Schema = GrantRecordSchema }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := checkDraftForGrant(base); err != nil {
				t.Fatal("valid neighbour", err.Code)
			}
			r := base
			tc.mutate(&r)
			if raw, c, err := checkDraftForGrant(r); err == nil || err.Code != tc.code || raw != nil {
				t.Fatalf("got %v, want %s; contract=%v", err, tc.code, c)
			}
			e, exit := f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: r, ConsentSig: sign(t, f.grantee, base.ConsentTemplate.ID)})
			mustRefuse(t, e, exit, tc.code)
		})
	}
	// Claim: Keychain's existing /1-only display remains fail-closed for a /2 draft; it cannot hide the new terms.
	if _, _, err := checkDraft(base); err == nil || err.Code != "BAD_INPUT" {
		t.Fatal("/2 entered /1 Keychain path", err)
	}
}

// Claim: draft refusals for rights, text and child certification happen before any node read or seal-ledger write.
func TestTrustContractV2DraftRefusalSideEffects(t *testing.T) {
	f, r, _ := v2DraftFixture(t, "regtest", nil)
	count := f.node.calls()
	cases := []struct {
		name, code string
		mutate     func(*GrantDraftV2Request)
	}{
		{"depth", "CONTRACT_DEPTH", func(r *GrantDraftV2Request) { r.Contract.Delegate.Depth = 1 }},
		{"right", "CONTRACT_DEPTH", func(r *GrantDraftV2Request) { r.Contract.Delegate.Actions = []string{"review"} }},
		{"scope", "SCOPE_TEXT_HASH", func(r *GrantDraftV2Request) { r.Contract.ScopeTextSHA256 = strings.Repeat("ab", 32) }},
		{"child", "CONTRACT_DEPTH", func(r *GrantDraftV2Request) {
			r.Contract.ParentGrantID = strings.Repeat("ab", 32)
			r.Contract.Ordinal = 1
		}},
		{"profile", "CONTRACT_PROFILE", func(r *GrantDraftV2Request) { r.Contract.Profile = TrustContractProfile }},
		{"schema", "BAD_INPUT", func(r *GrantDraftV2Request) { r.Schema = GrantDraftSchema }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := r
			tc.mutate(&bad)
			e, exit := v2CLI(t, "grant", "draft-v2", "--request", writeInput(t, bad), "--config", f.node.config, "--seal-ledger", f.ledger)
			mustRefuse(t, e, exit, tc.code)
			if f.node.calls() != count {
				t.Fatal("invalid draft read node")
			}
			if _, err := os.Stat(f.ledger); !os.IsNotExist(err) {
				t.Fatal("invalid draft wrote ledger", err)
			}
		})
	}
}

// Claim: unknown/duplicate/null transport fields refuse BAD_INPUT, while a valid /2 verification request succeeds.
func TestTrustContractV2ClosedRequests(t *testing.T) {
	c := baseV2Contract(t)
	raw := rawV2(t, c)
	signer := testSigner(t, keyLandlord)
	r := ContractVerifyV2Request{Schema: ContractVerifyV2Schema, ContractB64: base64.StdEncoding.EncodeToString(raw), IssuerKey: signer.PublicKey(), LandlordSig: sign(t, signer, sha256Hex(raw))}
	good, _ := json.Marshal(r)
	for _, bad := range []string{
		strings.Replace(string(good), `"schema":`, `"extra":0,"schema":`, 1),
		strings.Replace(string(good), `"schema":`, `"schema":"duplicate","schema":`, 1),
		strings.Replace(string(good), `"issuer_key":`, `"scope_text_b64":null,"issuer_key":`, 1),
	} {
		e, exit := v2CLI(t, "grant", "contract-verify", "--request", writeInput(t, r))
		mustOK(t, e, exit)
		path := writeInput(t, r)
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		e, exit = v2CLI(t, "grant", "contract-verify", "--request", path)
		mustRefuse(t, e, exit, "BAD_INPUT")
	}
}

// Claim: all four /1 CLI response envelopes remain byte-identical to the assigned eaa8523c base, including signature and commitment bytes.
func TestTrustContractV1CLIBytesUnchanged(t *testing.T) {
	raw, err := os.ReadFile("testdata/lip0014/v1-cli-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if sha256Hex(raw) != "dcab4bc07324137a43bf820a90ecaadace050b42d17f19dd3cad87527344b8c6" {
		t.Fatal("/1 baseline fixture changed")
	}
	var fixture struct {
		Base    string   `json:"base"`
		Outputs []string `json:"outputs"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Base != "eaa8523cafcfff90eec7d3d16066dcfd8f2c8dff" || len(fixture.Outputs) != 4 {
		t.Fatal("wrong baseline")
	}
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	f.prepare(regtestRequest([]string{"instruct", "land", "review", "spend"}, []string{"https://git.example/a/b"}, 1000))
	e, exit := f.signCmd(f.finalRequest())
	mustOK(t, e, exit)
	for i, out := range f.outputs {
		if string(out) != fixture.Outputs[i] {
			t.Fatalf("/1 output %d changed", i)
		}
	}
}

// Claim: bad grantee/landlord/grant signatures and changed scope bytes cannot sign a /2 grant or consume its seal, beside a valid unsigned-stage control.
func TestTrustContractV2CountersignNegatives(t *testing.T) {
	text := "scope\n"
	f, _, d := v2DraftFixture(t, "regtest", &text)
	consentReq := GrantConsentRequest{Schema: GrantConsentSchema, Draft: d.Draft, ConsentSig: sign(t, f.grantee, d.Draft.ConsentTemplate.ID)}
	e, exit := f.consentCmd(consentReq)
	mustOK(t, e, exit)
	event := resultAs[GrantConsentResult](t, e).ConsentEvent
	badConsent := consentReq
	badConsent.ConsentSig = strings.Repeat("00", 64)
	e, exit = f.consentCmd(badConsent)
	mustRefuse(t, e, exit, "CONSENT_SIGNATURE")
	base := GrantSignRequest{Schema: GrantSignSchema, Draft: d.Draft, ConsentEvent: event, LandlordSig: sign(t, f.landlord, d.Draft.ContractSHA256)}
	for _, tc := range []struct {
		name, code string
		mutate     func(*GrantSignRequest)
	}{
		{"consent", "CONSENT_SIGNATURE", func(r *GrantSignRequest) { r.ConsentEvent.Sig = strings.Repeat("00", 64) }},
		{"landlord", "LANDLORD_SIGNATURE", func(r *GrantSignRequest) { r.LandlordSig = strings.Repeat("00", 64) }},
		{"grant", "GRANT_SIGNATURE", func(r *GrantSignRequest) { r.GrantSig = strings.Repeat("00", 64) }},
		{"scope", "SCOPE_TEXT_HASH", func(r *GrantSignRequest) {
			b := base64.StdEncoding.EncodeToString([]byte("changed"))
			r.Draft.ScopeTextB64 = &b
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, exit := f.signCmd(base)
			mustOK(t, e, exit)
			bad := base
			tc.mutate(&bad)
			e, exit = f.signCmd(bad)
			mustRefuse(t, e, exit, tc.code)
			if b, err := os.ReadFile(f.ledger); err == nil && len(b) != 0 {
				t.Fatal("refusal consumed seal")
			}
		})
	}
}
