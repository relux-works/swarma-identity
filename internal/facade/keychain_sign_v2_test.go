package facade

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"

	"github.com/relux-works/swarma-identity/internal/keychain/keychainfake"
)

// v2Signing is one /2 issuance taken through the CLI up to the point where
// the landlord signs: grant draft-v2, grant consent and grant sign stage
// grant_hash. Every byte in it is the CLI's own output.
type v2Signing struct {
	f           *flow
	contract    TrustContractV2 // as requested from grant draft-v2
	draft       GrantDraft
	consent     rental.Event
	landlordSig string
	stage       GrantSignResult
}

// prepareV2 drafts a regtest root contract. Without an edit it has the
// G1.0 shape: instruct and review, no repository, no budget, depth 0.
func prepareV2(t *testing.T, text *string, edit func(*TrustContractV2)) *v2Signing {
	t.Helper()
	c := baseV2Contract(t)
	c.Network = "regtest"
	if edit != nil {
		edit(&c)
	}
	f := newFlow(t, "regtest", c.LandlordName, c.AgentName)
	r := GrantDraftV2Request{Schema: GrantDraftV2Schema, Contract: c, Seal: rental.Point{TxID: sealA, Vout: 1}, ConsentCreatedAt: c.NotBefore - 1}
	if text != nil {
		b64 := base64.StdEncoding.EncodeToString([]byte(*text))
		r.ScopeTextB64 = &b64
		r.Contract.ScopeTextSHA256 = sha256Hex([]byte(*text))
	}
	e, exit := v2CLI(t, "grant", "draft-v2", "--request", writeInput(t, r), "--config", f.node.config, "--seal-ledger", f.ledger)
	mustOK(t, e, exit)
	x := &v2Signing{f: f, contract: r.Contract, draft: resultAs[GrantDraftV2Result](t, e).Draft}
	e, exit = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: x.draft, ConsentSig: sign(t, f.grantee, x.draft.ConsentTemplate.ID)})
	mustOK(t, e, exit)
	x.consent = resultAs[GrantConsentResult](t, e).ConsentEvent
	x.landlordSig = sign(t, f.landlord, x.draft.ContractSHA256)
	e, exit = f.signCmd(GrantSignRequest{Schema: GrantSignSchema, Draft: x.draft, ConsentEvent: x.consent, LandlordSig: x.landlordSig})
	mustOK(t, e, exit)
	x.stage = resultAs[GrantSignResult](t, e)
	return x
}

func allFourV2(c *TrustContractV2) {
	c.Actions = []string{"instruct", "land", "review", "spend"}
	c.Repos = []string{"https://git.example/project/repo"}
	c.SpendBudget = 1000
	c.Note = `A note with "quotes" and a \ backslash.`
}

func hexValue(value string) *string {
	s := hex.EncodeToString([]byte(value))
	return &s
}

// The display's statement about the landlord value and its closing prompt,
// written out here and not taken from the implementation. %d is the length
// of the stated value.
const (
	wantUnverifiedValue = "Landlord value     : NOT VERIFIED BY THIS SIGNER. The %d bytes on the next line are the value stated by the request. This signer reads no chain and has not compared them with the current value of the landlord name; that check is the issuing command's (grant sign), which reads the chain."
	wantPrompt          = "Type SIGN to sign exactly the above, anything else declines: "
)

// overstatedValueWording is wording that would present the stated landlord
// value as a fact about the chain or about the landlord.
var overstatedValueWording = []string{"no holders", "legacy form", "on chain", "its grant key is the signing key"}

// checkValueUnverified requires the exact unverified statement, directly
// followed by the stated octets and then by the first grant field, and none
// of the overstated wording anywhere in the display.
func checkValueUnverified(t *testing.T, shown, value, landlordName string) {
	t.Helper()
	want := "\n" + fmt.Sprintf(wantUnverifiedValue, len(value)) + "\n  " + value + "\nLandlord           : " + landlordName + "\n"
	if strings.Count(shown, want) != 1 {
		t.Fatalf("display does not state once, before the grant fields, that the landlord value is the request's and unverified:\n%s", shown)
	}
	for _, bad := range overstatedValueWording {
		if strings.Contains(strings.ToLower(shown), bad) {
			t.Fatalf("display overstates the landlord value: it contains %q", bad)
		}
	}
}

// request asks for landlord_sig and the grant signature under sign/2, with
// the legacy landlord value of the draft's issuer key.
func (x *v2Signing) request() KeychainSignRequest {
	ev := x.consent
	return KeychainSignRequest{Schema: KeychainSignV2Schema, Draft: x.draft, ConsentEvent: &ev, LandlordSig: x.landlordSig, LandlordValueHex: hexValue(landlordValue(x.draft.IssuerKey)),
		ToSign: []SigningDigest{
			digestSigner("landlord", x.draft.IssuerKey, PurposeContract, x.draft.ContractSHA256),
			digestSigner("landlord", x.draft.IssuerKey, PurposeGrant, x.stage.GrantSigningHash),
		}}
}

func (x *v2Signing) contractBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(x.draft.ContractB64)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// rebindV2 points every derived draft member at other contract bytes, so a
// changed contract reaches the contract rules and is not refused earlier for
// a stale hash or stale consent tags.
func rebindV2(d *GrantDraft, raw []byte) {
	d.ContractB64 = base64.StdEncoding.EncodeToString(raw)
	d.ContractSHA256 = sha256Hex(raw)
	tpl := d.ConsentTemplate
	tpl.Tags = trustConsentTags(raw)
	tpl.ID = consentEventID(tpl.Pubkey, tpl.CreatedAt, tpl.Kind, tpl.Tags, tpl.Content)
	d.ConsentTemplate = tpl
}

// replaceOnce changes exactly one occurrence, so a fixture that stops
// containing the target fails the test instead of leaving the input valid.
func replaceOnce(t *testing.T, raw []byte, from, to string) []byte {
	t.Helper()
	if bytes.Count(raw, []byte(from)) != 1 {
		t.Fatalf("fixture does not contain exactly one %q", from)
	}
	return bytes.Replace(raw, []byte(from), []byte(to), 1)
}

// linesUnder returns the lines that follow the first line starting with
// header while they start with indent, with indent removed.
func linesUnder(shown, header, indent string) []string {
	lines := strings.Split(shown, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, header) {
			continue
		}
		var out []string
		for _, m := range lines[i+1:] {
			if !strings.HasPrefix(m, indent) {
				break
			}
			out = append(out, m[len(indent):])
		}
		return out
	}
	return nil
}

// The fifteen member names of LIP-0014 section 3, written out here and not
// taken from the implementation.
var lip0014Members = []string{"profile", "network", "landlord_name", "agent_name", "grantee_key", "actions", "repos", "spend_budget", "not_before", "not_after", "scope_text_sha256", "parent_grant_id", "ordinal", "delegate", "note"}

// memberLinesV2 is the expected member block: built from the typed contract
// the test asked grant draft-v2 for, one compact value per member, and each
// "name":value span is required to stand in the signed bytes.
func memberLinesV2(t *testing.T, c TrustContractV2, contract []byte) []string {
	t.Helper()
	values := []any{c.Profile, c.Network, c.LandlordName, c.AgentName, c.GranteeKey, c.Actions, c.Repos, c.SpendBudget, c.NotBefore, c.NotAfter, c.ScopeTextSHA256, c.ParentGrantID, c.Ordinal, c.Delegate, c.Note}
	var out []string
	for i, name := range lip0014Members {
		v, ok := compactJSON(values[i])
		if !ok || !bytes.Contains(contract, []byte(`"`+name+`":`+string(v))) {
			t.Fatalf("ground truth: member %s is not in the contract bytes as %s", name, v)
		}
		out = append(out, fmt.Sprintf("%2d %-17s = %s", i+1, name, v))
	}
	return out
}

// signOneV2 signs a one-digest request and returns the terminal transcript
// captured at the first secret read.
func signOneV2(t *testing.T, r KeychainSignRequest) string {
	t.Helper()
	h := newKC(t, confirmWord)
	e, code := h.sign(r)
	mustOK(t, e, code)
	res := resultAs[KeychainSignResult](t, e)
	if !h.keyRead || len(res.Signatures) != 1 || res.Signatures[0].Digest != r.ToSign[0].Digest || !sigValid(r.Draft.IssuerKey, r.ToSign[0].Digest, res.Signatures[0].Signature) {
		t.Fatalf("positive control did not sign: %v", h.log)
	}
	if h.log[0] != "public:"+kcLabel || h.count("show") != 1 || h.count("confirm") != 1 || h.count("secret:") != 1 {
		t.Fatalf("unexpected approval/secret ordering: %v", h.log)
	}
	return h.preKey
}

// Claim: for a /2 draft, the terminal transcript at the first secret read
// shows (a) all fifteen members of LIP-0014 section 3, in the spec's order,
// each with the value that stands in the signed bytes, and nothing else in
// that block; (b) as "path = value", exactly the leaves of the bytes each
// digest is the SHA-256 of, and those bytes verbatim: the /2 contract for
// contract_sha256 and "swarma-grant-v3" || canonical grant for
// grant_signing_hash; (c) the digest that is signed, which is the SHA-256 of
// those displayed bytes. The ground truth is grant draft-v2's and grant
// sign's own output bytes (contract_b64, grant_b64) and the typed contract
// the test requested, not the signer's renderer. Cases: the G1.0 shape
// (instruct and review, depth 0, no text) and all four actions with a
// repository, a budget, a note with both JSON escapes and a bound scope text.
// (d) The contract subtest also pins the landlord value section: the exact
// statement that the value is the request's and is not verified by this
// signer, then the stated octets, then the first grant field, with none of
// the overstated wording; and the closing line, which is the last line before
// the prompt and repeats the contract SHA-256, the document's SHA-256 when
// one is bound, and the digest to be signed.
func TestKeychainDisplayCoversEveryPreimageFieldV2(t *testing.T) {
	text := "Work on the documentation only.\n"
	for _, tc := range []struct {
		name string
		text *string
		edit func(*TrustContractV2)
	}{{"g1-shape", nil, nil}, {"all-four-with-text", &text, allFourV2}} {
		t.Run(tc.name, func(t *testing.T) {
			x := prepareV2(t, tc.text, tc.edit)
			contract := x.contractBytes(t)
			t.Run("contract", func(t *testing.T) {
				r := x.request()
				r.ToSign = r.ToSign[:1]
				shown := signOneV2(t, r)
				checkPreimageShown(t, shown, "", contract, x.draft.ContractSHA256)
				if sha256Hex(contract) != r.ToSign[0].Digest || !strings.Contains(shown, "\n  digest           : "+sha256Hex(contract)+"\n") {
					t.Fatal("display does not state the SHA-256 of the displayed contract bytes as the digest")
				}
				got, want := linesUnder(shown, "Trust contract     : ", "  "), memberLinesV2(t, x.contract, contract)
				if len(want) != 15 || !slices.Equal(got, want) {
					t.Fatalf("member block is not the fifteen members in order:\n got %q\nwant %q", got, want)
				}
				if !strings.Contains(shown, "\nRequest schema     : "+KeychainSignV2Schema+" (draft record "+GrantRecordV2Schema+")\n") {
					t.Fatal("display does not state the request schema")
				}
				checkValueUnverified(t, shown, landlordValue(x.draft.IssuerKey), x.draft.LandlordName)
				closing := "\nApproval covers    : contract SHA-256 " + x.draft.ContractSHA256
				if tc.text != nil {
					closing += "; scope document SHA-256 " + sha256Hex([]byte(*tc.text)) + " (the members and the SCOPE TEXT stand above the document)"
				}
				closing += "; contract_sha256 " + sha256Hex(contract) + "\n" + wantPrompt
				if !strings.HasSuffix(shown, closing) {
					t.Fatalf("the display does not end with the closing line and the prompt:\n%s", shown)
				}
			})
			t.Run("grant", func(t *testing.T) {
				r := x.request()
				r.ToSign = r.ToSign[1:]
				grant, err := base64.StdEncoding.DecodeString(x.stage.GrantB64)
				if err != nil {
					t.Fatal(err)
				}
				shown := signOneV2(t, r)
				checkPreimageShown(t, shown, "swarma-grant-v3", grant, x.stage.GrantSigningHash)
				if !strings.Contains(shown, "\n  digest           : "+sha256Hex(append([]byte("swarma-grant-v3"), grant...))+"\n") {
					t.Fatal("display does not state the SHA-256 of the displayed grant bytes as the digest")
				}
				if got, want := linesUnder(shown, "Trust contract     : ", "  "), memberLinesV2(t, x.contract, contract); !slices.Equal(got, want) {
					t.Fatalf("member block is not the fifteen members in order:\n got %q\nwant %q", got, want)
				}
			})
		})
	}
}

// Claim: the signatures keychain sign returns for a /2 request are the ones
// the rest of the flow accepts: the contract signature verifies offline under
// grant contract-verify, the grant signature completes grant sign to stage
// "signed", and a seal spend may ride along; the display and the confirmation
// come before the first of the three secret reads.
func TestKeychainSignV2CompletesIssuance(t *testing.T) {
	x := prepareV2(t, nil, nil)
	h := newKC(t, confirmWord)
	r := x.request()
	_, spend := sealSpendFor(t, x.draft, landlordP2PKH(t))
	r.SealSpend = &spend
	e, code := h.sign(r)
	mustOK(t, e, code)
	if e.Network != "regtest" {
		t.Fatalf("network %q", e.Network)
	}
	res := resultAs[KeychainSignResult](t, e)
	if len(res.Signatures) != 2 || res.SealSpend == nil || res.Key.XOnlyKey != x.draft.IssuerKey {
		t.Fatalf("result %+v", res)
	}
	if h.count("secret:") != 3 || len(h.log) < 4 || h.log[0] != "public:"+kcLabel || h.log[1] != "access:"+kcLabel || h.log[2] != "show" || h.log[3] != "confirm" {
		t.Fatalf("unexpected approval/secret ordering: %v", h.log)
	}
	vr := ContractVerifyV2Request{Schema: ContractVerifyV2Schema, ContractB64: x.draft.ContractB64, IssuerKey: x.draft.IssuerKey, LandlordSig: res.Signatures[0].Signature}
	e, code = v2CLI(t, "grant", "contract-verify", "--request", writeInput(t, vr))
	mustOK(t, e, code)
	if !resultAs[ContractVerifyV2Result](t, e).SignatureValid {
		t.Fatal("contract signature does not verify offline")
	}
	e, code = x.f.signCmd(GrantSignRequest{Schema: GrantSignSchema, Draft: x.draft, ConsentEvent: x.consent, LandlordSig: x.landlordSig, GrantSig: res.Signatures[1].Signature})
	mustOK(t, e, code)
	if resultAs[GrantSignResult](t, e).Stage != "signed" {
		t.Fatal("grant not signed")
	}
}

// The expected wording, written out here and not taken from the
// implementation.
var wantActionLines = map[string][2]string{
	"instruct": {"GRANTED instruct: the grantee may assign the agent work: tasks, requests, priorities.", "NOT GRANTED instruct: the grantee may not assign the agent work."},
	"land":     {"GRANTED land: the grantee may authorize a landing into the default branch of each repository listed below.", "NOT GRANTED land: the grantee may not authorize a landing into any repository."},
	"review":   {"GRANTED review: the grantee's review verdicts count as reviews for the agent's landing gates, within each repository's reviewer policy.", "NOT GRANTED review: the grantee's review verdicts do not count for the agent's landing gates."},
	"spend":    {"GRANTED spend: the grantee may request NMC payments up to the spend budget below in total, fees included.", "NOT GRANTED spend: the grantee may not request any payment."},
}

const (
	wantScopeHead   = "The landlord id/acme lets the holder of the key f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9 direct its agent id/acme-executor on network main."
	wantScopeWindow = "Window: not before 1794528000 (2026-11-13T00:00:00Z), not after 1797120000 (2026-12-13T00:00:00Z)."
	wantScopeDepth  = "Delegation: depth 0; the grantee cannot delegate: no child grant may be issued under this grant."
	wantScopeParent = "Parent: none; this is a root grant (ordinal 0)."
)

// The wording about a bound scope document; %s is its SHA-256 (member 11).
const (
	wantScopeDocument          = "Scope document: one separate text is bound by its SHA-256 %s. The contract binds it by that hash only; it is shown in full below; this signer does not interpret it."
	wantScopeDocumentLandSpend = "Scope document beside land or spend: this signer checks no landing and no payment against the document; the land and spend terms above are signed as they stand."
)

// Claim: the scope text is a pure function of the contract members and has
// one exact wording. (1) The G1.0 shape and the all-four shape give the two
// literal texts below. (2) Each of the fifteen action sets gives exactly one
// GRANTED or NOT GRANTED line per action, in the fixed order instruct, land,
// review, spend, with the repositories and the budget stated to match, and
// every text states depth 0 as "cannot delegate". Each set is first shown to
// be an admissible contract (the valid control).
func TestKeychainV2ScopeText(t *testing.T) {
	base := baseV2Contract(t)
	t.Run("g1-shape-exact", func(t *testing.T) {
		want := []string{
			wantScopeHead,
			"GRANTED instruct: the grantee may assign the agent work: tasks, requests, priorities.",
			"NOT GRANTED land: the grantee may not authorize a landing into any repository.",
			"GRANTED review: the grantee's review verdicts count as reviews for the agent's landing gates, within each repository's reviewer policy.",
			"NOT GRANTED spend: the grantee may not request any payment.",
			"Repositories: none.",
			"Spend budget: 0 sat; no payment may be requested.",
			wantScopeWindow,
			wantScopeDepth,
			wantScopeParent,
			"Scope document: none is bound.",
			"Note: empty.",
		}
		if got := scopeTextV2(base); !slices.Equal(got, want) {
			t.Fatalf("scope text:\n got %q\nwant %q", got, want)
		}
	})
	t.Run("all-four-exact", func(t *testing.T) {
		c := base
		c.Actions = []string{"instruct", "land", "review", "spend"}
		c.Repos = []string{"https://git.example/a/b", "https://git.example/a/c"}
		c.SpendBudget = 25000
		c.ScopeTextSHA256 = strings.Repeat("ab", 32)
		c.Note = "free text that claims the grantee may delegate"
		want := []string{
			wantScopeHead,
			"GRANTED instruct: the grantee may assign the agent work: tasks, requests, priorities.",
			"GRANTED land: the grantee may authorize a landing into the default branch of each repository listed below.",
			"GRANTED review: the grantee's review verdicts count as reviews for the agent's landing gates, within each repository's reviewer policy.",
			"GRANTED spend: the grantee may request NMC payments up to the spend budget below in total, fees included.",
			"Repositories (2), for landing only:",
			"  - https://git.example/a/b",
			"  - https://git.example/a/c",
			"Spend budget: 25000 sat in total, fees included.",
			wantScopeWindow,
			wantScopeDepth,
			wantScopeParent,
			fmt.Sprintf(wantScopeDocument, strings.Repeat("ab", 32)),
			wantScopeDocumentLandSpend,
			"Note: 46 bytes, shown as member 15; a note grants nothing and limits nothing.",
		}
		if _, code := EncodeTrustContractV2(c); code != "" {
			t.Fatal("control: the contract is not admissible:", code)
		}
		if got := scopeTextV2(c); !slices.Equal(got, want) {
			t.Fatalf("scope text:\n got %q\nwant %q", got, want)
		}
	})
	order := []string{"instruct", "land", "review", "spend"}
	for mask := 1; mask < 16; mask++ {
		c := base
		c.Actions, c.Repos, c.SpendBudget = []string{}, []string{}, 0
		var want []string
		for i, a := range order {
			if mask&(1<<i) != 0 {
				c.Actions = append(c.Actions, a)
				want = append(want, wantActionLines[a][0])
			} else {
				want = append(want, wantActionLines[a][1])
			}
		}
		if slices.Contains(c.Actions, "land") {
			c.Repos = []string{"https://git.example/a/b"}
			want = append(want, "Repositories (1), for landing only:", "  - https://git.example/a/b")
		} else {
			want = append(want, "Repositories: none.")
		}
		if slices.Contains(c.Actions, "spend") {
			c.SpendBudget = 7
			want = append(want, "Spend budget: 7 sat in total, fees included.")
		} else {
			want = append(want, "Spend budget: 0 sat; no payment may be requested.")
		}
		want = append(append([]string{wantScopeHead}, want...), wantScopeWindow, wantScopeDepth, wantScopeParent, "Scope document: none is bound.", "Note: empty.")
		t.Run(strings.Join(c.Actions, "+"), func(t *testing.T) {
			if _, code := EncodeTrustContractV2(c); code != "" {
				t.Fatal("control: the action set is not an admissible contract:", code)
			}
			got := scopeTextV2(c)
			if !slices.Equal(got, want) {
				t.Fatalf("scope text:\n got %q\nwant %q", got, want)
			}
			if n := strings.Count(strings.Join(got, "\n"), "cannot delegate"); n != 1 {
				t.Fatalf("depth 0 is stated as \"cannot delegate\" %d times", n)
			}
			// One unit word for the budget, and the same word as the grant
			// field line of the display ("Grant v3 budget    : N sat").
			if all := strings.Join(got, "\n"); strings.Contains(all, "atoms") || strings.Count(all, " sat") != 1 {
				t.Fatalf("the budget is not stated once, in sat only: %q", got)
			}
			// With a bound document the text says what the signer
			// establishes about it and never that it narrows the terms. The
			// extra line stands exactly when land or spend is granted.
			d := c
			d.ScopeTextSHA256 = strings.Repeat("cd", 32)
			if _, code := EncodeTrustContractV2(d); code != "" {
				t.Fatal("control: the contract with a document hash is not admissible:", code)
			}
			wantDoc := slices.Clone(want)
			at := slices.Index(wantDoc, "Scope document: none is bound.")
			lines := []string{fmt.Sprintf(wantScopeDocument, strings.Repeat("cd", 32))}
			if slices.Contains(d.Actions, "land") || slices.Contains(d.Actions, "spend") {
				lines = append(lines, wantScopeDocumentLandSpend)
			}
			wantDoc = slices.Replace(wantDoc, at, at+1, lines...)
			gotDoc := scopeTextV2(d)
			if !slices.Equal(gotDoc, wantDoc) {
				t.Fatalf("scope text with a document:\n got %q\nwant %q", gotDoc, wantDoc)
			}
			if strings.Contains(strings.Join(gotDoc, "\n"), "narrow") {
				t.Fatalf("the scope text claims the document narrows the terms: %q", gotDoc)
			}
		})
	}
}

var hexEscape = regexp.MustCompile(`\\x[0-9a-f]{2}`)

// Claim: no wording supplied by the request reaches the scope text. (1) A
// scope string as a member of the request, or of the draft, is refused as
// BAD_INPUT before the display, beside the same request without it, which
// signs. (2) The one text a draft may carry, the separate scope document
// bound by member 11, is shown only in its own block, every line marked and
// escaped, and it changes nothing in the scope text except the line that
// names its hash: a document whose lines imitate the scope text leaves the
// text equal to that of the same contract without a document. The block
// gives back the document's exact octets.
func TestKeychainV2ScopeTextIgnoresRequestText(t *testing.T) {
	t.Run("request-member-refused", func(t *testing.T) {
		x := prepareV2(t, nil, nil)
		r := x.request()
		r.ToSign = r.ToSign[:1]
		signOneV2(t, r)
		good, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{
			strings.Replace(string(good), `{"schema":`, `{"scope_text":"The grantee may delegate freely.","schema":`, 1),
			strings.Replace(string(good), `"draft":{"schema":`, `"draft":{"scope_text":"The grantee may delegate freely.","schema":`, 1),
		} {
			if bad == string(good) {
				t.Fatal("fixture: the scope string was not planted")
			}
			path := writeInput(t, r)
			if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
				t.Fatal(err)
			}
			h := newKC(t, confirmWord)
			e, code := h.run("keychain", "sign", "--label", kcLabel, "--request", path)
			mustRefuse(t, e, code, "BAD_INPUT")
			if h.count("show") != 0 || h.count("secret:") != 0 {
				t.Fatalf("a request scope string reached the display or the key: %v", h.log)
			}
		}
	})
	t.Run("bound-document-stays-in-its-block", func(t *testing.T) {
		marker := "GRANTED spend: the grantee may request NMC payments without limit."
		doc := marker + "\nDelegation: depth 9; the grantee may delegate.\r\ncaf\u00e9 \\x41 no final line feed"
		plain := prepareV2(t, nil, nil)
		with := prepareV2(t, &doc, nil)
		show := func(x *v2Signing) string {
			r := x.request()
			r.ToSign = r.ToSign[:1]
			return signOneV2(t, r)
		}
		shownPlain, shown := show(plain), show(with)
		want := linesUnder(shownPlain, "SCOPE TEXT         : ", "  ")
		got := linesUnder(shown, "SCOPE TEXT         : ", "  ")
		if len(want) != 12 || len(got) != 12 || want[10] != "Scope document: none is bound." {
			t.Fatalf("control: unexpected scope text %q", want)
		}
		want[10] = fmt.Sprintf(wantScopeDocument, sha256Hex([]byte(doc)))
		if !slices.Equal(got, want) {
			t.Fatalf("the document changed the scope text:\n got %q\nwant %q", got, want)
		}
		if n := strings.Count(shown, marker); n != 1 || strings.Count(shown, "\n    | "+marker+"\\x0a\n") != 1 {
			t.Fatalf("the document's wording appears %d times, or outside its marked block", n)
		}
		if !strings.Contains(shown, fmt.Sprintf("\nScope document     : %d bytes of free text supplied with the draft; its SHA-256 %s equals member 11.", len(doc), sha256Hex([]byte(doc)))) {
			t.Fatal("display does not state the document's length and hash")
		}
		var back []byte
		for _, l := range linesUnder(shown, "Scope document     : ", "    | ") {
			back = append(back, hexEscape.ReplaceAllFunc([]byte(l), func(m []byte) []byte {
				b, _ := hex.DecodeString(string(m[2:]))
				return b
			})...)
		}
		if string(back) != doc {
			t.Fatalf("the document block does not give back the exact octets:\n got %q\nwant %q", back, doc)
		}
		if !strings.Contains(shownPlain, "\nScope document     : none\n") {
			t.Fatal("control: a contract without a document does not say so")
		}
	})
}

// Claim: each condition below refuses a sign/2 request with its exact closed
// code and exit status, before anything is shown and before any secret is
// read. Each negative changes one thing in the valid request, and that
// unchanged request signs in the same subtest (the valid control). A changed
// contract is rebound (hash, consent tags, consent id), so the code comes
// from the rule named and not from a stale hash. The landlord value cases
// judge the value the request states: their codes and their message name the
// stated value, and are not the codes grant sign gives for the chain value.
func TestKeychainSignV2Refusals(t *testing.T) {
	x := prepareV2(t, nil, nil)
	contract := x.contractBytes(t)
	key := x.draft.IssuerKey
	other := testsigner_public(t, keyOther)
	swap := func(from, to string) func(*KeychainSignRequest) {
		changed := replaceOnce(t, contract, from, to)
		return func(r *KeychainSignRequest) { rebindV2(&r.Draft, changed) }
	}
	value := func(v string) func(*KeychainSignRequest) {
		return func(r *KeychainSignRequest) { r.LandlordValueHex = hexValue(v) }
	}
	cases := []struct {
		name, want string
		exit       int
		edit       func(*KeychainSignRequest)
	}{
		// /2 with depth > 0, in each form the right or a parent can take.
		{"depth-1", "CONTRACT_DEPTH", 3, swap(`"depth":0`, `"depth":1`)},
		{"right-with-actions", "CONTRACT_DEPTH", 3, swap(`"delegate":{"depth":0,"actions":[]`, `"delegate":{"depth":0,"actions":["review"]`)},
		{"child-of-a-parent", "CONTRACT_DEPTH", 3, swap(`"parent_grant_id":"","ordinal":0`, `"parent_grant_id":"`+strings.Repeat("ab", 32)+`","ordinal":1`)},
		// A non-canonical contract: the same members in another spelling.
		{"non-canonical-space", "CONTRACT_ENCODING", 3, swap(`{"profile":`, `{ "profile":`)},
		{"non-canonical-escape", "CONTRACT_ENCODING", 3, swap(`"network":"regtest"`, `"network":"regtes\u0074"`)},
		{"non-canonical-trailing-newline", "CONTRACT_ENCODING", 3, func(r *KeychainSignRequest) { rebindV2(&r.Draft, append(slices.Clone(contract), '\n')) }},
		// An unknown or a duplicate member.
		{"unknown-member", "CONTRACT_FIELD", 3, swap(`"note":""`, `"extra":0,"note":""`)},
		{"duplicate-member", "CONTRACT_FIELD", 3, swap(`"note":""`, `"note":"","note":""`)},
		// A profile string that is not the one of the member set.
		{"profile-string", "CONTRACT_PROFILE", 3, swap(`"profile":"swarma-trust-contract/2"`, `"profile":"swarma-trust-contract/1"`)},
		// Network or genesis: the contract against the grant fields.
		{"contract-network", "CONTRACT_MISMATCH", 3, swap(`"network":"regtest"`, `"network":"main"`)},
		{"grant-network-and-genesis", "CONTRACT_MISMATCH", 3, func(r *KeychainSignRequest) { r.Draft.Network, r.Draft.Genesis = "main", MainGenesis }},
		{"grant-network", "NETWORK_PIN", 3, func(r *KeychainSignRequest) { r.Draft.Network = "main" }},
		{"grant-genesis", "NETWORK_PIN", 3, func(r *KeychainSignRequest) { r.Draft.Genesis = MainGenesis }},
		// The same fifteen members with two adjacent ones in the other order.
		{"members-swapped", "CONTRACT_ENCODING", 3, swap(`"parent_grant_id":"","ordinal":0`, `"ordinal":0,"parent_grant_id":""`)},
		// A scope document on a contract that binds none.
		{"scope-document-unexpected", "SCOPE_TEXT_HASH", 3, func(r *KeychainSignRequest) {
			b := base64.StdEncoding.EncodeToString([]byte("Work on the documentation only.\n"))
			r.Draft.ScopeTextB64 = &b
		}},
		{"scope-document-unexpected-empty", "SCOPE_TEXT_HASH", 3, func(r *KeychainSignRequest) { b := ""; r.Draft.ScopeTextB64 = &b }},
		// The stated landlord value: only the legacy form, and only this key's.
		{"holders-empty", "STATED_LANDLORD_VALUE_NOT_V3", 3, value(`{"swarma":{"landlord":{"grant":"` + key + `","holders":[]}}}`)},
		{"holders-one-pin", "STATED_LANDLORD_VALUE_NOT_V3", 3, value(`{"swarma":{"landlord":{"grant":"` + key + `","holders":["02` + key + `"]}}}`)},
		{"value-of-an-agent", "STATED_LANDLORD_VALUE_NOT_V3", 3, value(agentValue(x.contract.LandlordName))},
		{"value-of-another-key", "STATED_LANDLORD_VALUE_KEY_MISMATCH", 3, value(landlordValue(other))},
		{"value-absent", "BAD_INPUT", 2, func(r *KeychainSignRequest) { r.LandlordValueHex = nil }},
		{"value-not-lower-hex", "BAD_INPUT", 2, func(r *KeychainSignRequest) { s := strings.ToUpper(*r.LandlordValueHex); r.LandlordValueHex = &s }},
		// Digest binding for /2.
		{"contract-digest-unbound", "DIGEST_BINDING", 3, func(r *KeychainSignRequest) { r.ToSign[0].Digest = r.ToSign[1].Digest }},
		{"grant-digest-unbound", "DIGEST_BINDING", 3, func(r *KeychainSignRequest) { r.ToSign[1].Digest = r.Draft.ContractSHA256 }},
		{"grant-digest-without-consent", "DIGEST_BINDING", 3, func(r *KeychainSignRequest) { r.ConsentEvent = nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			control := newKC(t, confirmWord)
			e, code := control.sign(x.request())
			mustOK(t, e, code)
			if control.count("show") != 1 || control.count("secret:") != 2 {
				t.Fatalf("valid control did not sign: %v", control.log)
			}
			h := newKC(t, confirmWord)
			r := x.request()
			c.edit(&r)
			e, code = h.sign(r)
			mustRefuse(t, e, code, c.want)
			if code != c.exit {
				t.Fatalf("exit %d, want %d", code, c.exit)
			}
			if h.count("show") != 0 || h.count("confirm") != 0 || h.count("secret:") != 0 {
				t.Fatalf("refused request reached the display or the key: %v", h.log)
			}
			if stated := strings.HasPrefix(c.want, "STATED_LANDLORD_VALUE_"); stated != strings.Contains(e.Error.Message, "the stated value") {
				t.Fatalf("refusal %s has the message %q", c.want, e.Error.Message)
			}
		})
	}
}

// Claim: under sign/2 a draft whose contract binds a scope document is
// refused as SCOPE_TEXT_HASH, before anything is shown and before any secret
// is read, when the document is missing, is another text, is the empty text
// or is not canonical base64. The unchanged request signs in the same subtest
// (the valid control). The companion cases, a document on a contract that
// binds none, are in TestKeychainSignV2Refusals.
func TestKeychainSignV2ScopeDocumentRefusals(t *testing.T) {
	text := "Work on the documentation only.\n"
	x := prepareV2(t, &text, nil)
	b64 := func(s string) *string {
		b := base64.StdEncoding.EncodeToString([]byte(s))
		return &b
	}
	raw := func(s string) *string { return &s }
	for name, doc := range map[string]*string{
		"missing":          nil,
		"another-text":     b64("Work on the documentation only."),
		"empty-text":       b64(""),
		"not-base64":       raw("!"),
		"unpadded-base64":  raw(strings.TrimRight(*b64(text), "=")),
		"trailing-newline": raw(*b64(text) + "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			control := newKC(t, confirmWord)
			e, code := control.sign(x.request())
			mustOK(t, e, code)
			if control.count("show") != 1 || control.count("secret:") != 2 {
				t.Fatalf("valid control did not sign: %v", control.log)
			}
			h := newKC(t, confirmWord)
			r := x.request()
			if doc != nil && *doc == *r.Draft.ScopeTextB64 {
				t.Fatal("fixture: the document was not changed")
			}
			r.Draft.ScopeTextB64 = doc
			e, code = h.sign(r)
			mustRefuse(t, e, code, "SCOPE_TEXT_HASH")
			if code != 3 {
				t.Fatalf("exit %d, want 3", code)
			}
			if h.count("show") != 0 || h.count("confirm") != 0 || h.count("secret:") != 0 {
				t.Fatalf("refused request reached the display or the key: %v", h.log)
			}
		})
	}
}

// Claim: the scope document is bounded before the display. A document of
// exactly 8192 bytes, and one of exactly 256 lines, sign; one byte or one
// line more is refused as SCOPE_TEXT_SIZE before anything is shown and before
// any secret is read. Both bounds are written out here. For a document at
// the bound the transcript keeps the order members, scope text, signature
// section, document, closing line, prompt; the closing line is the last line
// before the prompt and repeats the contract SHA-256, the document's SHA-256
// and the digest to be signed.
// Limit: the fake terminal is an unbounded buffer, so this proves the order
// and the bound, not what a physical terminal keeps in its scrollback.
func TestKeychainSignV2ScopeDocumentBounds(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		signs      bool
		lines      int // of the document block, when it signs
	}{
		{"bytes-at-bound", strings.Repeat("a", 8192), true, 1},
		{"bytes-above-bound", strings.Repeat("a", 8193), false, 0},
		{"lines-at-bound", strings.Repeat("a\n", 256), true, 256},
		{"lines-at-bound-no-final-line-feed", strings.Repeat("a\n", 255) + "a", true, 256},
		{"lines-above-bound", strings.Repeat("a\n", 257), false, 0},
		{"lines-above-bound-no-final-line-feed", strings.Repeat("a\n", 256) + "a", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := prepareV2(t, &tc.text, nil)
			r := x.request()
			r.ToSign = r.ToSign[:1]
			if !tc.signs {
				h := newKC(t, confirmWord)
				e, code := h.sign(r)
				mustRefuse(t, e, code, "SCOPE_TEXT_SIZE")
				if code != 3 {
					t.Fatalf("exit %d, want 3", code)
				}
				if h.count("show") != 0 || h.count("confirm") != 0 || h.count("secret:") != 0 {
					t.Fatalf("refused request reached the display or the key: %v", h.log)
				}
				return
			}
			shown := signOneV2(t, r)
			var at []int
			for _, mark := range []string{"\nTrust contract     : ", "\nSCOPE TEXT         : ", "\nSignature 1        : ", "\nScope document     : ", "\nApproval covers    : ", wantPrompt} {
				if strings.Count(shown, mark) != 1 {
					t.Fatalf("the display does not have exactly one %q", mark)
				}
				at = append(at, strings.Index(shown, mark))
			}
			if !slices.IsSorted(at) {
				t.Fatalf("the display sections are out of order: %v", at)
			}
			closing := "\nApproval covers    : contract SHA-256 " + x.draft.ContractSHA256 + "; scope document SHA-256 " + sha256Hex([]byte(tc.text)) + " (the members and the SCOPE TEXT stand above the document); contract_sha256 " + x.draft.ContractSHA256 + "\n" + wantPrompt
			if !strings.HasSuffix(shown, closing) {
				t.Fatal("the display does not end with the closing line and the prompt")
			}
			if got := len(linesUnder(shown, "Scope document     : ", "    | ")); got != tc.lines {
				t.Fatalf("the document block has %d lines, want %d", got, tc.lines)
			}
		})
	}
}

// Claim: the landlord value check of keychain sign is a check of the bytes
// the request states, and the display says so; the on-chain check is grant
// sign's. With the landlord name's current value changed to one that carries
// holders: (1) a request stating that value is refused, with the stated-value
// code; (2) a request stating the earlier legacy bytes signs, because this
// signer reads no chain, and its display states that the value is the
// request's and unverified, without the overstated wording and without the
// current value; (3) grant sign, which reads the chain, then refuses both the
// grant_hash stage and the completion with LANDLORD_NOT_V3. Control: the same
// grant sign request is accepted before the value changes.
// Limit: the chain is the loopback fixture node.
func TestKeychainSignV2StatedValueIsNotTheChainValue(t *testing.T) {
	x := prepareV2(t, nil, nil)
	key := x.draft.IssuerKey
	stage := GrantSignRequest{Schema: GrantSignSchema, Draft: x.draft, ConsentEvent: x.consent, LandlordSig: x.landlordSig}
	e, code := x.f.signCmd(stage)
	mustOK(t, e, code)

	current := `{"swarma":{"landlord":{"grant":"` + key + `","holders":[]}}}`
	x.f.node.set(x.contract.LandlordName, current)

	h := newKC(t, confirmWord)
	r := x.request()
	r.LandlordValueHex = hexValue(current)
	e, code = h.sign(r)
	mustRefuse(t, e, code, "STATED_LANDLORD_VALUE_NOT_V3")
	if h.count("show") != 0 || h.count("secret:") != 0 {
		t.Fatalf("refused request reached the display or the key: %v", h.log)
	}

	h = newKC(t, confirmWord)
	e, code = h.sign(x.request())
	mustOK(t, e, code)
	res := resultAs[KeychainSignResult](t, e)
	if len(res.Signatures) != 2 || h.count("show") != 1 || h.count("secret:") != 2 {
		t.Fatalf("the request stating the earlier value did not sign: %v", h.log)
	}
	shown := h.term.shown.String()
	checkValueUnverified(t, shown, landlordValue(key), x.draft.LandlordName)
	if strings.Contains(shown, "holders") {
		t.Fatal("the display mentions holders, which this signer never read")
	}

	e, code = x.f.signCmd(stage)
	mustRefuse(t, e, code, "LANDLORD_NOT_V3")
	stage.GrantSig = res.Signatures[1].Signature
	e, code = x.f.signCmd(stage)
	mustRefuse(t, e, code, "LANDLORD_NOT_V3")
}

// Claim: under sign/2 the label's stored key decides. With another key
// stored under the label, the request that signs under the landlord's key is
// refused as KEY_MISMATCH after the public read, before anything is shown and
// before any secret is read. Control: the same request signs with the
// landlord's key in the store.
func TestKeychainSignV2WrongStoreKey(t *testing.T) {
	x := prepareV2(t, nil, nil)
	control := newKC(t, confirmWord)
	e, code := control.sign(x.request())
	mustOK(t, e, code)
	if control.count("show") != 1 || control.count("secret:") != 2 {
		t.Fatalf("valid control did not sign: %v", control.log)
	}
	h := newKCWithStore(t, confirmWord, keychainfake.New(), bip340Secrets[keyOther])
	e, code = h.sign(x.request())
	mustRefuse(t, e, code, "KEY_MISMATCH")
	if code != 3 {
		t.Fatalf("exit %d, want 3", code)
	}
	if len(h.log) == 0 || h.log[0] != "public:"+kcLabel || h.count("show") != 0 || h.count("confirm") != 0 || h.count("secret:") != 0 {
		t.Fatalf("a request for another key reached the display or the key: %v", h.log)
	}
}

// Claim: the request schema alone selects the path, and it must agree with
// the draft record; nothing is inferred from the content. A /1 record under
// sign/2, a /2 record under sign/1, a record relabelled to the other schema,
// the sign/2 member landlord_value_hex under sign/1, and an unknown schema
// are all refused before the display, beside a valid sign/1 and a valid
// sign/2 request that sign.
func TestKeychainSignCrossSchema(t *testing.T) {
	f := preparedFlow(t)
	x := prepareV2(t, nil, nil)
	v1 := func() KeychainSignRequest {
		r := fullRequest(t, f)
		r.SealSpend = nil
		return r
	}
	for _, r := range []KeychainSignRequest{v1(), x.request()} {
		h := newKC(t, confirmWord)
		e, code := h.sign(r)
		mustOK(t, e, code)
		if h.count("show") != 1 || h.count("secret:") != 2 {
			t.Fatalf("valid control (%s) did not sign: %v", r.Schema, h.log)
		}
	}
	legacy := hexValue(landlordValue(x.draft.IssuerKey))
	cases := []struct {
		name, want string
		make       func() KeychainSignRequest
	}{
		{"v1-record-under-sign-2", "BAD_INPUT", func() KeychainSignRequest {
			r := v1()
			r.Schema, r.LandlordValueHex = KeychainSignV2Schema, legacy
			return r
		}},
		{"v2-record-under-sign-1", "BAD_INPUT", func() KeychainSignRequest {
			r := x.request()
			r.Schema, r.LandlordValueHex = KeychainSignSchema, nil
			return r
		}},
		{"v2-request-relabelled-sign-1", "BAD_INPUT", func() KeychainSignRequest {
			r := x.request()
			r.Schema = KeychainSignSchema
			return r
		}},
		{"sign-1-with-landlord-value", "BAD_INPUT", func() KeychainSignRequest {
			r := v1()
			r.LandlordValueHex = legacy
			return r
		}},
		{"v1-contract-in-a-v2-record", "CONTRACT_ENCODING", func() KeychainSignRequest {
			r := v1()
			r.Schema, r.LandlordValueHex, r.Draft.Schema = KeychainSignV2Schema, legacy, GrantRecordV2Schema
			return r
		}},
		{"v2-contract-in-a-v1-record", "CONTRACT_ENCODING", func() KeychainSignRequest {
			r := x.request()
			r.Schema, r.LandlordValueHex, r.Draft.Schema = KeychainSignSchema, nil, GrantRecordSchema
			return r
		}},
		{"unknown-schema", "BAD_INPUT", func() KeychainSignRequest {
			r := x.request()
			r.Schema = "swarma-keychain/sign/3"
			return r
		}},
		{"empty-schema", "BAD_INPUT", func() KeychainSignRequest {
			r := x.request()
			r.Schema = ""
			return r
		}},
		{"grant-sign-schema", "BAD_INPUT", func() KeychainSignRequest {
			r := x.request()
			r.Schema = GrantSignSchema
			return r
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newKC(t, confirmWord)
			e, code := h.sign(c.make())
			mustRefuse(t, e, code, c.want)
			if h.count("show") != 0 || h.count("secret:") != 0 {
				t.Fatalf("cross-schema request reached the display or the key: %v", h.log)
			}
		})
	}
}

// Claim: the signer's own gate between a parsed contract and the display
// holds without the parser. Given contract bytes and a typed contract, it
// admits them only when the typed contract re-encodes to exactly those bytes,
// carries the /2 profile string and the single depth-zero right on a root;
// it then returns the fifteen members read from the bytes. Each negative
// stands beside the valid pair. The members reader refuses any object that
// is not exactly the fifteen members in order: one missing, one extra, one
// repeated, or two adjacent members swapped.
func TestKeychainV2DisplayGate(t *testing.T) {
	c := baseV2Contract(t)
	raw := rawV2(t, c)
	members, code := admitV2Display(raw, c)
	if code != "" || len(members) != 15 {
		t.Fatalf("valid control refused: %q, %d members", code, len(members))
	}
	for i, m := range members {
		if m.name != lip0014Members[i] || !bytes.Contains(raw, []byte(`"`+m.name+`":`+m.value)) {
			t.Fatalf("member %d is %q = %s", i+1, m.name, m.value)
		}
	}
	typed := func(edit func(*TrustContractV2)) (TrustContractV2, []byte) {
		d := c
		d.Delegate = EmptyTrustDelegate()
		edit(&d)
		return d, rawV2(t, d)
	}
	// The same fifteen members with two adjacent ones in the other order: the
	// display claims the order of LIP-0014 section 3, so neither the gate nor
	// the members reader may admit it.
	swapped := replaceOnce(t, raw, `"parent_grant_id":"","ordinal":0`, `"ordinal":0,"parent_grant_id":""`)
	t.Run("members-swapped", func(t *testing.T) {
		if _, code := admitV2Display(swapped, c); code != "CONTRACT_ENCODING" {
			t.Fatalf("two members swapped: %q", code)
		}
	})
	t.Run("non-canonical-bytes", func(t *testing.T) {
		for _, bad := range [][]byte{replaceOnce(t, raw, `{"profile":`, `{ "profile":`), append(slices.Clone(raw), '\n'), replaceOnce(t, raw, `"network":"main"`, `"network":"mai\u006e"`)} {
			if _, code := admitV2Display(bad, c); code != "CONTRACT_ENCODING" {
				t.Fatalf("non-canonical bytes: %q", code)
			}
		}
	})
	t.Run("typed-contract-is-not-the-bytes", func(t *testing.T) {
		d, _ := typed(func(d *TrustContractV2) { d.Actions = []string{"instruct", "review", "spend"} })
		if _, code := admitV2Display(raw, d); code != "CONTRACT_ENCODING" {
			t.Fatalf("a typed contract that differs from the signed bytes: %q", code)
		}
	})
	t.Run("profile", func(t *testing.T) {
		d, b := typed(func(d *TrustContractV2) { d.Profile = TrustContractProfile })
		if _, code := admitV2Display(b, d); code != "CONTRACT_PROFILE" {
			t.Fatalf("profile /1 string: %q", code)
		}
	})
	for name, edit := range map[string]func(*TrustContractV2){
		"depth-1":    func(d *TrustContractV2) { d.Delegate.Depth = 1 },
		"actions":    func(d *TrustContractV2) { d.Delegate.Actions = []string{"review"} },
		"budget":     func(d *TrustContractV2) { d.Delegate.Budget = 1 },
		"slots":      func(d *TrustContractV2) { d.Delegate.Slots = []TrustSlot{{Executor: "id/x", Grantee: d.GranteeKey}} },
		"notaries":   func(d *TrustContractV2) { d.Delegate.Notaries = []TrustNotary{{Name: "id/n"}} },
		"checkpoint": func(d *TrustContractV2) { d.Delegate.Checkpoint = strings.Repeat("ab", 32) },
		"parent":     func(d *TrustContractV2) { d.ParentGrantID = strings.Repeat("ab", 32) },
		"ordinal":    func(d *TrustContractV2) { d.Ordinal = 1 },
	} {
		t.Run("not-depth-zero-root/"+name, func(t *testing.T) {
			d, b := typed(edit)
			if _, code := admitV2Display(b, d); code != "CONTRACT_DEPTH" {
				t.Fatalf("%s: %q", name, code)
			}
		})
	}
	t.Run("members-reader", func(t *testing.T) {
		if got, ok := contractMembersV2(raw); !ok || len(got) != 15 {
			t.Fatal("valid control refused")
		}
		for _, bad := range [][]byte{
			replaceOnce(t, raw, `,"note":""`, ``),
			replaceOnce(t, raw, `"note":""`, `"note":"","extra":0`),
			replaceOnce(t, raw, `"ordinal":0,`, ``),
			swapped,
			replaceOnce(t, raw, `"note":""`, `"note":"","note":""`),
			replaceOnce(t, raw, `{"profile":`, `{ "profile":`),
			append(slices.Clone(raw), '{', '}'),
			[]byte(`[]`), nil,
		} {
			if _, ok := contractMembersV2(bad); ok {
				t.Fatalf("admitted %q", bad)
			}
		}
	})
}

// Claim: escapeBytes shows every octet: printable ASCII as itself and any
// other byte as \xNN, never dropped or shortened; with the backslash flag a
// backslash is escaped too, so free text cannot spell an escape.
func TestKeychainV2EscapeBytes(t *testing.T) {
	in := []byte("a\\x41\x00\n\x7f\xc3\xa9~ ")
	if got := escapeBytes(in, false); got != `a\x41\x00\x0a\x7f\xc3\xa9~ ` {
		t.Fatalf("plain: %q", got)
	}
	if got := escapeBytes(in, true); got != `a\x5cx41\x00\x0a\x7f\xc3\xa9~ ` {
		t.Fatalf("with backslash: %q", got)
	}
	long := bytes.Repeat([]byte("z"), 5000)
	if got := escapeBytes(long, true); got != string(long) {
		t.Fatal("a long value was not shown in full")
	}
}
