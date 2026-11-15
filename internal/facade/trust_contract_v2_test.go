package facade

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

const depthZeroVectorsHash = "f5fabc272768026abb5e7631921ac4c2d59e4ef5b5901cc69e6a742212fefed2"

type depthZeroVectors struct {
	ScopeText string `json:"scope_text"`
	Contracts []struct {
		ID             string   `json:"id"`
		Contract       string   `json:"contract"`
		Bytes          int      `json:"bytes"`
		SHA256         string   `json:"sha256"`
		V3Scope        []string `json:"v3_scope"`
		V3Budget       int64    `json:"v3_budget"`
		ConsentBooking string   `json:"consent_booking"`
	} `json:"contracts"`
}

func loadDepthZeroVectors(t *testing.T) depthZeroVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/lip0014/depth-zero-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if sha256Hex(raw) != depthZeroVectorsHash {
		t.Fatal("pinned /2 subset changed")
	}
	var v depthZeroVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Contracts) != 4 {
		t.Fatal("missing depth-zero goldens")
	}
	return v
}

func baseV2Contract(t *testing.T) TrustContractV2 {
	t.Helper()
	c, code := ParseTrustContractV2([]byte(loadDepthZeroVectors(t).Contracts[0].Contract))
	if code != "" {
		t.Fatal(code)
	}
	c.ScopeTextSHA256, c.Note = "", ""
	return c
}

func rawV2(t *testing.T, c TrustContractV2) []byte {
	t.Helper()
	b, ok := compactJSON(c)
	if !ok {
		t.Fatal("encoding fixture")
	}
	return b
}

// Claim: four pinned LIP-0014 depth-zero contracts retain exact bytes, hashes, scopes, budgets and booking tags.
func TestTrustContractV2GoldenVectors(t *testing.T) {
	v := loadDepthZeroVectors(t)
	for _, vc := range v.Contracts {
		t.Run(vc.ID, func(t *testing.T) {
			c, code := ParseTrustContractV2([]byte(vc.Contract))
			if code != "" {
				t.Fatal(code)
			}
			raw, code := EncodeTrustContractV2(c)
			if code != "" || string(raw) != vc.Contract || len(raw) != vc.Bytes || sha256Hex(raw) != vc.SHA256 {
				t.Fatal("golden bytes/hash mismatch", code)
			}
			if !reflect.DeepEqual(trustScope(c.Actions), vc.V3Scope) || c.SpendBudget != vc.V3Budget || trustConsentTags(raw)[2][1] != vc.ConsentBooking {
				t.Fatal("golden derived fields mismatch")
			}
			if c.ParentGrantID == "" {
				issued, code := IssueTrustContractV2(c, []byte(v.ScopeText))
				if code != "" || !bytes.Equal(issued, raw) {
					t.Fatal("golden issuer mismatch", code)
				}
			} else if issued, code := IssueTrustContractV2(c, nil); code != "CONTRACT_DEPTH" || issued != nil {
				t.Fatal("child issuance bypasses certification", code)
			}
		})
	}
}

// Claim: each malformed byte/value fixture refuses by its named code beside an admitted unchanged positive neighbour.
func TestTrustContractV2PairedNegatives(t *testing.T) {
	base := baseV2Contract(t)
	good := rawV2(t, base)
	replace := func(old, new string) func([]byte) []byte {
		return func(b []byte) []byte { return []byte(strings.Replace(string(b), old, new, 1)) }
	}
	mutate := func(f func(*TrustContractV2)) func([]byte) []byte {
		return func([]byte) []byte { c := baseV2Contract(t); f(&c); return rawV2(t, c) }
	}
	cases := []struct {
		name, code string
		change     func([]byte) []byte
	}{
		{"depth-1", "CONTRACT_DEPTH", replace(`"depth":0`, `"depth":1`)},
		{"depth-2", "CONTRACT_DEPTH", replace(`"depth":0`, `"depth":2`)},
		{"actions", "CONTRACT_DEPTH", replace(`"depth":0,"actions":[]`, `"depth":0,"actions":["instruct"]`)},
		{"budget", "CONTRACT_DEPTH", replace(`"budget":0`, `"budget":1`)},
		{"slots", "CONTRACT_DEPTH", mutate(func(c *TrustContractV2) { c.Delegate.Slots = []TrustSlot{{c.AgentName, c.GranteeKey, 0, "id/notary"}} })},
		{"notaries", "CONTRACT_DEPTH", mutate(func(c *TrustContractV2) {
			c.Delegate.Notaries = []TrustNotary{{"id/notary", TrustRegistration{strings.Repeat("ab", 32), 0}, "02" + c.GranteeKey}}
		})},
		{"checkpoint", "CONTRACT_DEPTH", replace(`"checkpoint":""`, `"checkpoint":"`+strings.Repeat("ab", 32)+`"`)},
		{"unknown", "CONTRACT_FIELD", replace(`"note":""`, `"unknown":0,"note":""`)},
		{"duplicate", "CONTRACT_FIELD", replace(`"note":""`, `"note":"","note":""`)},
		{"delegate-unknown", "CONTRACT_FIELD", replace(`"checkpoint":""`, `"extra":0,"checkpoint":""`)},
		{"delegate-duplicate", "CONTRACT_FIELD", replace(`"depth":0`, `"depth":0,"depth":0`)},
		{"case-alias", "CONTRACT_FIELD", replace(`"note":""`, `"Note":""`)},
		{"missing", "CONTRACT_ENCODING", replace(`,"note":""`, ``)},
		{"missing-delegate-member", "CONTRACT_DELEGATE", replace(`"budget":0,`, ``)},
		{"order", "CONTRACT_ENCODING", replace(`"profile":"swarma-trust-contract/2","network":"main"`, `"network":"main","profile":"swarma-trust-contract/2"`)},
		{"delegate-order", "CONTRACT_DELEGATE", replace(`"depth":0,"actions":[]`, `"actions":[],"depth":0`)},
		{"space", "CONTRACT_ENCODING", replace(`"profile":`, `"profile": `)},
		{"tab", "CONTRACT_ENCODING", replace(`"profile":`, "\"profile\":\t")},
		{"newline", "CONTRACT_ENCODING", func(b []byte) []byte { return append(bytes.Clone(b), '\n') }},
		{"trailing-document", "CONTRACT_ENCODING", func(b []byte) []byte { return append(bytes.Clone(b), []byte(`{}`)...) }},
		{"profile-1", "CONTRACT_PROFILE", replace(TrustContractV2Profile, TrustContractProfile)},
		{"profile-3", "CONTRACT_PROFILE", replace(TrustContractV2Profile, "swarma-trust-contract/3")},
		{"hash-short", "CONTRACT_FIELD", mutate(func(c *TrustContractV2) { c.ScopeTextSHA256 = strings.Repeat("a", 63) })},
		{"hash-uppercase", "CONTRACT_FIELD", mutate(func(c *TrustContractV2) { c.ScopeTextSHA256 = strings.Repeat("AB", 32) })},
		{"hash-nonhex", "CONTRACT_FIELD", mutate(func(c *TrustContractV2) { c.ScopeTextSHA256 = strings.Repeat("zz", 32) })},
		{"network", "CONTRACT_FIELD", mutate(func(c *TrustContractV2) { c.Network = "testnet" })},
		{"same-name", "CONTRACT_FIELD", mutate(func(c *TrustContractV2) { c.AgentName = c.LandlordName })},
		{"name-syntax", "CONTRACT_FIELD", mutate(func(c *TrustContractV2) { c.AgentName = "id/UPPER" })},
		{"key", "CONTRACT_FIELD", mutate(func(c *TrustContractV2) { c.GranteeKey = strings.Repeat("00", 32) })},
		{"window", "CONTRACT_FIELD", mutate(func(c *TrustContractV2) { c.NotAfter = c.NotBefore })},
		{"time-bound", "CONTRACT_FIELD", mutate(func(c *TrustContractV2) { c.NotAfter = trustMaxTime + 1 })},
		{"empty-actions", "CONTRACT_ACTIONS", mutate(func(c *TrustContractV2) { c.Actions = []string{} })},
		{"action-duplicate", "CONTRACT_ACTIONS", mutate(func(c *TrustContractV2) { c.Actions = []string{"review", "review"} })},
		{"action-order", "CONTRACT_ACTIONS", mutate(func(c *TrustContractV2) { c.Actions = []string{"review", "instruct"} })},
		{"action-unknown", "CONTRACT_ACTIONS", mutate(func(c *TrustContractV2) { c.Actions = []string{"delegate"} })},
		{"land-without-repo", "CONTRACT_REPOS", mutate(func(c *TrustContractV2) { c.Actions = []string{"land"} })},
		{"repo-without-land", "CONTRACT_REPOS", mutate(func(c *TrustContractV2) { c.Repos = []string{"https://git.example/a"} })},
		{"spend-without-budget", "CONTRACT_BUDGET", mutate(func(c *TrustContractV2) { c.Actions = []string{"spend"} })},
		{"budget-without-spend", "CONTRACT_BUDGET", mutate(func(c *TrustContractV2) { c.SpendBudget = 1 })},
		{"note-limit", "CONTRACT_NOTE", mutate(func(c *TrustContractV2) { c.Note = strings.Repeat("a", 281) })},
		{"parent-ordinal", "CONTRACT_PARENT", mutate(func(c *TrustContractV2) { c.Ordinal = 1 })},
		{"parent-hash", "CONTRACT_PARENT", mutate(func(c *TrustContractV2) { c.ParentGrantID = "bad"; c.Ordinal = 1 })},
		{"ordinal-bound", "CONTRACT_PARENT", mutate(func(c *TrustContractV2) { c.ParentGrantID = strings.Repeat("ab", 32); c.Ordinal = 17 })},
		{"negative", "CONTRACT_ENCODING", replace(`"ordinal":0`, `"ordinal":-1`)},
		{"minus-zero", "CONTRACT_ENCODING", replace(`"depth":0`, `"depth":-0`)},
		{"fraction", "CONTRACT_ENCODING", replace(`"depth":0`, `"depth":0.0`)},
		{"exponent", "CONTRACT_ENCODING", replace(`"budget":0`, `"budget":0e0`)},
		{"overflow", "CONTRACT_ENCODING", replace(`"depth":0`, `"depth":9223372036854775808`)},
		{"leading-zero", "CONTRACT_ENCODING", replace(`"depth":0`, `"depth":00`)},
		{"null", "CONTRACT_ENCODING", replace(`"slots":[]`, `"slots":null`)},
		{"bool", "CONTRACT_ENCODING", replace(`"depth":0`, `"depth":false`)},
		{"string-integer", "CONTRACT_DELEGATE", replace(`"depth":0`, `"depth":"0"`)},
		{"wrong-top-type", "CONTRACT_ENCODING", replace(`"ordinal":0`, `"ordinal":"0"`)},
		{"escaped-key", "CONTRACT_ENCODING", replace(`"note":`, `"n\u006fte":`)},
		{"escaped-string", "CONTRACT_ENCODING", replace(`"note":""`, `"note":"\u0061"`)},
		{"non-ascii", "CONTRACT_ENCODING", mutate(func(c *TrustContractV2) { c.Note = "café" })},
		{"control", "CONTRACT_ENCODING", mutate(func(c *TrustContractV2) { c.Note = "line\nline" })},
		{"too-large", "CONTRACT_ENCODING", mutate(func(c *TrustContractV2) { c.Note = strings.Repeat("a", 8193) })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, code := ParseTrustContractV2(good); code != "" {
				t.Fatal("valid neighbour", code)
			}
			bad := tc.change(good)
			if bytes.Equal(good, bad) {
				t.Fatal("negative fixture was not changed")
			}
			c, code := ParseTrustContractV2(bad)
			if code != tc.code || !reflect.DeepEqual(c, TrustContractV2{}) {
				t.Fatalf("got %s, want %s; partial=%v", code, tc.code, c.Profile != "")
			}
		})
	}
}

// Claim: every top-level and delegate member refuses unknown/duplicate spellings beside the unchanged depth-zero contract.
func TestTrustContractV2ClosedMembers(t *testing.T) {
	good := rawV2(t, baseV2Contract(t))
	for group, names := range [][]string{contractV2Members, delegateV2Members} {
		for _, name := range names {
			for _, mode := range []string{"unknown", "duplicate"} {
				t.Run(name+"/"+mode, func(t *testing.T) {
					if _, code := ParseTrustContractV2(good); code != "" {
						t.Fatal(code)
					}
					needle := `"` + name + `":`
					replacement := `"unknown_` + name + `":`
					if mode == "duplicate" {
						replacement = needle + `0,` + needle
					}
					target := string(good)
					if group == 1 {
						i := strings.Index(target, `"delegate":`)
						target = target[:i] + strings.Replace(target[i:], needle, replacement, 1)
					} else {
						target = strings.Replace(target, needle, replacement, 1)
					}
					bad := []byte(target)
					if _, code := ParseTrustContractV2(bad); code != "CONTRACT_FIELD" {
						t.Fatal(code)
					}
				})
			}
		}
	}
}

// Claim: raw-hash BIP-340 succeeds; altered bytes, text, keys, signatures and a prefixed signature fail without a result.
func TestTrustContractV2SignatureAndScopePairs(t *testing.T) {
	landlord := testSigner(t, keyLandlord)
	c := baseV2Contract(t)
	text := []byte("scope\r\nUTF-8: café\n")
	c.ScopeTextSHA256 = sha256Hex(text)
	raw, code := IssueTrustContractV2(c, text)
	if code != "" {
		t.Fatal(code)
	}
	sig := sign(t, landlord, sha256Hex(raw))
	cases := []struct {
		name           string
		raw, text      []byte
		key, sig, code string
	}{
		{"text-change", raw, append(bytes.Clone(text), ' '), landlord.PublicKey(), sig, "SCOPE_TEXT_HASH"},
		{"text-newline", raw, bytes.ReplaceAll(text, []byte("\r\n"), []byte("\n")), landlord.PublicKey(), sig, "SCOPE_TEXT_HASH"},
		{"text-absent", raw, nil, landlord.PublicKey(), sig, "SCOPE_TEXT_HASH"},
		{"text-empty", raw, []byte{}, landlord.PublicKey(), sig, "SCOPE_TEXT_HASH"},
		{"signature", raw, text, landlord.PublicKey(), strings.Repeat("00", 64), "LANDLORD_SIGNATURE"},
		{"signature-uppercase", raw, text, landlord.PublicKey(), strings.ToUpper(sig), "LANDLORD_SIGNATURE"},
		{"signature-short", raw, text, landlord.PublicKey(), sig[:126], "LANDLORD_SIGNATURE"},
		{"wrong-key", raw, text, testsigner_public(t, keyOther), sig, "LANDLORD_SIGNATURE"},
		{"bad-key", raw, text, strings.Repeat("00", 32), sig, "LANDLORD_SIGNATURE"},
		{"wrong-domain", raw, text, landlord.PublicKey(), sign(t, landlord, sha256Hex(append([]byte("swarma-trust-contract/2"), raw...))), "LANDLORD_SIGNATURE"},
		{"changed-contract", bytes.Replace(raw, []byte(`"note":""`), []byte(`"note":"changed"`), 1), text, landlord.PublicKey(), sig, "LANDLORD_SIGNATURE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, code := VerifyTrustContractV2(raw, text, landlord.PublicKey(), sig); code != "" || !reflect.DeepEqual(got, c) {
				t.Fatal("valid neighbour", code)
			}
			got, code := VerifyTrustContractV2(tc.raw, tc.text, tc.key, tc.sig)
			if code != tc.code || !reflect.DeepEqual(got, TrustContractV2{}) {
				t.Fatalf("got %s, want %s", code, tc.code)
			}
		})
	}
	// Claim: nil means no document, while a present empty document hashes normally and cannot alias absence.
	for _, empty := range []bool{false, true} {
		c := baseV2Contract(t)
		var text []byte
		if empty {
			text = []byte{}
			c.ScopeTextSHA256 = sha256Hex(text)
		}
		raw, code := IssueTrustContractV2(c, text)
		if code != "" {
			t.Fatal(code)
		}
		if _, code := VerifyTrustContractV2(raw, text, landlord.PublicKey(), sign(t, landlord, sha256Hex(raw))); code != "" {
			t.Fatal(code)
		}
		wrong := []byte{}
		if empty {
			wrong = nil
		}
		if b, code := IssueTrustContractV2(c, wrong); b != nil || code != "SCOPE_TEXT_HASH" {
			t.Fatal("empty/absent alias", code)
		}
	}
}

// Claim: the /1 reader and encoder retain all pinned /1 vector bytes and still refuse /2 profiles or member sets.
func TestTrustContractV1UnchangedBesideV2(t *testing.T) {
	for _, v := range loadLIP0013(t).ValidContracts {
		c, code := ParseTrustContract([]byte(v.Contract))
		if code != "" {
			t.Fatal(code)
		}
		b, code := EncodeTrustContract(c)
		if code != "" || string(b) != v.Contract || hex.EncodeToString(b) != v.ContractHex {
			t.Fatal("/1 changed", code)
		}
		if _, code := ParseTrustContractV2(b); code != "CONTRACT_ENCODING" {
			t.Fatal("/2 accepted eleven members", code)
		}
		if _, code := ParseTrustContract([]byte(strings.Replace(v.Contract, TrustContractProfile, TrustContractV2Profile, 1))); code != "CONTRACT_PROFILE" {
			t.Fatal("/1 profile rule changed", code)
		}
	}
	if _, code := ParseTrustContract(rawV2(t, baseV2Contract(t))); code != "CONTRACT_ENCODING" {
		t.Fatal("/1 accepted fifteen members", code)
	}
}

// Claim: unknown/duplicate slot, notary and registration members refuse CONTRACT_FIELD, beside the admitted empty-right neighbour.
func TestTrustContractV2NestedClosedMembers(t *testing.T) {
	good := rawV2(t, baseV2Contract(t))
	row := `{"executor":"id/worker","grantee":"` + baseV2Contract(t).GranteeKey + `","cap":0,"notary":"id/notary"}`
	entry := `{"name":"id/notary","registration":{"txid":"` + strings.Repeat("ab", 32) + `","vout":0},"owner":"02` + baseV2Contract(t).GranteeKey + `"}`
	for _, tc := range []struct {
		name, needle, shape string
		members             []string
	}{
		{"slot", `"slots":[]`, `"slots":[` + row + `]`, []string{"executor", "grantee", "cap", "notary"}},
		{"notary", `"notaries":[]`, `"notaries":[` + entry + `]`, []string{"name", "registration", "owner", "txid", "vout"}},
	} {
		for _, name := range tc.members {
			for _, mode := range []string{"unknown", "duplicate"} {
				t.Run(tc.name+"/"+name+"/"+mode, func(t *testing.T) {
					if _, code := ParseTrustContractV2(good); code != "" {
						t.Fatal("valid neighbour", code)
					}
					shape := tc.shape
					needle := `"` + name + `":`
					replacement := `"unknown_` + name + `":`
					if mode == "duplicate" {
						replacement = needle + `0,` + needle
					}
					shape = strings.Replace(shape, needle, replacement, 1)
					bad := []byte(strings.Replace(string(good), tc.needle, shape, 1))
					if _, code := ParseTrustContractV2(bad); code != "CONTRACT_FIELD" {
						t.Fatalf("got %s, want CONTRACT_FIELD", code)
					}
				})
			}
		}
	}
}

// Claim: the typed issuer refuses nil arrays instead of silently filling members, beside the explicit canonical empty arrays.
func TestTrustContractV2IssuerNoImplicitArrays(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*TrustContractV2)
	}{
		{"actions", func(c *TrustContractV2) { c.Actions = nil }},
		{"repos", func(c *TrustContractV2) { c.Repos = nil }},
		{"delegate-actions", func(c *TrustContractV2) { c.Delegate.Actions = nil }},
		{"slots", func(c *TrustContractV2) { c.Delegate.Slots = nil }},
		{"notaries", func(c *TrustContractV2) { c.Delegate.Notaries = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := baseV2Contract(t)
			if b, code := IssueTrustContractV2(c, nil); code != "" || b == nil {
				t.Fatal("valid neighbour", code)
			}
			tc.mutate(&c)
			if b, code := IssueTrustContractV2(c, nil); code != "CONTRACT_ENCODING" || b != nil {
				t.Fatalf("got %s, want CONTRACT_ENCODING", code)
			}
		})
	}
}
