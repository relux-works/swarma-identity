package facade

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Reviewer rev362 F1 reproduction helpers and test names are preserved from
// inputs/rev362/repro; the two original regression functions are unmodified.
const rev362Canonical = `{"profile":"swarma-trust-contract/2","network":"regtest","landlord_name":"id/review","agent_name":"id/review-agent","grantee_key":"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9","actions":["instruct","review"],"repos":[],"spend_budget":0,"not_before":1794528000,"not_after":1797120000,"scope_text_sha256":"","parent_grant_id":"","ordinal":0,"delegate":{"depth":0,"actions":[],"budget":0,"slots":[],"notaries":[],"checkpoint":""},"note":""}`

func rev362Bytes(t *testing.T, value any) []byte {
	t.Helper()
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n"))
}

func rev362Contract(t *testing.T) TrustContractV2 {
	t.Helper()
	var contract TrustContractV2
	if err := json.Unmarshal([]byte(rev362Canonical), &contract); err != nil {
		t.Fatal(err)
	}
	if _, code := ParseTrustContractV2([]byte(rev362Canonical)); code != "" {
		t.Fatalf("positive neighbour: %s", code)
	}
	return contract
}

func rev362Hash(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func rev362Replace(t *testing.T, raw, before, after string) []byte {
	t.Helper()
	if strings.Count(raw, before) != 1 {
		t.Fatalf("ambiguous fixture anchor: %q", before)
	}
	return []byte(strings.Replace(raw, before, after, 1))
}

func rev362Refuse(t *testing.T, raw []byte, want string) {
	t.Helper()
	if _, code := ParseTrustContractV2([]byte(rev362Canonical)); code != "" {
		t.Fatalf("positive neighbour: %s", code)
	}
	contract, code := ParseTrustContractV2(raw)
	t.Logf("got=%s want=%s partial=%t", code, want, contract.Profile != "")
	if code != want || !reflect.DeepEqual(contract, TrustContractV2{}) {
		t.Errorf("got %q, want %q; no partial contract required", code, want)
	}
}

// Claim: a nested duplicate is owned by rule 9, so it cannot preempt a demonstrated earlier rule failure even if local duplicate codes are retained.
func TestRev362FreeHuntPrecedence(t *testing.T) {
	cases := []struct{ name, before, after, want string }{
		{"profile-rule-2", `swarma-trust-contract/2`, `swarma-trust-contract/1`, "CONTRACT_PROFILE"},
		{"actions-rule-4", `"actions":["instruct","review"]`, `"actions":["review","instruct"]`, "CONTRACT_ACTIONS"},
		{"budget-rule-6", `"spend_budget":0`, `"spend_budget":1`, "CONTRACT_BUDGET"},
		{"note-rule-7", `"note":""`, `"note":"` + strings.Repeat("a", 281) + `"`, "CONTRACT_NOTE"},
		{"parent-rule-8", `"ordinal":0`, `"ordinal":17`, "CONTRACT_PARENT"},
	}
	for _, entry := range cases {
		t.Run(entry.name, func(t *testing.T) {
			rev362Contract(t)
			earlier := rev362Replace(t, rev362Canonical, entry.before, entry.after)
			if _, code := ParseTrustContractV2(earlier); code != entry.want {
				t.Fatalf("isolated primary failure: got %s want %s", code, entry.want)
			}
			unknown := rev362Replace(t, string(earlier), `"checkpoint":""`, `"unknown":0,"checkpoint":""`)
			if _, code := ParseTrustContractV2(unknown); code != entry.want {
				t.Fatalf("unknown-member control: got %s want %s", code, entry.want)
			}
			compound := rev362Replace(t, string(earlier), `"checkpoint":""`, `"checkpoint":"","checkpoint":""`)
			rev362Refuse(t, compound, entry.want)
		})
	}
}

// Claim: the mandatory first-failure order is also observable through grant contract-verify, with each isolated earlier failure checked first.
func TestRev362FreeHuntPrecedenceCLI(t *testing.T) {
	signer := testSigner(t, keyLandlord)
	for _, entry := range []struct{ name, before, after, want string }{
		{"profile", `swarma-trust-contract/2`, `swarma-trust-contract/1`, "CONTRACT_PROFILE"},
		{"actions", `"actions":["instruct","review"]`, `"actions":["review","instruct"]`, "CONTRACT_ACTIONS"},
	} {
		t.Run(entry.name, func(t *testing.T) {
			invoke := func(raw []byte) (Envelope, int) {
				request := ContractVerifyV2Request{Schema: ContractVerifyV2Schema, ContractB64: base64.StdEncoding.EncodeToString(raw), IssuerKey: signer.PublicKey(), LandlordSig: sign(t, signer, rev362Hash(raw))}
				envelope, exit, _ := runCLI(t, "grant", "contract-verify", "--request", writeInput(t, request), "--json")
				return envelope, exit
			}
			envelope, exit := invoke([]byte(rev362Canonical))
			mustOK(t, envelope, exit)
			earlier := rev362Replace(t, rev362Canonical, entry.before, entry.after)
			envelope, exit = invoke(earlier)
			mustRefuse(t, envelope, exit, entry.want)
			compound := rev362Replace(t, string(earlier), `"checkpoint":""`, `"checkpoint":"","checkpoint":""`)
			envelope, exit = invoke(compound)
			mustRefuse(t, envelope, exit, entry.want)
		})
	}
}

// Claim: duplicates at every delegate object depth defer to rules 2–8, beside canonical, isolated-earlier and isolated-structure controls.
func TestTrustContractV2NestedDuplicateRuleOrder(t *testing.T) {
	earlier := []struct{ name, before, after, want string }{
		{"profile", `swarma-trust-contract/2`, `swarma-trust-contract/1`, "CONTRACT_PROFILE"},
		{"actions", `"actions":["instruct","review"]`, `"actions":["review","instruct"]`, "CONTRACT_ACTIONS"},
		{"repos", `"repos":[]`, `"repos":["https://git.example/a"]`, "CONTRACT_REPOS"},
		{"budget", `"spend_budget":0`, `"spend_budget":1`, "CONTRACT_BUDGET"},
		{"note", `"note":""`, `"note":"` + strings.Repeat("a", 281) + `"`, "CONTRACT_NOTE"},
		{"parent", `"ordinal":0`, `"ordinal":17`, "CONTRACT_PARENT"},
	}
	for _, shape := range []struct{ name, before, after string }{
		{"delegate", `"checkpoint":""`, `"checkpoint":"","checkpoint":""`},
		{"slot", `"slots":[]`, `"slots":[{"executor":"id/worker","grantee":"` + strings.Repeat("ab", 32) + `","cap":0,"cap":0,"notary":"id/notary"}]`},
		{"notary", `"notaries":[]`, `"notaries":[{"name":"id/notary","name":"id/notary","registration":{"txid":"` + strings.Repeat("ab", 32) + `","vout":0},"owner":"02` + strings.Repeat("ab", 32) + `"}]`},
		{"registration", `"notaries":[]`, `"notaries":[{"name":"id/notary","registration":{"txid":"` + strings.Repeat("ab", 32) + `","vout":0,"vout":0},"owner":"02` + strings.Repeat("ab", 32) + `"}]`},
	} {
		for _, entry := range earlier {
			t.Run(shape.name+"/"+entry.name, func(t *testing.T) {
				rev362Contract(t)
				isolated := rev362Replace(t, rev362Canonical, entry.before, entry.after)
				rev362Refuse(t, isolated, entry.want)
				structure := rev362Replace(t, rev362Canonical, shape.before, shape.after)
				rev362Refuse(t, structure, "CONTRACT_FIELD")
				compound := rev362Replace(t, string(isolated), shape.before, shape.after)
				rev362Refuse(t, compound, entry.want)
			})
		}
	}
}

// Claim: top-level duplicate structure and nested lexical violations remain rule-1 checks even when a nested duplicate or bad profile also exists.
func TestTrustContractV2DuplicateLexicalBoundary(t *testing.T) {
	nested := string(rev362Replace(t, rev362Canonical, `"checkpoint":""`, `"checkpoint":"","checkpoint":""`))
	for _, entry := range []struct{ name, before, after string }{
		{"whitespace", `"note":""`, `"note": ""`},
		{"number-before-duplicate", `"depth":0`, `"depth":-0`},
		{"number-after-duplicate", `"note":""`, `"note":0e0`},
		{"null", `"slots":[]`, `"slots":null`},
		{"boolean", `"depth":0`, `"depth":false`},
		{"escape-after-duplicate", `"note":""`, `"note":"\u0061"`},
	} {
		t.Run(entry.name, func(t *testing.T) {
			rev362Contract(t)
			isolated := rev362Replace(t, rev362Canonical, entry.before, entry.after)
			rev362Refuse(t, isolated, "CONTRACT_ENCODING")
			compound := rev362Replace(t, nested, entry.before, entry.after)
			compound = rev362Replace(t, string(compound), TrustContractV2Profile, TrustContractProfile)
			rev362Refuse(t, compound, "CONTRACT_ENCODING")
		})
	}
	t.Run("top-level-duplicate", func(t *testing.T) {
		rev362Contract(t)
		raw := rev362Replace(t, rev362Canonical, `"note":""`, `"note":"","note":""`)
		rev362Refuse(t, raw, "CONTRACT_FIELD")
		raw = rev362Replace(t, string(raw), TrustContractV2Profile, TrustContractProfile)
		rev362Refuse(t, raw, "CONTRACT_FIELD")
	})
}
