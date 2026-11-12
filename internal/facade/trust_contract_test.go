package facade

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

const lip0013VectorsSHA256 = "9c29cddd739d56c5d15f4663c3cc923c6ea016730fc62634bff4b4214bf27ff8"

type lip0013Vectors struct {
	ValidContracts []struct {
		ID          string     `json:"id"`
		Contract    string     `json:"contract"`
		ContractHex string     `json:"contract_hex"`
		SHA256      string     `json:"sha256"`
		V3Scope     []string   `json:"v3_scope"`
		V3Budget    int64      `json:"v3_budget"`
		ConsentTags [][]string `json:"consent_tags"`
	} `json:"valid_contracts"`
	InvalidContracts []struct {
		ID       string `json:"id"`
		Contract string `json:"contract"`
		Expect   string `json:"expect"`
	} `json:"invalid_contracts"`
	Bindings []struct {
		ID          string `json:"id"`
		ContractRef string `json:"contract_ref"`
		Grant       struct {
			Network        string     `json:"network"`
			AgentName      string     `json:"agent_name"`
			LandlordName   string     `json:"landlord_name"`
			GranteeKey     string     `json:"grantee_key"`
			ContractSHA256 string     `json:"contract_sha256"`
			Scope          []string   `json:"scope"`
			Budget         int64      `json:"budget"`
			NotBefore      int64      `json:"not_before"`
			NotAfter       int64      `json:"not_after"`
			ConsentTags    [][]string `json:"consent_tags"`
		} `json:"grant"`
		Expect string `json:"expect"`
	} `json:"bindings"`
	Envelopes []struct {
		ID     string `json:"id"`
		Event  string `json:"event"`
		Expect string `json:"expect"`
	} `json:"envelopes"`
}

func loadLIP0013(t *testing.T) lip0013Vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/lip0013/trust-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v lip0013Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Claim: the vector file is the exact pinned copy of swarma-link-spec 8ea31e0.
func TestTrustVectorsPinned(t *testing.T) {
	raw, err := os.ReadFile("testdata/lip0013/trust-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != lip0013VectorsSHA256 {
		t.Fatal("LIP-0013 vector copy differs from the pinned file")
	}
	v := loadLIP0013(t)
	if len(v.ValidContracts) != 4 || len(v.InvalidContracts) != 32 || len(v.Bindings) != 15 {
		t.Fatalf("vector counts %d/%d/%d", len(v.ValidContracts), len(v.InvalidContracts), len(v.Bindings))
	}
}

// Claim: each of the four valid LIP-0013 contracts parses, re-encodes from its
// parsed fields to the exact vector bytes and hash, and derives the vector's
// v3 scope, budget and consent tags.
func TestTrustContractValidVectors(t *testing.T) {
	for _, vc := range loadLIP0013(t).ValidContracts {
		t.Run(vc.ID, func(t *testing.T) {
			c, code := ParseTrustContract([]byte(vc.Contract))
			if code != "" {
				t.Fatalf("valid vector refused %s", code)
			}
			raw, code := EncodeTrustContract(c)
			if code != "" || string(raw) != vc.Contract || hex.EncodeToString(raw) != vc.ContractHex || sha256Hex(raw) != vc.SHA256 {
				t.Fatal("re-encoded bytes or hash differ from the vector")
			}
			if !reflect.DeepEqual(trustScope(c.Actions), vc.V3Scope) || c.SpendBudget != vc.V3Budget {
				t.Fatal("derived scope or budget differs from the vector")
			}
			if !reflect.DeepEqual(trustConsentTags(raw), vc.ConsentTags) {
				t.Fatal("consent tags differ from the vector")
			}
		})
	}
}

// Claim: each of the 32 invalid LIP-0013 contracts refuses with exactly its
// section 2.3 code, and EncodeTrustContract never emits bytes the reader would
// refuse. Limit: vector coverage, not a grammar fuzzer.
func TestTrustContractInvalidVectors(t *testing.T) {
	for _, vc := range loadLIP0013(t).InvalidContracts {
		t.Run(vc.ID, func(t *testing.T) {
			c, code := ParseTrustContract([]byte(vc.Contract))
			if code != vc.Expect {
				t.Fatalf("code %q, want %q", code, vc.Expect)
			}
			if raw, encoded := EncodeTrustContract(c); encoded == "" {
				if _, again := ParseTrustContract(raw); again != "" {
					t.Fatal("encoder emitted refused bytes")
				}
			}
		})
	}
}

// Claim: the 15 LIP-0013 binding vectors give their section 2.5 result: the 4
// matching grants bind and each of the 11 one-field defects refuses with its
// own code (hash, contract field, scope, budget, consent tags).
func TestTrustContractBindingVectors(t *testing.T) {
	v := loadLIP0013(t)
	contracts := map[string]string{}
	for _, vc := range v.ValidContracts {
		contracts[vc.ID] = vc.Contract
	}
	for _, b := range v.Bindings {
		t.Run(b.ID, func(t *testing.T) {
			g := b.Grant
			code := bindTrustContract([]byte(contracts[b.ContractRef]), trustGrantView{g.Network, g.AgentName, g.LandlordName, g.GranteeKey, g.ContractSHA256, g.Scope, g.Budget, g.NotBefore, g.NotAfter, g.ConsentTags})
			if code == "" {
				code = "OK"
			}
			if code != b.Expect {
				t.Fatalf("binding %q, want %q", code, b.Expect)
			}
		})
	}
}
