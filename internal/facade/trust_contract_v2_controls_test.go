package facade

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: bounded overlay removals are killed by named /2 regression assertions, with an unchanged positive binary for each plant.
func TestTrustContractV2PlantedControls(t *testing.T) {
	o, root := controlScratch(t, "trust-v2-controls-")
	baseline := filepath.Join(o.scratch, "baseline.test")
	o.goCommand(t, "baseline-build", "test", "-mod=readonly", "-p", "1", "-c", "-o", baseline, "./internal/facade")
	t.Cleanup(func() { os.Remove(baseline) })
	cases := []struct{ name, file, before, after, test, diagnostic string }{
		{"allow-depth-1", "trust_contract_v2.go", "r.Depth != 0 || len(r.Actions)", "len(r.Actions)", "^TestTrustContractV2PairedNegatives$/^depth-1$", "want CONTRACT_DEPTH"},
		{"allow-delegate-actions", "trust_contract_v2.go", "len(r.Actions) != 0 || r.Budget", "r.Budget", "^TestTrustContractV2PairedNegatives$/^actions$", "want CONTRACT_DEPTH"},
		{"ignore-member-set", "trust_contract_v2.go", `if code := v2Members(raw, contractV2Members, "CONTRACT_ENCODING"); code != "" {`, `if code := v2Members(raw, contractV2Members, "CONTRACT_ENCODING"); false {`, "^TestTrustContractV2PairedNegatives$/^unknown$", "want CONTRACT_FIELD"},
		{"ignore-canonical-bytes", "trust_contract_v2.go", "err != io.EOF || !bytes.Equal(raw, canonical)", "err != io.EOF || !bytes.Equal(canonical, canonical)", "^TestTrustContractV2PairedNegatives$/^space$", "want CONTRACT_ENCODING"},
		{"ignore-scope-hash", "trust_contract_v2.go", "text == nil || sha256Hex(text) != c.ScopeTextSHA256", "text == nil", "^TestTrustContractV2SignatureAndScopePairs$/^text-change$", "want SCOPE_TEXT_HASH"},
		{"ignore-landlord-signature", "grant_contract_v2.go", "if !sigValid(issuerKey, sha256Hex(raw), landlordSig) {", "if false {", "^TestTrustContractV2SignatureAndScopePairs$/^signature$", "want LANDLORD_SIGNATURE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if exit, _ := o.testProcess(t, baseline, tc.name+"-positive", tc.test); exit != 0 {
				t.Fatal("unchanged control failed")
			}
			path := filepath.Join(root, "internal", "facade", tc.file)
			source, err := os.ReadFile(path)
			if err != nil || bytes.Count(source, []byte(tc.before)) != 1 {
				t.Fatal("plant anchor missing or ambiguous")
			}
			copyPath := filepath.Join(o.scratch, tc.name+".go")
			if err := os.WriteFile(copyPath, bytes.Replace(source, []byte(tc.before), []byte(tc.after), 1), 0600); err != nil {
				t.Fatal(err)
			}
			overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{path: copyPath}})
			overlayPath := filepath.Join(o.scratch, tc.name+".json")
			if err := os.WriteFile(overlayPath, overlay, 0600); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(o.scratch, tc.name+".test")
			o.goCommand(t, tc.name+"-build", "test", "-mod=readonly", "-p", "1", "-c", "-overlay", overlayPath, "-o", binary, "./internal/facade")
			t.Cleanup(func() { os.Remove(binary) })
			exit, log := o.testProcess(t, binary, tc.name+"-negative", tc.test)
			if exit != 1 || !strings.Contains(log, tc.diagnostic) || !strings.Contains(log, "--- FAIL: Test") || strings.Contains(log, "panic:") {
				t.Fatalf("plant did not fail at its named assertion: exit %d; evidence %s", exit, o.scratch)
			}
			t.Logf("%s: unmodified exit 0; mutant exit 1; %s; assertion %s", tc.name, tc.test, tc.diagnostic)
		})
	}
}
