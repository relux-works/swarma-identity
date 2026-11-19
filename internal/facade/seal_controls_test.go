package facade

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each bounded removal must compile and fail its named behavioral assertion;
// setup failures, panics and missing plants are not killed mutants. Existing
// observer helpers preserve isolated overlays and command/exit receipts.
func TestSealLifecyclePlantedControls(testingContext *testing.T) {
	observer, root := controlScratch(testingContext, "seal-lifecycle-controls-")
	baseline := filepath.Join(observer.scratch, "baseline.test")
	observer.goCommand(testingContext, "baseline-build", "test", "-mod=readonly", "-p", "1", "-c", "-o", baseline, "./internal/facade")
	testingContext.Cleanup(func() { os.Remove(baseline) })
	cases := []struct{ name, file, before, after, test, diagnostic string }{
		{"no-network-pin", "seal_lifecycle.go", "if grant.Network != request.Network || grant.Genesis != pinnedGenesis(request.Network) {", "if false && (grant.Network != request.Network || grant.Genesis != pinnedGenesis(request.Network)) {", "^TestSealPlanV3Controls$", "want NETWORK_PIN"},
		{"no-funding-owner-pin", "seal_lifecycle.go", "request.Funding.ScriptHex != \"0014\"+hex.EncodeToString(btcutil.Hash160(public))", "(request.Funding.ScriptHex != \"0014\"+hex.EncodeToString(btcutil.Hash160(public)) && false)", "^TestSealPlanV3Controls$", "want FUNDING_NOT_OWNED"},
		{"no-grant-outpoint-pin", "seal_lifecycle.go", "if grant.Seal.TxID != plan.UnsignedTxID || grant.Seal.Vout != 0 {", "if false && (grant.Seal.TxID != plan.UnsignedTxID || grant.Seal.Vout != 0) {", "^TestSealPlanV3Controls$", "want SEAL_GRANT_MISMATCH"},
		{"no-fee-cap", "seal_lifecycle.go", "if plan.FeeSat > request.MaxFeeSat {", "if false && plan.FeeSat > request.MaxFeeSat {", "^TestSealPlanV3Controls$", "want SEAL_FEE_CAP"},
		{"no-mempool-acceptance", "seal_lifecycle.go", "if !*acceptance[0].Allowed {", "if false && !*acceptance[0].Allowed {", "^TestSealBroadcastPreflightRefusals$", "want SEAL_MEMPOOL_REJECTED"},
		{"no-approval", "seal_sign.go", "if err != nil || !approved {", "if err != nil || (!approved && false) {", "^TestSealSignRefusals$", "want CONFIRMATION_DECLINED"},
		{"no-signature-recheck", "seal_journal.go", "} else if failure := journal.verifySigned(); failure != nil {", "} else if failure := journal.verifySigned(); failure != nil && false {", "^TestSealJournalTamperRefusals$", "want SEAL_SIGNED_TRANSACTION"},
		{"no-attempt-flag", "seal_lifecycle.go", "journal.Attempted = true", "journal.Attempted = false", "^TestSealCanceledAfterIntentNeverSends$", "incorrect canceled send"},
		{"no-local-idempotent-report", "seal_lifecycle.go", "if journal.Attempted {", "if journal.Attempted && false {", "^TestSealBroadcastUncertainNeverRetries$", "command refused"},
		{"no-active-block-check", "seal_lifecycle.go", "if observed == blockHash {", "if true {", "^TestSealObservationRefusalsAndInactiveBlock$", "inactive block counted toward depth"},
		{"one-confirmation-not-floor", "seal_lifecycle.go", "if depth >= journal.Request.MinConfirmations {", "if depth > 0 {", "^TestSealLifecycleV3Regtest$", "command refused"},
		{"accept-eof-fragment", "keychain_sign.go", "ReadString('\\n')\n\tif err != nil {", "ReadString('\\n')\n\tif err != nil && line == \"\" {", "^TestSealExactTerminalLine$", "accept=true, want false"},
	}
	for _, test := range cases {
		testingContext.Run(test.name, func(testingContext *testing.T) {
			if code, _ := observer.testProcess(testingContext, baseline, test.name+"-positive", test.test); code != 0 {
				testingContext.Fatal("unmodified seal control failed")
			}
			path := filepath.Join(root, "internal", "facade", test.file)
			source, err := os.ReadFile(path)
			if err != nil || bytes.Count(source, []byte(test.before)) != 1 {
				testingContext.Fatal("seal plant setup: expected exactly one source anchor")
			}
			copyPath := filepath.Join(observer.scratch, test.name+".go")
			if err := os.WriteFile(copyPath, bytes.Replace(source, []byte(test.before), []byte(test.after), 1), 0600); err != nil {
				testingContext.Fatal(err)
			}
			overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{path: copyPath}})
			overlayPath := filepath.Join(observer.scratch, test.name+".json")
			if err := os.WriteFile(overlayPath, overlay, 0600); err != nil {
				testingContext.Fatal(err)
			}
			binary := filepath.Join(observer.scratch, test.name+".test")
			observer.goCommand(testingContext, test.name+"-build", "test", "-mod=readonly", "-p", "1", "-c", "-overlay", overlayPath, "-o", binary, "./internal/facade")
			testingContext.Cleanup(func() { os.Remove(binary) })
			code, log := observer.testProcess(testingContext, binary, test.name+"-negative", test.test)
			if code != 1 || !strings.Contains(log, test.diagnostic) || !strings.Contains(log, "--- FAIL: Test") || strings.Contains(log, "panic:") {
				testingContext.Fatalf("seal plant missed its named assertion: exit %d, evidence %s", code, observer.scratch)
			}
			testingContext.Logf("mutant %s: baseline exit 0, mutant exit 1, named test %s, assertion %q", test.name, test.test, test.diagnostic)
		})
	}
}
