package facade

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testsignerPackage = "github.com/relux-works/swarma-identity/internal/testsigner"

// Signing and private-key construction APIs that product code must not use.
var forbiddenKeyAPIs = []string{"schnorr.Sign(", "ecdsa.Sign", "PrivKeyFromBytes", "NewPrivateKey", "PrivateKey", "IssueGrant", "testsigner"}

// keyAPIUse returns the first forbidden key API that the source text uses.
func keyAPIUse(source []byte) string {
	for _, api := range forbiddenKeyAPIs {
		if bytes.Contains(source, []byte(api)) {
			return api
		}
	}
	return ""
}

func controlScratch(t *testing.T, prefix string) (*nostrObserver, string) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".temp"), 0700); err != nil {
		t.Fatalf("control scratch root: %v", err)
	}
	scratch, err := os.MkdirTemp(filepath.Join(root, ".temp"), prefix)
	if err != nil {
		t.Fatalf("control scratch: %v", err)
	}
	return &nostrObserver{root: root, scratch: scratch}, root
}

// Claim: the shipped binary cannot hold a private key through this repository:
// its dependency closure excludes the test signer, and no product source file
// under cmd/ or internal/facade/ uses a signing or private-key API. The control
// halves show that the dependency check sees the signer where it is imported
// and that the source scan flags each forbidden API in a planted snippet.
// Limit: the linked chain-lab rental module still contains its own regtest
// issuer code; this proves only that no product path here calls it.
func TestBinaryHoldsNoSigner(t *testing.T) {
	o, root := controlScratch(t, "grant-custody-")
	deps := string(o.goCommand(t, "deps-binary", "list", "-mod=readonly", "-deps", "./cmd/swarma-identity"))
	if !strings.Contains(deps, "github.com/relux-works/swarma-identity/internal/facade\n") || strings.Contains(deps, testsignerPackage) {
		t.Fatal("binary dependency closure includes the test signer or is unreadable")
	}
	control := string(o.goCommand(t, "deps-control", "list", "-mod=readonly", "-deps", "./internal/testsigner"))
	if !strings.Contains(control, testsignerPackage+"\n") {
		t.Fatal("dependency control does not see a direct listing of the signer")
	}
	var files []string
	for _, dir := range []string{"cmd/swarma-identity", "internal/facade"} {
		matches, _ := filepath.Glob(filepath.Join(root, dir, "*.go"))
		for _, m := range matches {
			if !strings.HasSuffix(m, "_test.go") {
				files = append(files, m)
			}
		}
	}
	if len(files) < 10 {
		t.Fatal("source scan found too few product files")
	}
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if api := keyAPIUse(b); api != "" {
			t.Fatalf("%s uses %s", filepath.Base(path), api)
		}
	}
	for _, api := range forbiddenKeyAPIs {
		if keyAPIUse([]byte("package facade\nfunc f() { _ = "+api+" }\n")) != api {
			t.Fatalf("source scan misses planted %s", api)
		}
	}
}

// Claim: each key grant-issuance negative is detected by its named test. Removing or
// narrowing one product check in an isolated overlay copy makes that test
// fail at its own assertion, while the unmodified build passes the same
// selection. One planted removal is expected to survive, and its bound is
// stated beside it.
// Limit: single-check removals, not exhaustive mutation testing. Files on
// disk are never changed.
func TestGrantPlantedControls(t *testing.T) {
	o, root := controlScratch(t, "grant-controls-")
	cases := []struct {
		name, pkg, file, before, after, test, diagnostic string
		survives                                         bool
	}{
		{"no-consent-signature", "facade", "grant.go",
			"if !sigValid(d.GranteeKey, e.ID, e.Sig) {", "if false {",
			"^TestGrantConsentSignerNegatives$", "want CONSENT_SIGNATURE", false},
		{"no-consent-signer", "facade", "grant.go",
			"if e.Pubkey != d.GranteeKey {", "if false {",
			"^TestGrantConsentSignerNegatives$", "want CONSENT_SIGNER", false},
		{"no-contract-hash", "facade", "trust_contract.go",
			"if sha256Hex(raw) != g.ContractSHA256 {", "if false {",
			"^TestGrantFieldsBindToContract$", "want CONTRACT_HASH", false},
		{"no-agent-binding", "facade", "trust_contract.go",
			"c.LandlordName != g.LandlordName || c.AgentName != g.AgentName ||", "c.LandlordName != g.LandlordName ||",
			"^TestGrantFieldsBindToContract$", "want CONTRACT_MISMATCH", false},
		{"no-scope-binding", "facade", "trust_contract.go",
			"if g.Scope == nil || !slices.Equal(trustScope(c.Actions), g.Scope) {", "if g.Scope == nil {",
			"^TestGrantFieldsBindToContract$", "want SCOPE_MISMATCH", false},
		{"no-budget-binding", "facade", "trust_contract.go",
			"if c.SpendBudget != g.Budget {", "if false {",
			"^TestGrantFieldsBindToContract$", "want BUDGET_MISMATCH", false},
		{"no-on-chain-key-pin", "facade", "grant.go",
			"if onChain != d.IssuerKey {", "if false {",
			"^TestGrantLandlordKeyNegatives$", "want LANDLORD_KEY_MISMATCH", false},
		{"no-landlord-sig-check", "facade", "grant.go",
			"if !sigValid(onChain, d.ContractSHA256, r.LandlordSig) {", "if false {",
			"^TestGrantLandlordKeyNegatives$", "want LANDLORD_SIGNATURE", false},
		// Bound: rental.ParseSignedGrant re-verifies the grant signature and
		// refuses with the same code, so this removal is not observable.
		{"no-grant-sig-check", "facade", "grant.go",
			"if !sigValid(onChain, hash, r.GrantSig) {", "if false {",
			"^TestGrantLandlordKeyNegatives$", "", true},
		{"no-genesis-pin-at-sign", "facade", "grant.go",
			"if d.Network != c.config.Network || c.config.Node.GenesisHash != pinnedGenesis(d.Network) {", "if d.Network != c.config.Network {",
			"^TestGrantDraftPartyNegatives$", "want NETWORK_PIN", false},
		{"no-seal-check-at-sign", "facade", "grant.go",
			`if recorded != "" && recorded != id {`, "if false {",
			"^TestGrantSealReuse$", "want SEAL_REUSED", false},
		{"no-seal-check-at-draft", "facade", "grant.go",
			`if ledger.lookup(r.Seal.TxID, r.Seal.Vout) != "" {`, "if false {",
			"^TestGrantSealReuse$", "want SEAL_REUSED", false},
		{"no-ledger-walk-nofollow", "facade", "seal_ledger.go",
			"next, err := openAt(dir, c, unix.O_RDONLY|unix.O_DIRECTORY, 0)", "next, err := unix.Openat(dir, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)",
			"^TestGrantSealLedgerCustody$", "want LEDGER_FILE", false},
		{"no-ledger-rebind-check", "facade", "seal_ledger.go",
			`lockDir(ctx, dir) != nil || !l.bound() || ledgerStep("locked") != nil`, `lockDir(ctx, dir) != nil || ledgerStep("locked") != nil`,
			"^TestSealLedgerParentSubstitution$", "want LEDGER_FILE", false},
		{"no-ledger-handle-binding", "facade", "seal_ledger.go",
			"fd, err := openAt(l.dir, l.name, unix.O_RDONLY|unix.O_NONBLOCK, 0)", "fd, err := openAt(unix.AT_FDCWD, l.path, unix.O_RDONLY|unix.O_NONBLOCK, 0)",
			"^TestSealLedgerParentSubstitution$", "want SEAL_REUSED", false},
		{"ledger-empty-reads-as-new", "facade", "seal_ledger.go",
			"st.Size() == 0 || st.Size() > sealLedgerMax {", "st.Size() > sealLedgerMax {\n\t\treturn refuse(\"LEDGER_FILE\")\n\t}\n\tif st.Size() == 0 {\n\t\treturn nil\n\t}\n\tif false {",
			"^TestSealLedgerInterruptedUpdate$", "want LEDGER_FILE", false},
		{"ledger-update-in-place", "facade", "seal_ledger.go",
			"fd, err := openAt(l.dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)", "if t, err := openAt(l.dir, l.name, unix.O_WRONLY|unix.O_TRUNC, 0); err == nil {\n\t\tunix.Close(t)\n\t}\n\tfd, err := openAt(l.dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)",
			"^TestSealLedgerWriteFailureKeepsHistory$", "failed write step changed the committed ledger", false},
		// r5: a leftover temporary file fences every ledger read, and only
		// recover, after merging, removes a file that may hold history.
		{"ledger-no-fence-owner-witness", "facade", "seal_ledger.go",
			"if f := l.fence(); f != nil {", "if f := l.fence(); f != nil && false {",
			"^TestReviewPR8InterruptedForeignExchange$", "previous seal reusable after interrupted exchange", false},
		{"ledger-fence-lists-but-admits", "facade", "seal_ledger.go",
			"if len(names) != 0 {", "if len(names) != 0 && false {",
			"^TestSealLedgerRecoverInterruptedExchange$", "want LEDGER_FILE", false},
		{"ledger-cleanup-deletes-ledger-temp-owner-witness", "facade", "seal_ledger.go",
			"if f := l.fence(); f != nil {", "for _, n := range func() []string { n, _ := l.leftovers(); return n }() {\n\t\tunix.Unlinkat(l.dir, n, 0)\n\t}\n\tif f := l.fence(); f != nil {",
			"^TestReviewPR8InterruptedForeignExchange$", "restart cleanup destroyed the only preserved prior ledger", false},
		{"ledger-recover-drops-ledger-temp", "facade", "seal_ledger_recover.go",
			"ledgers = append(ledgers, lf.entries)", "_ = ledgers",
			"^TestSealLedgerRecoverInterruptedExchange$", "recover lost the prior history", false},
		{"ledger-recover-removes-unclassified", "facade", "seal_ledger_recover.go",
			"if lf.entries == nil && len(lf.raw) != 0 && !tornWrite(lf.raw, ledgers) {", "if lf.entries == nil && len(lf.raw) != 0 && false {",
			"^TestSealLedgerRecoverRefusals$", "want LEDGER_FILE", false},
		{"ledger-recover-ignores-conflict", "facade", "seal_ledger_recover.go",
			"if g != e.GrantID || s != seal {", "if g != e.GrantID && s != seal && false {",
			"^TestSealLedgerRecoverRefusals$", "want LEDGER_RECOVERY_CONFLICT", false},
		// r6: a torn write is only an exact prefix of the writer's own bytes.
		// The first two re-admit the ledger's bytes followed by anything;
		// the r5 heuristic admits any tail with at most one brace; the last
		// keeps the grammar but admits any byte where a part breaks off.
		{"ledger-recover-torn-any-length", "facade", "seal_ledger_recover.go",
			"tornEntry(raw[len(stem):], base, room)", "true",
			"^TestSealLedgerRecoverRefusals$", "want LEDGER_FILE", false},
		{"ledger-recover-torn-any-suffix-owner-witness", "facade", "seal_ledger_recover.go",
			"tornEntry(raw[len(stem):], base, room)", "true",
			"^TestReviewPR8RecoverRejectsImpossibleTornWrite$", "unclassifiable leftover admitted", false},
		{"ledger-recover-torn-brace-count-r5-owner-witness", "facade", "seal_ledger_recover.go",
			"tornEntry(raw[len(stem):], base, room)", `bytes.Count(raw[len(stem):], []byte("{")) <= 1`,
			"^TestReviewPR8RecoverRejectsImpossibleTornWrite$", "unclassifiable leftover admitted", false},
		{"ledger-recover-torn-any-next-byte", "facade", "seal_ledger_recover.go",
			"return n == len(tail)", "return true",
			"^TestTornEntryGrammar$", "admitted a byte the writer never writes", false},
		// r7: a torn entry is admitted only when some completion is an entry
		// a writer records. The first restores the r6 EOF acceptance of a
		// vout, keeping the duplicate check once a delimiter follows; the
		// second does the same for a hex value; the vout set rows let a
		// completion take a leading zero or pass uint32; the last drops the
		// sealLedgerMax bound on the completed document.
		{"ledger-recover-torn-vout-eof-r6-review-witness", "facade", "seal_ledger_recover.go",
			"return n == len(tail) && permittedCompletion(values, slot, base, room)", "return n == len(tail) && (part == tornVoutValue || permittedCompletion(values, slot, base, room))",
			"^TestSealLedgerRecoverTerminalVout$", "impossible terminal vout admitted", false},
		{"ledger-recover-torn-hex-eof", "facade", "seal_ledger_recover.go",
			"return n == len(tail) && permittedCompletion(values, slot, base, room)", "return n == len(tail) && (part == tornHexValue || permittedCompletion(values, slot, base, room))",
			"^TestTornEntryCompletions$", "grant id prefix with no free completion admitted", false},
		{"ledger-recover-vout-leading-zero-completion", "facade", "seal_ledger_recover.go",
			"lo = max(lo, pow10(l-1))", "lo = max(lo, 0)",
			"^TestSealLedgerRecoverTerminalVout$", "impossible terminal vout admitted", false},
		{"ledger-recover-vout-past-uint32-completion", "facade", "seal_ledger_recover.go",
			"hi = min(hi, math.MaxUint32)", "hi = min(hi, math.MaxUint32*10)",
			"^TestSealLedgerRecoverTerminalVout$", "impossible terminal vout admitted", false},
		{"ledger-recover-no-size-bound", "facade", "seal_ledger_recover.go",
			"room := sealLedgerMax - len(full) - 2*64 + 1", "room := 10",
			"^TestTornEntryCompletions$", "a prefix of a document past sealLedgerMax admitted", false},
		// r6: recover reads the union back before it removes a leftover,
		// whether or not it restored entries.
		{"ledger-recover-no-readback", "facade", "seal_ledger_recover.go",
			"if !l.verify(union) {", "if false {",
			"^TestSealLedgerRecoverReadBack$", "read-back mismatch admitted", false},
		{"ledger-recover-readback-skipped-after-restore", "facade", "seal_ledger_recover.go",
			"if !l.verify(union) {", "if restored == 0 && !l.verify(union) {",
			"^TestSealLedgerRecoverReadBack$", "read-back mismatch admitted", false},
		{"ledger-recover-readback-skipped-without-restore", "facade", "seal_ledger_recover.go",
			"if !l.verify(union) {", "if restored > 0 && !l.verify(union) {",
			"^TestSealLedgerRecoverReadBack$", "read-back mismatch admitted", false},
		{"ledger-lock-on-pathname", "facade", "seal_ledger.go",
			"if lockDir(ctx, dir) != nil", `if lockDir(ctx, func() int { fd, _ := openAt(dir, name+".lock", unix.O_RDWR|unix.O_CREAT, 0600); return fd }()) != nil`,
			"^TestSealLedgerLockSubstitution$", "both writers ran", false},
		{"ledger-no-post-exchange-inode-check", "facade", "seal_ledger.go",
			"if nameErr == nil && tmpErr == nil && sameFile(&now, mine) && sameFile(&displaced, l.held) {", "if nameErr == nil && tmpErr == nil {",
			"^TestSealLedgerForeignTempCommit$", "committed a temporary file that is not its own", false},
		{"ledger-first-record-no-inode-check", "facade", "seal_ledger.go",
			"if l.statName(l.name, &now) == nil && sameFile(&now, mine) {", "if l.statName(l.name, &now) == nil {",
			"^TestSealLedgerForeignTempCommit$", "committed a temporary file that is not its own", false},
		// The r3 commit: a plain rename over the ledger, then the inode check,
		// refusing with no way back.
		{"ledger-plain-rename-commit-owner-witness", "facade", "seal_ledger.go",
			"if exchangeAt(l.dir, tmp, l.name) != nil {",
			"if unix.Renameat(l.dir, tmp, l.dir, l.name) == nil {\n\t\treturn l.statName(l.name, &now) == nil && sameFile(&now, mine), false\n\t}\n\tif true {",
			"^TestReviewPR8ForeignTempKeepsHistory$", "refused temporary substitution replaced prior committed ledger", false},
		{"ledger-no-restore-after-foreign-commit", "facade", "seal_ledger.go",
			"if tmpErr != nil || exchangeAt(l.dir, tmp, l.name) != nil || l.statName(l.name, &now) != nil || !sameFile(&now, &displaced) {", "if true {",
			"^TestSealLedgerForeignTempCommit$", "a refused foreign commit changed the committed ledger", false},
		{"ledger-first-record-no-withdraw", "facade", "seal_ledger.go",
			"if renameNewAt(l.dir, l.name, tmp) != nil || l.statName(l.name, &now) != unix.ENOENT {", "if true {",
			"^TestSealLedgerForeignTempCommit$", "a refused first record left a ledger", false},
		{"ledger-shared-temp-name", "facade", "seal_ledger.go",
			"tmp := l.tempPrefix() + hex.EncodeToString(suffix[:])", "tmp := l.tempPrefix() + hex.EncodeToString(make([]byte, len(suffix)))",
			"^TestSealLedgerTempOwnership$", "writers did not use their own temporary files", false},
		{"ledger-entry-unchecked", "facade", "seal_ledger.go",
			"|| !validEntries(doc.Seals) {", "{",
			"^TestSealLedgerMalformedEntries$", "want LEDGER_FILE", false},
		{"ledger-entry-unchecked-owner-witness", "facade", "seal_ledger.go",
			"|| !validEntries(doc.Seals) {", "{",
			"^TestReviewPR8EmptyGrantID$", "invalid ledger grant_id must refuse LEDGER_FILE", false},
		{"ledger-lock-blocking-owner-witness", "facade", "seal_ledger.go",
			"unix.LOCK_EX|unix.LOCK_NB", "unix.LOCK_EX",
			"^TestReviewPR8LedgerLockDeadline$", "exceeded 15-second total bound", false},
		{"ledger-lock-ignores-caller-deadline", "facade", "grant.go",
			"ledger, f := openSealLedger(ctx, ledgerPath, final)", "lockCtx, lockCancel := context.WithTimeout(context.Background(), grantSignBound)\n\tdefer lockCancel()\n\tledger, f := openSealLedger(lockCtx, ledgerPath, final)",
			"^TestSealLedgerLockCallerDeadline$", "still waiting on the ledger lock after 2 s", false},
		{"ledger-lock-unbounded", "facade", "grant.go",
			"ctx, cancel := context.WithTimeout(ctx, grantSignBound)", "cancel := context.CancelFunc(func() {})",
			"^TestSealLedgerLockTotalBound$", "past the 15-second total bound", false},
		{"keychain-display-drops-nested-consent-sig", "facade", "keychain_sign.go",
			`out = append(out, path+" = "+strconv.QuoteToASCII(v))`, `if path != "consent.consent_event.sig" { out = append(out, path+" = "+strconv.QuoteToASCII(v)) }`,
			"^TestKeychainDisplayCoversEveryPreimageField$", `lacks committed field "consent.consent_event.sig = `, false},
		{"keychain-display-hides-consent-time-difference", "facade", "keychain_sign.go",
			"if it.consentAt == t {", "if true {",
			"^TestKeychainDisplayCoversEveryPreimageField$", "display does not state the consent time difference", false},
		{"keychain-display-omits-exact-bytes", "facade", "keychain_sign.go",
			"for off := 0; off < len(pre); off += 64 {", "for off := 0; off < 0; off += 64 {",
			"^TestKeychainDisplayCoversEveryPreimageField$", "display does not show the hashed bytes verbatim", false},
		{"no-key-file-mode", "testsigner", "testsigner.go",
			"st.Mode().Perm() == 0600", "true",
			"^TestSignerKeyFileCustody$", "mode 644", false},
		{"no-key-symlink-check", "testsigner", "testsigner.go",
			"if real, err := filepath.EvalSymlinks(path); err != nil || real != path {", "if real, err := filepath.EvalSymlinks(path); (err != nil || real != path) && false {",
			"^TestSignerKeyFileCustody$", "key behind a symlinked directory: <nil>", false},
		{"no-test-vector-allowlist", "testsigner", "testsigner.go",
			"if _, ok := PublishedKeys[public]; !ok {", "if _, ok := PublishedKeys[public]; !ok && false {",
			"^TestSignerKeyFileCustody$", "non-vector key", false},
	}
	baselines := map[string]string{}
	for _, pkg := range []string{"facade", "testsigner"} {
		baselines[pkg] = filepath.Join(o.scratch, pkg+"-baseline.test")
		o.goCommand(t, pkg+"-baseline-build", "test", "-mod=readonly", "-p", "1", "-c", "-o", baselines[pkg], "./internal/"+pkg)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := o.testProcess(t, baselines[tc.pkg], tc.name+"-positive", tc.test); code != 0 {
				t.Fatal("unmodified grant control failed")
			}
			path := filepath.Join(root, "internal", tc.pkg, tc.file)
			source, err := os.ReadFile(path)
			if err != nil || bytes.Count(source, []byte(tc.before)) != 1 {
				t.Fatal("grant plant setup: expected exactly one source anchor")
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
			o.goCommand(t, tc.name+"-build", "test", "-mod=readonly", "-p", "1", "-c", "-overlay", overlayPath, "-o", binary, "./internal/"+tc.pkg)
			t.Cleanup(func() { os.Remove(binary) })
			code, log := o.testProcess(t, binary, tc.name+"-negative", tc.test)
			if tc.survives {
				if code != 0 {
					t.Fatalf("expected survivor was killed: exit%d; log under %s", code, o.scratch)
				}
				t.Logf("control %s: survives as stated (backstop refuses with the same code)", tc.name)
				return
			}
			if code != 1 || !strings.Contains(log, tc.diagnostic) || !strings.Contains(log, "--- FAIL: Test") || strings.Contains(log, "panic:") {
				t.Fatalf("grant plant missed its assertion: exit%d; log under %s", code, o.scratch)
			}
			t.Logf("control %s: unmodified exit0; plant exit1 at %q", tc.name, tc.diagnostic)
		})
	}
	t.Cleanup(func() {
		for _, b := range baselines {
			os.Remove(b)
		}
	})
}
