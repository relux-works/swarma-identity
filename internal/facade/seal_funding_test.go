package facade

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

func sealTwoFundingInputs(testingContext *testing.T, original GrantFunding, foreign bool) GrantFunding {
	testingContext.Helper()
	raw, _ := hex.DecodeString(original.Inputs[0].PrevTxHex)
	parent := wire.NewMsgTx(2)
	if parent.Deserialize(bytes.NewReader(raw)) != nil {
		testingContext.Fatal("funding fixture encoding")
	}
	script := append([]byte{}, parent.TxOut[0].PkScript...)
	if foreign {
		script[len(script)-1] ^= 1
	}
	parent.AddTxOut(wire.NewTxOut(1000000, script))
	parentHex := transactionHex(testingContext, parent)
	copy := original
	copy.Inputs = []GrantFundingInput{{TxID: parent.TxHash().String(), Vout: 0, PrevTxHex: parentHex}, {TxID: parent.TxHash().String(), Vout: 1, PrevTxHex: parentHex}}
	return copy
}

func rebindSealFunding(testingContext *testing.T, fixture *sealLifecycleFixture, funding GrantFunding) {
	testingContext.Helper()
	raw, _ := grantBase64(fixture.request.SignedGrantB64)
	signed, err := rental.ParseSignedGrant(raw)
	if err != nil {
		testingContext.Fatal(err)
	}
	script, err := rental.GrantSealScript(signed.Grant.IssuerKey)
	if err != nil {
		testingContext.Fatal(err)
	}
	funds, failure := grantFunding(funding, script, nil)
	if failure != nil {
		testingContext.Fatal(failure)
	}
	plan, failure := funds.build(fixture.request.AmountSat, script, "seal", funding.FeeRateSatVByte)
	if failure != nil {
		testingContext.Fatal(failure)
	}
	flow := newFlow(testingContext, "regtest", "id/landlord-a", "id/landlord-a-agent")
	request := regtestRequest([]string{"instruct", "review"}, []string{}, 0)
	request.Seal = rental.Point{TxID: plan.UnsignedTxID, Vout: 0}
	flow.issue(request)
	fixture.request.Funding, fixture.request.SignedGrantB64, fixture.request.ContractB64 = funding, flow.signed.SignedGrantB64, flow.signed.ContractB64
	fixture.plan = *plan
	fixture.path = filepath.Join(canonicalTemp(testingContext), flow.signed.GrantID+".seal.json")
}

// Two same-key funding inputs produce two authenticated, independently
// executable SIGHASH_ALL witnesses; a foreign second input is not overlooked.
func TestSealMultipleFundingInputs(testingContext *testing.T) {
	fixture := newSealFixture(testingContext)
	foreign := fixture.request
	foreign.Funding = sealTwoFundingInputs(testingContext, fixture.request.Funding, true)
	if _, _, failure := sealPlan(foreign); failure == nil || failure.Code != "FUNDING_SCRIPT_MISMATCH" {
		testingContext.Fatalf("foreign second input admitted: %+v", failure)
	}
	if fixture.harness.keyRead {
		testingContext.Fatal("foreign funding read a secret")
	}
	rebindSealFunding(testingContext, fixture, sealTwoFundingInputs(testingContext, fixture.request.Funding, false))
	fixture.signed()
	journal := fixture.journal()
	raw, _ := hex.DecodeString(journal.SignedTxHex)
	transaction := wire.NewMsgTx(2)
	if transaction.Deserialize(bytes.NewReader(raw)) != nil {
		testingContext.Fatal("signed encoding")
	}
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for index, input := range transaction.TxIn {
		output, _ := prevTxOutput(fixture.request.Funding.Inputs[index].PrevTxHex, input.PreviousOutPoint)
		fetcher.AddPrevOut(input.PreviousOutPoint, output)
	}
	hashes := txscript.NewTxSigHashes(transaction, fetcher)
	for index, input := range transaction.TxIn {
		output := fetcher.FetchPrevOutput(input.PreviousOutPoint)
		engine, err := txscript.NewEngine(output.PkScript, transaction, index, txscript.StandardVerifyFlags, nil, hashes, output.Value, fetcher)
		if err != nil || engine.Execute() != nil {
			testingContext.Fatal("invalid funding witness", err)
		}
	}
	count := 0
	for _, event := range fixture.harness.store.Events {
		if strings.HasPrefix(event, "secret:") {
			count++
		}
	}
	if count != 2 || !strings.Contains(fixture.harness.preKey, "Input 1:") {
		testingContext.Fatal("per-input authentication or display missing")
	}
}

// A failure on the second authentication releases no partial signature
// result and preserves the exact planned journal, beside a valid retry.
func TestSealPartialSigningKeepsPlannedJournal(testingContext *testing.T) {
	fixture := newSealFixture(testingContext)
	rebindSealFunding(testingContext, fixture, sealTwoFundingInputs(testingContext, fixture.request.Funding, false))
	fixture.planned()
	before, err := os.ReadFile(fixture.path)
	if err != nil {
		testingContext.Fatal(err)
	}
	original := fixture.harness.store.OnEvent
	count := 0
	fixture.harness.store.OnEvent = func(event string) {
		original(event)
		if strings.HasPrefix(event, "secret:") {
			count++
			if count == 2 {
				fixture.harness.store.SecretErr = errors.New("fixture authentication refusal")
			}
		}
	}
	envelope, code := fixture.run("seal", "sign", "--journal", fixture.path, "--label", kcLabel)
	mustRefuse(testingContext, envelope, code, "KEYCHAIN_ERROR")
	after, err := os.ReadFile(fixture.path)
	if err != nil || !bytes.Equal(before, after) || fixture.journal().SignedTxHex != "" {
		testingContext.Fatal("partial signing changed journal")
	}
	fixture.harness.store.OnEvent, fixture.harness.store.SecretErr = original, nil
	envelope, code = fixture.run("seal", "sign", "--journal", fixture.path, "--label", kcLabel)
	mustOK(testingContext, envelope, code)
	if fixture.journal().State != "signed" {
		testingContext.Fatal("valid signing retry did not advance")
	}
}

// Native ACL inspection being unavailable is shown as a limitation before
// any secret read, rather than claiming the metadata proves native flags.
func TestSealSignerPolicyDisplay(testingContext *testing.T) {
	fixture := newSealFixture(testingContext)
	fixture.harness.store.HideAccessInspection = true
	fixture.signed()
	for _, text := range []string{"Native ACL flags: unavailable", "policy metadata", "Touch ID separately", "Operator confirmation floor: 3"} {
		if !strings.Contains(fixture.harness.preKey, text) {
			testingContext.Fatalf("missing pre-sign policy display %q", text)
		}
	}
}

// Replanning cannot alter pinned policy or downgrade signed state; idempotent
// signing returns the existing record without another authentication.
func TestSealPlanAndSignIdempotent(testingContext *testing.T) {
	fixture := newSealFixture(testingContext)
	fixture.signed()
	before, err := os.ReadFile(fixture.path)
	if err != nil {
		testingContext.Fatal(err)
	}
	changed := fixture.request
	changed.MinConfirmations++
	envelope, code := fixture.run("seal", "plan", "--request", writeInput(testingContext, changed), "--journal", fixture.path)
	mustRefuse(testingContext, envelope, code, "SEAL_JOURNAL_CONFLICT")
	fixture.planned()
	secrets := len(fixture.harness.store.Reasons)
	envelope, code = fixture.run("seal", "sign", "--journal", fixture.path, "--label", kcLabel)
	mustOK(testingContext, envelope, code)
	after, err := os.ReadFile(fixture.path)
	if err != nil || !bytes.Equal(before, after) || len(fixture.harness.store.Reasons) != secrets || fixture.journal().State != "signed" {
		testingContext.Fatal("repeated plan/sign altered the signed record")
	}
}
