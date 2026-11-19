package facade

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-identity/internal/keychain/keychainfake"
)

type sealLifecycleFixture struct {
	testingContext *testing.T
	harness        *kcHarness
	request        SealPlanRequest
	plan           GrantTransaction
	path           string
	node           *sealRPCFixture
}

func newSealFixture(testingContext *testing.T) *sealLifecycleFixture {
	testingContext.Helper()
	harness := newKCWithStore(testingContext, confirmWord, keychainfake.New(), bip340Secrets[keyOther])
	public, err := harness.deps.signer.Public(kcLabel)
	if err != nil {
		testingContext.Fatal(err)
	}
	funding := grantTestFunding(testingContext, "0014"+hex.EncodeToString(btcutil.Hash160(public)), 1000000)
	flow := newFlow(testingContext, "regtest", "id/landlord-a", "id/landlord-a-agent")
	script, err := rental.GrantSealScript(flow.landlord.PublicKey())
	if err != nil {
		testingContext.Fatal(err)
	}
	funds, failure := grantFunding(funding, script, nil)
	if failure != nil {
		testingContext.Fatal(failure)
	}
	plan, failure := funds.build(minGrantSealAtoms, script, "seal", funding.FeeRateSatVByte)
	if failure != nil {
		testingContext.Fatal(failure)
	}
	request := regtestRequest([]string{"instruct", "review"}, []string{}, 0)
	request.Seal = rental.Point{TxID: plan.UnsignedTxID, Vout: 0}
	flow.issue(request)
	fixture := &sealLifecycleFixture{testingContext: testingContext, harness: harness, plan: *plan, request: SealPlanRequest{
		Schema: SealPlanSchema, Network: "regtest", SignedGrantB64: flow.signed.SignedGrantB64, ContractB64: flow.signed.ContractB64,
		AmountSat: minGrantSealAtoms, Funding: funding, FundingPubkey: hex.EncodeToString(public), MaxFeeSat: 10000, MaxFeeRateSatVByte: 10, MinConfirmations: 3,
	}}
	fixture.path = filepath.Join(canonicalTemp(testingContext), flow.signed.GrantID+".seal.json")
	fixture.node = newSealRPCFixture(testingContext, fixture)
	return fixture
}

func (fixture *sealLifecycleFixture) planned() {
	fixture.testingContext.Helper()
	envelope, code := fixture.harness.run("seal", "plan", "--request", writeInput(fixture.testingContext, fixture.request), "--journal", fixture.path)
	mustOK(fixture.testingContext, envelope, code)
}

func (fixture *sealLifecycleFixture) signed() {
	fixture.testingContext.Helper()
	fixture.planned()
	envelope, code := fixture.harness.run("seal", "sign", "--journal", fixture.path, "--label", kcLabel)
	mustOK(fixture.testingContext, envelope, code)
}

func (fixture *sealLifecycleFixture) broadcast() (Envelope, int) {
	fixture.testingContext.Helper()
	envelope, code, _ := runCLI(fixture.testingContext, "seal", "broadcast", "--journal", fixture.path, "--config", fixture.node.read, "--broadcast-config", fixture.node.write, "--json")
	return envelope, code
}

func (fixture *sealLifecycleFixture) observe() (Envelope, int) {
	fixture.testingContext.Helper()
	envelope, code, _ := runCLI(fixture.testingContext, "seal", "observe", "--journal", fixture.path, "--config", fixture.node.read, "--json")
	return envelope, code
}

func (fixture *sealLifecycleFixture) journal() sealJournal {
	fixture.testingContext.Helper()
	raw, err := os.ReadFile(fixture.path)
	if err != nil {
		fixture.testingContext.Fatal(err)
	}
	var journal sealJournal
	if DecodeStrict(raw, &journal) != nil {
		fixture.testingContext.Fatal("invalid test journal")
	}
	return journal
}

type sealRPCFixture struct {
	mu          sync.Mutex
	read, write string
	mode        string
	methods     []string
	sends       int
	depth       int64
	raw         string
}

func atomJSON(amount int64) json.Number {
	return json.Number(fmt.Sprintf("%d.%08d", amount/100000000, amount%100000000))
}

func newSealRPCFixture(testingContext *testing.T, fixture *sealLifecycleFixture) *sealRPCFixture {
	testingContext.Helper()
	node := &sealRPCFixture{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		node.mu.Lock()
		defer node.mu.Unlock()
		var query struct {
			ID     int               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(request.Body).Decode(&query) != nil {
			testingContext.Error("malformed RPC")
			return
		}
		node.methods = append(node.methods, query.Method)
		user, _, ok := request.BasicAuth()
		if !ok || (query.Method == "sendrawtransaction" && user != "broadcaster") || (query.Method != "sendrawtransaction" && user != "verifier") {
			testingContext.Error("RPC authority crossed")
			writer.WriteHeader(403)
			return
		}
		var result, rpcError any
		bad := func() {
			testingContext.Errorf("unexpected %s RPC parameters", query.Method)
			rpcError = map[string]any{"code": -8, "message": "fixture refusal"}
		}
		switch query.Method {
		case "getnetworkinfo":
			result = map[string]any{"version": 280000, "connections": 1}
		case "getblockchaininfo":
			chain := "regtest"
			if node.mode == "wrong-network" {
				chain = "test"
			}
			result = map[string]any{"chain": chain, "bestblockhash": fixtureTip, "blocks": 100, "headers": 100, "initialblockdownload": false, "verificationprogress": 1}
		case "getbestblockhash":
			result = fixtureTip
		case "getblockhash":
			var height int64
			if len(query.Params) != 1 || json.Unmarshal(query.Params[0], &height) != nil {
				bad()
				break
			}
			result = pinnedGenesis("regtest")
			if height != 0 {
				result = sealB
			}
			if height != 0 && node.mode == "inactive-block" {
				result = sealA
			}
		case "gettxout":
			var txid string
			var vout uint32
			var mempool bool
			input := fixture.request.Funding.Inputs[0]
			if len(query.Params) != 3 || json.Unmarshal(query.Params[0], &txid) != nil || json.Unmarshal(query.Params[1], &vout) != nil || json.Unmarshal(query.Params[2], &mempool) != nil || txid != input.TxID || vout != input.Vout || !mempool {
				bad()
				break
			}
			if node.mode != "missing-input" {
				result = map[string]any{"bestblock": fixtureTip, "value": atomJSON(1000000), "confirmations": 1, "scriptPubKey": map[string]any{"hex": fixture.request.Funding.ScriptHex}}
			}
		case "decoderawtransaction":
			var raw string
			var witness bool
			if len(query.Params) != 2 || json.Unmarshal(query.Params[0], &raw) != nil || json.Unmarshal(query.Params[1], &witness) != nil || !witness || raw != fixture.journal().SignedTxHex {
				bad()
				break
			}
			decoded, err := hex.DecodeString(raw)
			transaction := wire.NewMsgTx(2)
			if err != nil || transaction.Deserialize(bytes.NewReader(decoded)) != nil {
				bad()
				break
			}
			var outputs []any
			for index, output := range transaction.TxOut {
				script := hex.EncodeToString(output.PkScript)
				if node.mode == "decode-mismatch" {
					script = "51"
				}
				entry := map[string]any{"n": index, "value": atomJSON(output.Value), "scriptPubKey": map[string]any{"hex": script}}
				if node.mode == "decode-missing-index" && index == 0 {
					delete(entry, "n")
				}
				outputs = append(outputs, entry)
			}
			result = map[string]any{"txid": transaction.TxHash().String(), "vout": outputs}
		case "testmempoolaccept":
			var transactions []string
			var rate json.Number
			if len(query.Params) != 2 || json.Unmarshal(query.Params[0], &transactions) != nil || len(transactions) != 1 || transactions[0] != fixture.journal().SignedTxHex || json.Unmarshal(query.Params[1], &rate) != nil || rate != "0.00010" {
				bad()
				break
			}
			decoded, err := hex.DecodeString(transactions[0])
			transaction := wire.NewMsgTx(2)
			if err != nil || transaction.Deserialize(bytes.NewReader(decoded)) != nil || len(transaction.TxIn) != 1 {
				bad()
				break
			}
			script, _ := hex.DecodeString(fixture.request.Funding.ScriptHex)
			fetcher := txscript.NewCannedPrevOutputFetcher(script, 1000000)
			hashes := txscript.NewTxSigHashes(transaction, fetcher)
			engine, err := txscript.NewEngine(script, transaction, 0, txscript.StandardVerifyFlags, nil, hashes, 1000000, fetcher)
			allowed := node.mode != "mempool-reject" && err == nil && engine.Execute() == nil
			fee := int64(1000000)
			for _, output := range transaction.TxOut {
				fee -= output.Value
				if output.Value < 0 {
					allowed = false
				}
			}
			if fee < 0 {
				allowed = false
			}
			vsize := (transaction.SerializeSizeStripped()*3 + transaction.SerializeSize() + 3) / 4
			if node.mode == "fee-mismatch" {
				fee++
			}
			result = []any{map[string]any{"txid": transaction.TxHash().String(), "allowed": allowed, "vsize": vsize, "fees": map[string]any{"base": atomJSON(fee)}}}
		case "sendrawtransaction":
			var raw string
			var rate json.Number
			if len(query.Params) != 2 || json.Unmarshal(query.Params[0], &raw) != nil || raw != fixture.journal().SignedTxHex || json.Unmarshal(query.Params[1], &rate) != nil || rate != "0.00010" {
				bad()
				break
			}
			node.sends++
			node.raw = raw
			if node.mode == "lost-response" {
				connection, _, err := writer.(http.Hijacker).Hijack()
				if err != nil {
					testingContext.Error(err)
					return
				}
				connection.Close()
				return
			}
			if node.mode == "reject-send" {
				rpcError = map[string]any{"code": -26, "message": "fixture refusal"}
			} else {
				result = fixture.plan.UnsignedTxID
			}
			if node.mode == "send-txid-mismatch" {
				result = sealA
			}
		case "getrawtransaction":
			var txid string
			var verbose bool
			if len(query.Params) != 2 || json.Unmarshal(query.Params[0], &txid) != nil || txid != fixture.plan.UnsignedTxID || json.Unmarshal(query.Params[1], &verbose) != nil || !verbose {
				bad()
				break
			}
			if node.mode == "unknown-transaction" {
				rpcError = map[string]any{"code": -5, "message": "fixture unknown"}
				break
			}
			view := map[string]any{"txid": fixture.plan.UnsignedTxID, "hex": node.raw}
			if node.depth > 0 {
				view["blockhash"], view["confirmations"] = sealB, node.depth
			}
			result = view
		case "getblockheader":
			var block string
			var verbose bool
			if len(query.Params) != 2 || json.Unmarshal(query.Params[0], &block) != nil || block != sealB || json.Unmarshal(query.Params[1], &verbose) != nil || !verbose {
				bad()
				break
			}
			result = map[string]any{"hash": sealB, "height": 101 - node.depth, "confirmations": node.depth}
		default:
			testingContext.Errorf("forbidden seal RPC method %s", query.Method)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(map[string]any{"id": query.ID, "result": result, "error": rpcError}); err != nil {
			testingContext.Error(err)
		}
	}))
	testingContext.Cleanup(server.Close)
	directory := canonicalTemp(testingContext)
	for _, role := range []string{"verifier", "broadcaster"} {
		auth := filepath.Join(directory, role+".auth")
		if err := os.WriteFile(auth, []byte(role+":fixture-only"), 0600); err != nil {
			testingContext.Fatal(err)
		}
		profile := "namecoin-core-read/1"
		if role == "broadcaster" {
			profile = "namecoin-core-broadcast/1"
		}
		config := Config{Schema: ConfigSchema, Network: "regtest", Node: NodeConfig{ID: "fixture", RPCURL: server.URL, AuthFile: auth, GenesisHash: pinnedGenesis("regtest"), RPCProfile: profile}}
		path := writeInput(testingContext, config)
		if role == "verifier" {
			node.read = path
		} else {
			node.write = path
		}
	}
	return node
}

// This exercises one v3 P2PKH seal with a distinct public-vector funding key,
// independent script execution, exact display/approval and reorg-aware depth.
// The loopback Core-shaped fixture does not establish live node policy or ACLs.
func TestSealLifecycleV3Regtest(testingContext *testing.T) {
	fixture := newSealFixture(testingContext)
	fixture.signed()
	journal := fixture.journal()
	assertGrantPlan(testingContext, journal.Plan, fixture.request.Funding, minGrantSealAtoms, fixture.plan.Outputs[0].ScriptHex, "seal")
	for _, text := range []string{sealSummary(journal.GrantID, &journal.Plan), "Output 0 (seal)", "Output 1 (change)", "regtest", "SIGHASH_ALL without ANYONECANPAY", fixture.request.FundingPubkey, fixture.plan.Outputs[0].ScriptHex, fixture.plan.Outputs[1].ScriptHex, "Type SIGN"} {
		if !strings.Contains(fixture.harness.preKey, text) {
			testingContext.Fatalf("secret read before complete display: missing %s", text)
		}
	}
	transaction := wire.NewMsgTx(2)
	raw, _ := hex.DecodeString(journal.SignedTxHex)
	if transaction.Deserialize(bytes.NewReader(raw)) != nil {
		testingContext.Fatal("signed wire encoding")
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
			testingContext.Fatal("funding signature is not a valid standard P2WPKH spend", err)
		}
	}
	envelope, code := fixture.broadcast()
	mustOK(testingContext, envelope, code)
	if got := resultAs[SealLifecycleResult](testingContext, envelope); got.State != "broadcast" || got.NeedsReconciliation || got.TxID != fixture.plan.UnsignedTxID {
		testingContext.Fatal(got)
	}
	before := len(fixture.node.methods)
	envelope, code = fixture.broadcast()
	mustOK(testingContext, envelope, code)
	if fixture.node.sends != 1 || len(fixture.node.methods) != before {
		testingContext.Fatal("idempotent broadcast contacted node")
	}
	for _, depth := range []int64{0, 1, 2, 3, 0, 4} {
		fixture.node.depth = depth
		envelope, code = fixture.observe()
		mustOK(testingContext, envelope, code)
		got := resultAs[SealLifecycleResult](testingContext, envelope)
		if got.Confirmations != depth || (got.State == "confirmed") != (depth >= 3) {
			testingContext.Fatalf("incorrect depth: %+v", got)
		}
	}
	persisted := fixture.journal()
	if persisted.validate() != nil {
		testingContext.Fatal("persisted journal invalid")
	}
	data, _ := os.ReadFile(fixture.path)
	if bytes.Contains(data, []byte("fixture-only")) || bytes.Contains(data, []byte("auth_file")) || bytes.Contains(data, []byte("rpc_url")) {
		testingContext.Fatal("journal contains RPC authority")
	}
}

// A minimal v3 contract without its own seal is valid at the v0.1.61 pin;
// changed outpoints, ownership and fee caps refuse before a signing secret read.
func TestSealPlanV3Controls(testingContext *testing.T) {
	fixture := newSealFixture(testingContext)
	contract, _ := grantBase64(fixture.request.ContractB64)
	if bytes.Contains(contract, []byte("seal")) {
		testingContext.Fatal("control is not a minimal contract")
	}
	if _, _, failure := sealPlan(fixture.request); failure != nil {
		testingContext.Fatal(failure)
	}
	cases := []struct {
		name, code string
		change     func(*SealPlanRequest)
	}{
		{"network", "NETWORK_PIN", func(request *SealPlanRequest) { request.Network = "main" }},
		{"fee", "SEAL_FEE_CAP", func(request *SealPlanRequest) { request.MaxFeeSat = 1 }},
		{"rate", "SEAL_FEE_CAP", func(request *SealPlanRequest) { request.MaxFeeRateSatVByte = 1 }},
		{"outpoint", "SEAL_GRANT_MISMATCH", func(request *SealPlanRequest) { request.AmountSat++ }},
		{"ownership", "FUNDING_NOT_OWNED", func(request *SealPlanRequest) { request.FundingPubkey = "02" + cedarKey }},
		{"depth", "BAD_INPUT", func(request *SealPlanRequest) { request.MinConfirmations = 0 }},
	}
	for _, test := range cases {
		testingContext.Run(test.name, func(testingContext *testing.T) {
			request := fixture.request
			test.change(&request)
			_, _, failure := sealPlan(request)
			if failure == nil || failure.Code != test.code {
				testingContext.Fatalf("got %+v, want %s", failure, test.code)
			}
		})
	}
	if fixture.harness.keyRead {
		testingContext.Fatal("planning read a signing secret")
	}
}

// Declined approval and wrong custody refuse without signatures or state
// advancement; the existing signer terminal is not replaced by stdin/flags.
func TestSealSignRefusals(testingContext *testing.T) {
	for _, answer := range []string{"", "sign", " SIGN", "SIGN ", "SIGN\nSIGN"} {
		testingContext.Run(fmt.Sprintf("answer-%q", answer), func(testingContext *testing.T) {
			fixture := newSealFixture(testingContext)
			fixture.planned()
			fixture.harness.term.answer = answer
			envelope, code := fixture.harness.run("seal", "sign", "--journal", fixture.path, "--label", kcLabel)
			mustRefuse(testingContext, envelope, code, "CONFIRMATION_DECLINED")
			if fixture.harness.keyRead || fixture.journal().State != "planned" {
				testingContext.Fatal("declined signing changed state")
			}
		})
	}
	fixture := newSealFixture(testingContext)
	fixture.planned()
	other := newKC(testingContext, confirmWord)
	envelope, code := other.run("seal", "sign", "--journal", fixture.path, "--label", kcLabel)
	mustRefuse(testingContext, envelope, code, "FUNDING_NOT_OWNED")
	if other.keyRead {
		testingContext.Fatal("foreign signer secret read")
	}
	envelope, code, _ = runCLI(testingContext, "seal", "sign", "--journal", fixture.path, "--label", kcLabel, "--json")
	mustRefuse(testingContext, envelope, code, "UNSUPPORTED_CAPABILITY")
}

// Each read-side failure has a valid neighbor and leaves send count zero;
// the RPC fake enforces Core parameter order, authority and money units.
func TestSealBroadcastPreflightRefusals(testingContext *testing.T) {
	cases := []struct{ mode, code string }{
		{"wrong-network", "WRONG_NETWORK"}, {"missing-input", "SEAL_FUNDING_UNAVAILABLE"},
		{"decode-mismatch", "PROVIDER_PROTOCOL"}, {"decode-missing-index", "PROVIDER_PROTOCOL"}, {"mempool-reject", "SEAL_MEMPOOL_REJECTED"}, {"fee-mismatch", "SEAL_FEE_CAP"},
	}
	for _, test := range cases {
		testingContext.Run(test.mode, func(testingContext *testing.T) {
			fixture := newSealFixture(testingContext)
			fixture.signed()
			fixture.node.mode = test.mode
			envelope, code := fixture.broadcast()
			mustRefuse(testingContext, envelope, code, test.code)
			if fixture.node.sends != 0 || fixture.journal().Attempted {
				testingContext.Fatal("preflight failure sent a transaction")
			}
			fixture.node.mode = ""
			envelope, code = fixture.broadcast()
			mustOK(testingContext, envelope, code)
			if fixture.node.sends != 1 {
				testingContext.Fatal("positive control did not broadcast")
			}
		})
	}
}

// A timeout, explicit send refusal or dishonest txid consumes the only attempt;
// subsequent invocations are local reports, never blind retries.
func TestSealBroadcastUncertainNeverRetries(testingContext *testing.T) {
	for _, mode := range []string{"lost-response", "reject-send", "send-txid-mismatch"} {
		testingContext.Run(mode, func(testingContext *testing.T) {
			fixture := newSealFixture(testingContext)
			fixture.signed()
			fixture.node.mode = mode
			envelope, code := fixture.broadcast()
			mustRefuse(testingContext, envelope, code, "SEAL_BROADCAST_UNCERTAIN")
			journal := fixture.journal()
			if !journal.Attempted || journal.State != "accepted" {
				testingContext.Fatal("attempt not durable")
			}
			before := len(fixture.node.methods)
			envelope, code = fixture.broadcast()
			mustOK(testingContext, envelope, code)
			got := resultAs[SealLifecycleResult](testingContext, envelope)
			if !got.NeedsReconciliation || got.TxID != fixture.plan.UnsignedTxID || fixture.node.sends != 1 || len(fixture.node.methods) != before {
				testingContext.Fatal("uncertain attempt retried or reported as certain")
			}
			fixture.node.mode = ""
			fixture.node.depth = 3
			envelope, code = fixture.observe()
			mustOK(testingContext, envelope, code)
			if resultAs[SealLifecycleResult](testingContext, envelope).State != "confirmed" || fixture.node.sends != 1 {
				testingContext.Fatal("read-only reconciliation failed")
			}
		})
	}
}

// Interrupted saves before the attempt allow a first send; after the send,
// save failure preserves the intent fence and prevents any second send.
func TestSealJournalInterruptedBroadcast(testingContext *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		testingContext.Run(fmt.Sprint(failAt), func(testingContext *testing.T) {
			fixture := newSealFixture(testingContext)
			fixture.signed()
			count := 0
			ledgerHook = func(step string) error {
				if step == "rename" {
					count++
					if count == failAt {
						return errors.New("bounded save failure")
					}
				}
				return nil
			}
			testingContext.Cleanup(func() { ledgerHook = nil })
			envelope, code := fixture.broadcast()
			mustRefuse(testingContext, envelope, code, "SEAL_JOURNAL_FILE")
			ledgerHook = nil
			if (fixture.node.sends == 1) != (failAt == 3) {
				testingContext.Fatal("wrong crash boundary")
			}
			envelope, code = fixture.broadcast()
			mustOK(testingContext, envelope, code)
			if fixture.node.sends != 1 {
				testingContext.Fatal("duplicate or missing first broadcast")
			}
			if resultAs[SealLifecycleResult](testingContext, envelope).NeedsReconciliation != (failAt == 3) {
				testingContext.Fatal("lost intent fence")
			}
		})
	}
}

// The directory lock serializes separate clients around the complete send;
// cancellation while waiting changes neither the journal nor the send count.
func TestSealBroadcastConcurrentAndLockDeadline(testingContext *testing.T) {
	fixture := newSealFixture(testingContext)
	fixture.signed()
	journal, failure := openSealJournal(context.Background(), fixture.path, nil)
	if failure != nil {
		testingContext.Fatal(failure)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, failure := openSealJournal(ctx, fixture.path, nil); failure == nil || failure.Code != "SEAL_JOURNAL_FILE" {
		testingContext.Fatalf("lock did not honor deadline: %+v", failure)
	}
	journal.guard.close()
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			envelope, code := fixture.broadcast()
			if code != 0 || !envelope.OK {
				testingContext.Errorf("concurrent broadcast refused: %+v", envelope.Error)
			}
		}()
	}
	wait.Wait()
	if fixture.node.sends != 1 {
		testingContext.Fatal("concurrent sends", fixture.node.sends)
	}
}

// Edited output scripts, signed outputs, broad permissions and symlinks cannot
// turn an existing journal into a signing/broadcast authority.
func TestSealJournalTamperRefusals(testingContext *testing.T) {
	for _, mode := range []string{"plan-script", "signed-output", "mode", "symlink", "partial-temp"} {
		testingContext.Run(mode, func(testingContext *testing.T) {
			fixture := newSealFixture(testingContext)
			fixture.signed()
			journal := fixture.journal()
			want := "SEAL_JOURNAL_FILE"
			switch mode {
			case "plan-script":
				journal.Plan.Outputs[0].ScriptHex = "51"
				want = "SEAL_JOURNAL_INVALID"
			case "signed-output":
				raw, _ := hex.DecodeString(journal.SignedTxHex)
				transaction := wire.NewMsgTx(2)
				transaction.Deserialize(bytes.NewReader(raw))
				transaction.TxOut[0].PkScript = []byte{txscript.OP_TRUE}
				var encoded bytes.Buffer
				transaction.Serialize(&encoded)
				journal.SignedTxHex = hex.EncodeToString(encoded.Bytes())
				want = "SEAL_SIGNED_TRANSACTION"
			case "mode":
				if err := os.Chmod(fixture.path, 0644); err != nil {
					testingContext.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(fixture.path, fixture.path+".old"); err != nil {
					testingContext.Fatal(err)
				}
				if err := os.Symlink(fixture.path+".old", fixture.path); err != nil {
					testingContext.Fatal(err)
				}
			case "partial-temp":
				if err := os.WriteFile(filepath.Join(filepath.Dir(fixture.path), "."+filepath.Base(fixture.path)+".tmp-0000000000000000"), []byte("partial"), 0600); err != nil {
					testingContext.Fatal(err)
				}
				want = "SEAL_JOURNAL_RECOVERY_REQUIRED"
			}
			if mode == "plan-script" || mode == "signed-output" {
				raw, _ := compactJSON(journal)
				if err := os.WriteFile(fixture.path, raw, 0600); err != nil {
					testingContext.Fatal(err)
				}
			}
			envelope, code := fixture.broadcast()
			mustRefuse(testingContext, envelope, code, want)
			if fixture.node.sends != 0 {
				testingContext.Fatal("tampered journal broadcast")
			}
		})
	}
}

// The production confirmation parser accepts a complete SIGN line (LF/CRLF),
// not an EOF fragment, padded text, extra carriage returns or a truncated line.
func TestSealExactTerminalLine(testingContext *testing.T) {
	for _, test := range []struct {
		line   string
		accept bool
	}{
		{"SIGN\n", true}, {"SIGN\r\n", true}, {"SIGN", false},
		{"sign\n", false}, {" SIGN\n", false}, {"SIGN \n", false},
		{"SIGN\r\r\n", false}, {"SIGN\x00\n", false},
		{"SIGN" + strings.Repeat(" ", 80) + "\n", false},
	} {
		testingContext.Run(fmt.Sprintf("%q", test.line), func(testingContext *testing.T) {
			path := filepath.Join(canonicalTemp(testingContext), "terminal")
			if err := os.WriteFile(path, []byte(test.line), 0600); err != nil {
				testingContext.Fatal(err)
			}
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				testingContext.Fatal(err)
			}
			defer file.Close()
			terminal := &ttyTerminal{f: file}
			accept, _ := terminal.Confirm("")
			if accept != test.accept {
				testingContext.Fatalf("accept=%t, want %t", accept, test.accept)
			}
		})
	}
}

// Cancellation after the durable intent but before dispatch can produce zero
// sends; a later call still must not turn that uncertain attempt into a send.
func TestSealCanceledAfterIntentNeverSends(testingContext *testing.T) {
	fixture := newSealFixture(testingContext)
	fixture.signed()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	journal, failure := openSealJournal(ctx, fixture.path, nil)
	if failure != nil {
		testingContext.Fatal(failure)
	}
	count := 0
	ledgerHook = func(step string) error {
		if step == "rename" {
			count++
			if count == 2 {
				cancel()
			}
		}
		return nil
	}
	testingContext.Cleanup(func() { ledgerHook = nil })
	failure = journal.broadcast(ctx, fixture.node.read, fixture.node.write)
	journal.guard.close()
	ledgerHook = nil
	if failure == nil || failure.Code != "SEAL_BROADCAST_UNCERTAIN" || !fixture.journal().Attempted || fixture.node.sends != 0 {
		testingContext.Fatalf("incorrect canceled send: %+v", failure)
	}
	envelope, code := fixture.broadcast()
	mustOK(testingContext, envelope, code)
	if !resultAs[SealLifecycleResult](testingContext, envelope).NeedsReconciliation || fixture.node.sends != 0 {
		testingContext.Fatal("canceled attempt was retried")
	}
}

// Ordinary read clients and seal reads still refuse write/wallet methods;
// missing or reused broadcast authority leaves the first attempt unconsumed.
func TestSealRPCAuthorityFences(testingContext *testing.T) {
	fixture := newSealFixture(testingContext)
	fixture.signed()
	journal, failure := openSealJournal(context.Background(), fixture.path, nil)
	if failure != nil {
		testingContext.Fatal(failure)
	}
	defer journal.guard.close()
	reader, failure := journal.reader(fixture.node.read)
	if failure != nil {
		testingContext.Fatal(failure)
	}
	defer reader.Close()
	for _, method := range []string{"sendrawtransaction", "walletprocesspsbt", "getnewaddress"} {
		if _, failure := reader.call(context.Background(), method, nil); failure == nil || failure.Code != "UNSUPPORTED_CAPABILITY" {
			testingContext.Fatalf("ordinary fence admits %s: %+v", method, failure)
		}
		if _, failure := sealRead(context.Background(), reader, method, nil); failure == nil || failure.Code != "UNSUPPORTED_CAPABILITY" {
			testingContext.Fatalf("seal fence admits %s: %+v", method, failure)
		}
	}
	if failure := journal.broadcast(context.Background(), fixture.node.read, fixture.node.read); failure == nil || failure.Code != "SEAL_BROADCAST_CONFIG" {
		testingContext.Fatalf("read-only config became write authority: %+v", failure)
	}
	if fixture.node.sends != 0 || journal.Attempted {
		testingContext.Fatal("authority refusal consumed an attempt")
	}
}

// Active-chain membership, unknown transactions and floor comparisons cannot
// be replaced by a claimed confirmation counter or an absence assumption.
func TestSealObservationRefusalsAndInactiveBlock(testingContext *testing.T) {
	fixture := newSealFixture(testingContext)
	fixture.signed()
	envelope, code := fixture.broadcast()
	mustOK(testingContext, envelope, code)
	fixture.node.mode, fixture.node.depth = "unknown-transaction", 3
	envelope, code = fixture.observe()
	mustRefuse(testingContext, envelope, code, "RPC_REFUSED")
	if fixture.journal().State != "broadcast" || fixture.node.sends != 1 {
		testingContext.Fatal("unavailable read altered delivery")
	}
	fixture.node.mode = "inactive-block"
	envelope, code = fixture.observe()
	mustOK(testingContext, envelope, code)
	if resultAs[SealLifecycleResult](testingContext, envelope).State != "broadcast" || resultAs[SealLifecycleResult](testingContext, envelope).Confirmations != 0 {
		testingContext.Fatal("inactive block counted toward depth")
	}
	fixture.node.mode = ""
	envelope, code = fixture.observe()
	mustOK(testingContext, envelope, code)
	if resultAs[SealLifecycleResult](testingContext, envelope).State != "confirmed" || fixture.node.sends != 1 {
		testingContext.Fatal("active positive control failed")
	}
}
