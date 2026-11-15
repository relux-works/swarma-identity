package facade

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// grantTxNode extends the existing grantNode RPC fake, forwarding its existing
// identity/health methods and modeling gettxout per nc28.0 blockchain.cpp.
// An absent or chain-spent coin is null; a mempool spend is null only when
// include_mempool is true. No fake response asserts live-node qualification.
type grantTxNode struct {
	mu       sync.Mutex
	config   string
	point    rental.Point
	script   string
	amount   int64
	mode     string
	methods  []string
	seenSeal bool
	server   *httptest.Server
}

func newGrantTxNode(t *testing.T, base *grantNode, key string) *grantTxNode {
	t.Helper()
	var config Config
	if f := inputFile(base.config, &config); f != nil {
		t.Fatal(f.Code)
	}
	endpoint := config.Node.RPCURL
	script, err := rental.GrantSealScript(key)
	if err != nil {
		t.Fatal(err)
	}
	n := &grantTxNode{point: rental.Point{TxID: sealA, Vout: 1}, script: script, amount: 100000}
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	n.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		defer n.mu.Unlock()
		raw, err := io.ReadAll(r.Body)
		var q struct {
			ID     int               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err != nil || json.Unmarshal(raw, &q) != nil {
			t.Error("invalid extended fixture request")
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		n.methods = append(n.methods, q.Method)
		reply := func(value, rpcError any) {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]any{"id": q.ID, "result": value, "error": rpcError}); err != nil {
				t.Error(err)
			}
		}
		if q.Method == "gettxout" {
			n.seenSeal = true
			var point rental.Point
			var mempool bool
			if len(q.Params) != 3 || json.Unmarshal(q.Params[0], &point.TxID) != nil || json.Unmarshal(q.Params[1], &point.Vout) != nil || json.Unmarshal(q.Params[2], &mempool) != nil || point != n.point {
				t.Error("gettxout must send [exact txid, numeric vout, boolean include_mempool]")
				reply(nil, map[string]any{"code": -8, "message": "invalid fixture args"})
				return
			}
			switch n.mode {
			case "missing", "spent":
				reply(nil, nil)
				return
			case "mempool-spent":
				if mempool {
					reply(nil, nil)
					return
				}
			case "rpc-refused":
				reply(nil, map[string]any{"code": -1, "message": "fixture-password"})
				return
			case "rpc-unsupported":
				reply(nil, map[string]any{"code": -32601, "message": "unknown method"})
				return
			}
			pk := map[string]any{"hex": n.script, "type": "pubkeyhash"}
			value := map[string]any{"bestblock": fixtureTip, "confirmations": 1, "value": json.Number("0.00100000"), "scriptPubKey": pk, "coinbase": false}
			if n.amount != 100000 {
				// Tests keep exact money lexemes; no float conversion is used.
				value["value"] = json.Number("0.00000001")
			}
			switch n.mode {
			case "unconfirmed":
				value["confirmations"] = 0
			case "wrong-type":
				pk["type"], pk["hex"] = "witness_v0_keyhash", "0014"+strings.Repeat("11", 20)
			case "lying-type":
				pk["hex"] = "0014" + strings.Repeat("11", 20)
			case "wrong-key":
				pk["hex"] = "76a914" + strings.Repeat("11", 20) + "88ac"
			case "wrong-parity":
				pub, _ := hex.DecodeString("03" + key)
				pk["hex"] = hex.EncodeToString(p2pkhScript(pub))
			case "malformed":
				pk["hex"] = "zz"
			case "bad-amount":
				value["value"] = json.Number("0.000000001")
			case "null-confirmations":
				value["confirmations"] = nil
			case "negative-confirmations":
				value["confirmations"] = -1
			case "future-confirmations":
				value["confirmations"] = 102
			case "missing-coinbase":
				delete(value, "coinbase")
			case "bestblock-changed":
				value["bestblock"] = strings.Repeat("2", 64)
			}
			reply(value, nil)
			return
		}
		if q.Method == "getnetworkinfo" && n.mode == "wrong-backend" {
			reply(map[string]any{"version": 280001, "connections": 10}, nil)
			return
		}
		if q.Method == "getbestblockhash" && n.seenSeal && n.mode == "tip-after-seal" {
			reply(strings.Repeat("2", 64), nil)
			return
		}
		// All other methods use the existing fake and its RPC allowlist.
		forward, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewReader(raw))
		if err != nil {
			t.Error(err)
			return
		}
		forward.Header = r.Header.Clone()
		response, err := transport.RoundTrip(forward)
		if err != nil {
			t.Error(err)
			return
		}
		defer response.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		if _, err := io.Copy(w, response.Body); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(n.server.Close)
	config.Node.RPCURL = n.server.URL
	n.config = writeInput(t, config)
	return n
}

func (n *grantTxNode) reset(mode string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.mode, n.methods, n.seenSeal = mode, nil, false
}

func (n *grantTxNode) trace() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string{}, n.methods...)
}

func transactionHex(t *testing.T, tx *wire.MsgTx) string {
	t.Helper()
	var b bytes.Buffer
	if err := tx.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b.Bytes())
}

func grantTestFunding(t *testing.T, script string, amount int64) GrantFunding {
	t.Helper()
	if script == "" {
		r := validDerivation(t)
		r.Count = 1
		rows, f := Derive(r)
		if f != nil {
			t.Fatal(f.Code)
		}
		script = rows[0].scriptHex
	}
	pk, _ := hex.DecodeString(script)
	parent := wire.NewMsgTx(2)
	parent.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 1}, []byte{0x51}, nil))
	parent.AddTxOut(wire.NewTxOut(amount, pk))
	return GrantFunding{ScriptHex: script, Inputs: []GrantFundingInput{{TxID: parent.TxHash().String(), Vout: 0, PrevTxHex: transactionHex(t, parent)}}, FeeRateSatVByte: 2}
}

func anchorFlow(t *testing.T) (*flow, *grantTxNode, GrantAnchorRequest) {
	t.Helper()
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	f.issue(regtestRequest([]string{"instruct", "review"}, []string{}, 0))
	n := newGrantTxNode(t, f.node, f.landlord.PublicKey())
	r := GrantAnchorRequest{Schema: GrantAnchorSchema, SignedGrantB64: f.signed.SignedGrantB64, ContractB64: f.signed.ContractB64, Funding: grantTestFunding(t, "", 1000000)}
	return f, n, r
}

func anchorCmd(t *testing.T, n *grantTxNode, r GrantAnchorRequest) (Envelope, int) {
	t.Helper()
	e, code, _ := runCLI(t, "grant", "anchor", "--config", n.config, "--request", writeInput(t, r), "--json")
	return e, code
}

func sealCmd(t *testing.T, n *grantTxNode, r GrantSealRequest) (Envelope, int) {
	t.Helper()
	e, code, _ := runCLI(t, "grant", "seal", "--config", n.config, "--request", writeInput(t, r), "--json")
	return e, code
}

func assertGrantPlan(t *testing.T, plan GrantTransaction, funding GrantFunding, firstAmount int64, firstScript, role string) *wire.MsgTx {
	t.Helper()
	raw, err := hex.DecodeString(plan.UnsignedTxHex)
	if err != nil {
		t.Fatal(err)
	}
	var tx wire.MsgTx
	if tx.Deserialize(bytes.NewReader(raw)) != nil || tx.Version != 2 || tx.LockTime != 0 || tx.TxHash().String() != plan.UnsignedTxID || len(tx.TxIn) != len(funding.Inputs) || len(tx.TxOut) != 2 {
		t.Fatal("wrong transaction shape")
	}
	packetRaw, err := base64.StdEncoding.DecodeString(plan.PSBTB64)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := psbt.NewFromRawBytes(bytes.NewReader(packetRaw), false)
	if err != nil || transactionHex(t, packet.UnsignedTx) != plan.UnsignedTxHex {
		t.Fatal("PSBT unsigned transaction differs")
	}
	total := int64(0)
	for i, input := range tx.TxIn {
		want := funding.Inputs[i]
		if input.PreviousOutPoint.Hash.String() != want.TxID || input.PreviousOutPoint.Index != want.Vout || len(input.SignatureScript) != 0 || len(input.Witness) != 0 || input.Sequence != 0xfffffffe {
			t.Fatal("input changed or signed")
		}
		p := packet.Inputs[i]
		if p.NonWitnessUtxo == nil || p.NonWitnessUtxo.TxHash() != input.PreviousOutPoint.Hash || transactionHex(t, p.NonWitnessUtxo) != want.PrevTxHex || p.WitnessUtxo == nil || p.SighashType != txscript.SigHashAll || len(p.PartialSigs) != 0 || p.FinalScriptSig != nil || p.FinalScriptWitness != nil {
			t.Fatal("missing parent, wrong sighash, or signed PSBT")
		}
		prev := p.NonWitnessUtxo.TxOut[want.Vout]
		if p.WitnessUtxo.Value != prev.Value || !bytes.Equal(p.WitnessUtxo.PkScript, prev.PkScript) || hex.EncodeToString(prev.PkScript) != funding.ScriptHex {
			t.Fatal("PSBT prevout mismatch")
		}
		total += prev.Value
	}
	first, change := tx.TxOut[0], tx.TxOut[1]
	if first.Value != firstAmount || hex.EncodeToString(first.PkScript) != firstScript || change.Value < 1000 || hex.EncodeToString(change.PkScript) != funding.ScriptHex || total != first.Value+change.Value+plan.FeeSat || plan.FeeRateSatVByte != funding.FeeRateSatVByte {
		t.Fatal("wrong outputs, change pin or amount conservation")
	}
	// Model maximum witness lengths independently on a copy of the wire tx.
	sized := tx.Copy()
	for _, in := range sized.TxIn {
		in.Witness = wire.TxWitness{make([]byte, 72), make([]byte, 33)}
	}
	weight := sized.SerializeSizeStripped()*3 + sized.SerializeSize()
	if plan.MaxSignedVBytes != (weight+3)/4 || plan.FeeSat != int64(plan.MaxSignedVBytes)*funding.FeeRateSatVByte {
		t.Fatal("fee projection does not include the full signed witness and frame")
	}
	if !reflect.DeepEqual(plan.Outputs, []GrantTxOutput{{0, firstAmount, firstScript, role}, {1, change.Value, funding.ScriptHex, "change"}}) || plan.RequiredReview == "" {
		t.Fatal("public plan differs from actual transaction")
	}
	return &tx
}

// Claim: both pinned networks build an even-y P2PKH seal and a separate framed
// issuance through the CLI, without signing, spending the seal, or changing the ledger.
func TestGrantTransactionsEndToEnd(t *testing.T) {
	for _, network := range []string{"regtest", "main"} {
		t.Run(network, func(t *testing.T) {
			f := newFlow(t, network, "id/landlord-a", "id/landlord-a-agent")
			n := newGrantTxNode(t, f.node, f.landlord.PublicKey())
			sealReq := GrantSealRequest{GrantSealSchema, network, "id/landlord-a", f.landlord.PublicKey(), 100000, grantTestFunding(t, "", 1000000)}
			e, code := sealCmd(t, n, sealReq)
			mustOK(t, e, code)
			seal := resultAs[GrantSealResult](t, e)
			// The literal key prefix enforces even-y independently of GrantSealScript.
			pub, _ := hex.DecodeString("02" + f.landlord.PublicKey())
			script := hex.EncodeToString(p2pkhScript(pub))
			assertGrantPlan(t, seal.Transaction, sealReq.Funding, 100000, script, "seal")
			if !seal.DryRun || seal.Seal != (rental.Point{TxID: seal.Transaction.UnsignedTxID, Vout: 0}) || seal.IssuerKey != f.landlord.PublicKey() || seal.ObservedTip != (Tip{fixtureTip, 100}) {
				t.Fatal("seal result does not bind the unsigned outpoint/key/tip")
			}
			r := regtestRequest([]string{"instruct", "review"}, []string{}, 0)
			r.Network, r.Seal = network, seal.Seal
			f.issue(r)
			before, err := os.ReadFile(f.ledger)
			if err != nil {
				t.Fatal(err)
			}
			n.mu.Lock()
			n.point = seal.Seal
			n.mu.Unlock()
			n.reset("")
			anchorReq := GrantAnchorRequest{Schema: GrantAnchorSchema, SignedGrantB64: f.signed.SignedGrantB64, ContractB64: f.signed.ContractB64, Funding: grantTestFunding(t, "", 500000)}
			e, code = anchorCmd(t, n, anchorReq)
			mustOK(t, e, code)
			anchor := resultAs[GrantAnchorResult](t, e)
			signedRaw, _ := base64.StdEncoding.DecodeString(f.signed.SignedGrantB64)
			commit := independentCommitment(t, signedRaw, *f.signed.SignedGrant)
			frame := "6a03534c014201" + commit + "01" + sha256Hex(signedRaw)
			tx := assertGrantPlan(t, anchor.Transaction, anchorReq.Funding, 0, frame, "issuance-commitment")
			if !anchor.DryRun || anchor.GrantID != sha256Hex(signedRaw) || anchor.Commitment != commit || anchor.FrameHex != frame || len(tx.TxOut[0].PkScript) != 72 || anchor.Seal.Point != seal.Seal || anchor.Seal.Confirmations != 1 || !anchor.Seal.IncludeMempool || anchor.Seal.ScriptHex != script || anchor.ObservedTip != seal.ObservedTip {
				t.Fatal("anchor does not bind the exact grant, seal and observation")
			}
			want := []string{"getnetworkinfo", "getblockchaininfo", "getblockhash", "name_show", "name_show", "getbestblockhash", "gettxout", "getbestblockhash"}
			if !reflect.DeepEqual(n.trace(), want) {
				t.Fatalf("unexpected anchor RPCs: %v", n.trace())
			}
			after, err := os.ReadFile(f.ledger)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("anchor altered the seal ledger")
			}
		})
	}
}

// Claim: each seal pre-check refusal emits no transaction, paired with a valid
// one-confirmation neighbour; null/spent include mempool, and bytes beat RPC type labels.
func TestGrantAnchorSealPrechecks(t *testing.T) {
	_, n, r := anchorFlow(t)
	for _, tc := range []struct{ mode, code string }{
		{"missing", "SEAL_MISSING_OR_SPENT"}, {"spent", "SEAL_MISSING_OR_SPENT"}, {"mempool-spent", "SEAL_MISSING_OR_SPENT"},
		{"unconfirmed", "SEAL_UNCONFIRMED"}, {"wrong-type", "SEAL_SCRIPT_TYPE"}, {"lying-type", "SEAL_SCRIPT_TYPE"},
		{"wrong-key", "SEAL_KEY_MISMATCH"}, {"wrong-parity", "SEAL_KEY_MISMATCH"}, {"malformed", "PROVIDER_PROTOCOL"},
		{"bad-amount", "PROVIDER_PROTOCOL"}, {"null-confirmations", "PROVIDER_PROTOCOL"}, {"negative-confirmations", "PROVIDER_PROTOCOL"},
		{"future-confirmations", "PROVIDER_PROTOCOL"}, {"missing-coinbase", "PROVIDER_PROTOCOL"},
		{"bestblock-changed", "SNAPSHOT_CHANGED"}, {"tip-after-seal", "SNAPSHOT_CHANGED"},
		{"rpc-refused", "RPC_REFUSED"}, {"rpc-unsupported", "UNSUPPORTED_CAPABILITY"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			n.reset("")
			e, code := anchorCmd(t, n, r)
			mustOK(t, e, code)
			n.reset(tc.mode)
			e, code = anchorCmd(t, n, r)
			mustRefuse(t, e, code, tc.code)
			if !strings.Contains(strings.Join(n.trace(), ","), "gettxout") {
				t.Fatal("seal negative did not reach gettxout")
			}
			wantExit := 3
			if tc.code == "PROVIDER_PROTOCOL" {
				wantExit = 5
			} else if tc.code == "SNAPSHOT_CHANGED" {
				wantExit = 4
			}
			if code != wantExit || e.Error.Retryable != (wantExit == 4) {
				t.Fatal("unexpected pre-check exit/retry semantics")
			}
		})
	}
}

// Claim: a frozen signed-grant vector produces exact LIP-0005 bytes; forbidden
// versions, locators, encodings and oversized candidates refuse before any RPC.
func TestGrantAnchorFrameGoldenAndRefusals(t *testing.T) {
	f, n, r := anchorFlow(t)
	e, code := anchorCmd(t, n, r)
	mustOK(t, e, code)
	valid := resultAs[GrantAnchorResult](t, e).FrameHex
	// Frozen frame from the deterministic public BIP-340/LIP-0013 fixture;
	// retain an independent commitment/id calculation as a second oracle.
	const golden = "6a03534c014201bf052f87937313efecdae89338b77312ae1e1f27c315c09334602a9a18fb91ae01e80c0f76d7aa4e4d9f97a751d976fd21efec49a120e090361ed533845db541e3"
	raw, _ := base64.StdEncoding.DecodeString(f.signed.SignedGrantB64)
	want := "6a03534c014201" + independentCommitment(t, raw, *f.signed.SignedGrant) + "01" + sha256Hex(raw)
	if valid != golden || valid != want || len(valid) != 144 {
		t.Fatalf("frame golden differs: %s", valid)
	}
	for _, tc := range []struct{ name, frame, code string }{
		{"oversize", valid + strings.Repeat("00", 12), "ANCHOR_FRAME_SIZE"},
		{"version", valid[:12] + "02" + valid[14:], "ANCHOR_FRAME_VERSION"},
		{"torrent", valid[:78] + "02" + valid[80:], "ANCHOR_FRAME_LOCATOR"},
		{"wrong-pointer", valid[:80] + strings.Repeat("22", 32), "ANCHOR_FRAME_LOCATOR"},
		{"batch", valid[:8] + "02" + valid[10:], "ANCHOR_FRAME_ACTION"},
		{"commitment", valid[:14] + strings.Repeat("33", 32) + valid[78:], "ANCHOR_FRAME_COMMITMENT"},
		{"bare", "6a20" + valid[14:78], "ANCHOR_FRAME"},
		{"pushdata", valid[:10] + "4c42" + valid[12:], "ANCHOR_FRAME"},
		{"trailing", valid + "00", "ANCHOR_FRAME"},
		{"uppercase", strings.ToUpper(valid), "ANCHOR_FRAME"},
		{"not-hex", "zz", "ANCHOR_FRAME"},
		{"unknown-locator", valid[:78] + "80" + valid[80:], "ANCHOR_FRAME"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			control := r
			control.FrameHex = valid
			n.reset("")
			e, code := anchorCmd(t, n, control)
			mustOK(t, e, code)
			control.FrameHex = tc.frame
			n.reset("")
			e, code = anchorCmd(t, n, control)
			mustRefuse(t, e, code, tc.code)
			if len(n.trace()) != 0 {
				t.Fatal("invalid frame contacted the node")
			}
		})
	}
}

// Claim: both transaction commands retain the exact Core 280000 pin and current
// issuer-key pin; adjacent valid requests work and refused plans return no result.
func TestGrantTransactionBackendAndIssuerPins(t *testing.T) {
	f, n, anchor := anchorFlow(t)
	seal := GrantSealRequest{GrantSealSchema, "regtest", "id/landlord-a", f.landlord.PublicKey(), 100000, grantTestFunding(t, "", 1000000)}
	for _, command := range []string{"seal", "anchor"} {
		t.Run(command, func(t *testing.T) {
			run := func() (Envelope, int) {
				if command == "seal" {
					return sealCmd(t, n, seal)
				}
				return anchorCmd(t, n, anchor)
			}
			n.reset("")
			e, code := run()
			mustOK(t, e, code)
			n.reset("wrong-backend")
			e, code = run()
			mustRefuse(t, e, code, "UNSUPPORTED_CAPABILITY")
			if !reflect.DeepEqual(n.trace(), []string{"getnetworkinfo"}) {
				t.Fatal("wrong backend reached chain/seal reads")
			}
			n.reset("")
			f.node.set("id/landlord-a", landlordValue(testsigner_public(t, keyOther)))
			e, code = run()
			mustRefuse(t, e, code, "LANDLORD_KEY_MISMATCH")
			f.node.set("id/landlord-a", landlordValue(f.landlord.PublicKey()))
			e, code = run()
			mustOK(t, e, code)
		})
	}
}

// Claim: Core's gettxout null exception is scoped to that read, and explicit
// include_mempool=true is mandatory; malformed/unsafe requests send no HTTP call.
func TestGrantGetTxOutRPCFenceAndCoreSemantics(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	n := newGrantTxNode(t, f.node, f.landlord.PublicKey())
	var config Config
	if f := inputFile(n.config, &config); f != nil {
		t.Fatal(f.Code)
	}
	c, failure := NewClient(config)
	if failure != nil {
		t.Fatal(failure.Code)
	}
	defer c.Close()
	n.reset("mempool-spent")
	raw, failure := c.call(context.Background(), "gettxout", []any{sealA, uint32(1), true})
	if failure != nil || string(raw) != "null" {
		t.Fatal("Core-style spent null did not cross the RPC envelope")
	}
	for _, params := range [][]any{{sealA, uint32(1), false}, {sealA, uint32(1)}, {sealA, "1", true}, {sealA, int64(1), true}, {"bad", uint32(1), true}, {sealA, uint32(1), true, true}} {
		if _, f := c.call(context.Background(), "gettxout", params); f == nil || f.Code != "UNSUPPORTED_CAPABILITY" {
			t.Fatal("gettxout argument fence admitted an unsafe request")
		}
	}
	if !reflect.DeepEqual(n.trace(), []string{"gettxout"}) {
		t.Fatal("forbidden gettxout arguments reached the node")
	}
	// Bypass the client fence only to establish that this fake distinguishes
	// the chain-only view from the mempool-inclusive view, as nc28.0 does.
	for _, mempool := range []bool{false, true} {
		body, _ := json.Marshal(map[string]any{"id": 99, "method": "gettxout", "params": []any{sealA, 1, mempool}})
		response, err := http.Post(n.server.URL, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var e struct{ Result json.RawMessage }
		err = json.NewDecoder(response.Body).Decode(&e)
		response.Body.Close()
		if err != nil || (string(e.Result) == "null") != mempool {
			t.Fatal("fake include_mempool semantics disagree with Core 28.0")
		}
	}
	for _, method := range []string{"signrawtransactionwithwallet", "walletcreatefundedpsbt", "walletprocesspsbt", "sendrawtransaction", "getrawtransaction"} {
		if _, f := c.call(context.Background(), method, nil); f == nil || f.Code != "UNSUPPORTED_CAPABILITY" {
			t.Fatal("new read fence admitted a wallet/sign/broadcast/historical RPC")
		}
	}
}

// Claim: both builders enforce funding/change separation, full-parent bindings,
// uniqueness, value bounds and explicit fees before RPC, with valid neighbours.
func TestGrantTransactionFundingRefusals(t *testing.T) {
	f, n, anchor := anchorFlow(t)
	sealScript, _ := rental.GrantSealScript(f.landlord.PublicKey())
	for _, command := range []string{"seal", "anchor"} {
		for _, tc := range []struct {
			name, code string
			mutate     func(*GrantFunding)
		}{
			{"no-inputs", "FUNDING_INPUT", func(r *GrantFunding) { r.Inputs = []GrantFundingInput{} }},
			{"too-many-inputs", "FUNDING_INPUT", func(r *GrantFunding) {
				for len(r.Inputs) <= 16 {
					r.Inputs = append(r.Inputs, r.Inputs[0])
				}
			}},
			{"duplicate", "FUNDING_DUPLICATE_INPUT", func(r *GrantFunding) { r.Inputs = append(r.Inputs, r.Inputs[0]) }},
			{"bad-txid", "FUNDING_INPUT", func(r *GrantFunding) { r.Inputs[0].TxID = "zz" }},
			{"wrong-txid", "FUNDING_PREVOUT", func(r *GrantFunding) { r.Inputs[0].TxID = sealB }},
			{"wrong-vout", "FUNDING_PREVOUT", func(r *GrantFunding) { r.Inputs[0].Vout = 1 }},
			{"missing-parent", "FUNDING_PREVOUT", func(r *GrantFunding) { r.Inputs[0].PrevTxHex = "" }},
			{"parent-tail", "FUNDING_PREVOUT", func(r *GrantFunding) { r.Inputs[0].PrevTxHex += "00" }},
			{"seal-pin", "FUNDING_POLICY", func(r *GrantFunding) { r.ScriptHex = sealScript }},
			{"arbitrary-change", "FUNDING_POLICY", func(r *GrantFunding) { r.ScriptHex = "51" }},
			{"seal-prevout", "FUNDING_SEAL_SCRIPT", func(r *GrantFunding) { r.Inputs = grantTestFunding(t, sealScript, 1000000).Inputs }},
			{"wrong-prevout-script", "FUNDING_SCRIPT_MISMATCH", func(r *GrantFunding) { r.Inputs = grantTestFunding(t, "0014"+strings.Repeat("11", 20), 1000000).Inputs }},
			{"zero-prevout", "FUNDING_AMOUNT", func(r *GrantFunding) { r.Inputs = grantTestFunding(t, r.ScriptHex, 0).Inputs }},
			{"negative-prevout", "FUNDING_AMOUNT", func(r *GrantFunding) { r.Inputs = grantTestFunding(t, r.ScriptHex, -1).Inputs }},
			{"over-max-money", "FUNDING_AMOUNT", func(r *GrantFunding) { r.Inputs = grantTestFunding(t, r.ScriptHex, maxMoneyAtoms+1).Inputs }},
			{"total-overflow", "FUNDING_AMOUNT", func(r *GrantFunding) {
				r.Inputs = append(grantTestFunding(t, r.ScriptHex, maxMoneyAtoms).Inputs, grantTestFunding(t, r.ScriptHex, 1).Inputs...)
			}},
			{"fee-zero", "FEE_RATE", func(r *GrantFunding) { r.FeeRateSatVByte = 0 }},
			{"fee-negative", "FEE_RATE", func(r *GrantFunding) { r.FeeRateSatVByte = -1 }},
			{"fee-high", "FEE_RATE", func(r *GrantFunding) { r.FeeRateSatVByte = 1001 }},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				run := func(funding GrantFunding) (Envelope, int) {
					if command == "seal" {
						return sealCmd(t, n, GrantSealRequest{GrantSealSchema, "regtest", "id/landlord-a", f.landlord.PublicKey(), 100000, funding})
					}
					r := anchor
					r.Funding = funding
					return anchorCmd(t, n, r)
				}
				n.reset("")
				e, code := run(grantTestFunding(t, "", 1000000))
				mustOK(t, e, code)
				bad := grantTestFunding(t, "", 1000000)
				tc.mutate(&bad)
				n.reset("")
				e, code = run(bad)
				mustRefuse(t, e, code, tc.code)
				if code != 3 || len(n.trace()) != 0 {
					t.Fatal("funding shape failure contacted node or used wrong exit")
				}
			})
		}
	}
	// The exact seal input is forbidden independently of its claimed parent.
	bad := anchor
	bad.Funding.Inputs = append([]GrantFundingInput{}, anchor.Funding.Inputs...)
	bad.Funding.Inputs[0].TxID, bad.Funding.Inputs[0].Vout = sealA, 1
	n.reset("")
	e, code := anchorCmd(t, n, bad)
	mustRefuse(t, e, code, "ISSUANCE_SPENDS_SEAL")
	if len(n.trace()) != 0 {
		t.Fatal("seal input admission reached node")
	}
}

// Claim: seal denomination and fee/change boundaries conserve value; anchor
// funding includes the full 72-byte frame, and multiple distinct inputs work.
func TestGrantTransactionAmountBoundaries(t *testing.T) {
	f, n, anchor := anchorFlow(t)
	seal := GrantSealRequest{GrantSealSchema, "regtest", "id/landlord-a", f.landlord.PublicKey(), 100000, grantTestFunding(t, "", 1000000)}
	for _, amount := range []int64{100000, 100001} {
		seal.AmountSat = amount
		e, code := sealCmd(t, n, seal)
		mustOK(t, e, code)
	}
	for _, amount := range []int64{0, -1, 99999, maxMoneyAtoms + 1} {
		seal.AmountSat = amount
		n.reset("")
		e, code := sealCmd(t, n, seal)
		mustRefuse(t, e, code, "SEAL_AMOUNT")
		if len(n.trace()) != 0 {
			t.Fatal("bad denomination reached node")
		}
	}
	seal.AmountSat = 100000
	for _, command := range []string{"seal", "anchor"} {
		run := func(funding GrantFunding) (GrantTransaction, Envelope, int) {
			r := anchor
			r.Funding = funding
			var e Envelope
			var code int
			if command == "seal" {
				q := seal
				q.Funding = funding
				e, code = sealCmd(t, n, q)
			} else {
				e, code = anchorCmd(t, n, r)
			}
			if code != 0 {
				return GrantTransaction{}, e, code
			}
			if command == "seal" {
				return resultAs[GrantSealResult](t, e).Transaction, e, code
			}
			return resultAs[GrantAnchorResult](t, e).Transaction, e, code
		}
		base := grantTestFunding(t, "", 1000000)
		plan, e, code := run(base)
		mustOK(t, e, code)
		amount := int64(0)
		if command == "seal" {
			amount = 100000
		}
		exact := grantTestFunding(t, base.ScriptHex, amount+plan.FeeSat+1000)
		p, e, code := run(exact)
		mustOK(t, e, code)
		if p.Outputs[1].AmountSat != 1000 {
			t.Fatal("minimum change boundary moved")
		}
		_, e, code = run(grantTestFunding(t, base.ScriptHex, amount+plan.FeeSat+999))
		mustRefuse(t, e, code, "FUNDING_OR_DUST_RESERVE")
		if command == "anchor" {
			// 38 extra script bytes distinguish the framed plan from a bare
			// commitment plan; funding sufficient only for bare must refuse.
			_, e, code = run(grantTestFunding(t, base.ScriptHex, plan.FeeSat-38*base.FeeRateSatVByte+1000))
			mustRefuse(t, e, code, "FUNDING_OR_DUST_RESERVE")
		}
		multi := base
		multi.Inputs = append(append([]GrantFundingInput{}, base.Inputs...), grantTestFunding(t, base.ScriptHex, 1000001).Inputs...)
		plan, e, code = run(multi)
		mustOK(t, e, code)
		assertGrantPlan(t, plan, multi, amount, plan.Outputs[0].ScriptHex, plan.Outputs[0].Role)
	}
}

// Claim: malformed/publicly invalid requests, bad signatures, contract mismatch
// and network mismatches refuse without a partial plan; no signing/broadcast flag exists.
func TestGrantTransactionClosedInputAndBindings(t *testing.T) {
	f, n, anchor := anchorFlow(t)
	seal := GrantSealRequest{GrantSealSchema, "regtest", "id/landlord-a", f.landlord.PublicKey(), 100000, grantTestFunding(t, "", 1000000)}
	for _, command := range []string{"seal", "anchor"} {
		var request any = anchor
		if command == "seal" {
			request = seal
		}
		path := writeInput(t, request)
		e, code, _ := runCLI(t, "grant", command, "--config", n.config, "--request", path, "--json")
		mustOK(t, e, code)
		for _, extra := range [][]string{{"--broadcast"}, {"--sign"}, {"--json"}, {"--seal-ledger", f.ledger}} {
			args := []string{"grant", command, "--config", n.config, "--request", path, "--json"}
			n.reset("")
			e, code, _ := runCLI(t, append(args, extra...)...)
			mustRefuse(t, e, code, "BAD_INPUT")
			if code != 2 || len(n.trace()) != 0 {
				t.Fatal("unsupported flag was not rejected before reads")
			}
		}
		b, _ := json.Marshal(request)
		var object map[string]json.RawMessage
		json.Unmarshal(b, &object)
		for _, mode := range []string{"unknown", "null-funding", "missing-schema", "aliased-schema"} {
			mutated := make(map[string]json.RawMessage)
			for k, v := range object {
				mutated[k] = v
			}
			switch mode {
			case "unknown":
				mutated["private_key"] = json.RawMessage(`"fixture-password"`)
			case "null-funding":
				mutated["funding"] = json.RawMessage(`null`)
			case "missing-schema":
				delete(mutated, "schema")
			case "aliased-schema":
				mutated["Schema"] = mutated["schema"]
			}
			n.reset("")
			e, code, _ := runCLI(t, "grant", command, "--config", n.config, "--request", writeInput(t, mutated), "--json")
			mustRefuse(t, e, code, "BAD_INPUT")
			if len(n.trace()) != 0 {
				t.Fatal("closed-input negative contacted the node")
			}
		}
	}
	for _, tc := range []struct {
		name, code string
		mutate     func(*GrantAnchorRequest)
	}{
		{"bad-base64", "BAD_INPUT", func(r *GrantAnchorRequest) { r.SignedGrantB64 = "!" }},
		{"base64-newline", "BAD_INPUT", func(r *GrantAnchorRequest) { r.SignedGrantB64 += "\n" }},
		{"bad-contract", "BAD_INPUT", func(r *GrantAnchorRequest) { r.ContractB64 = "!" }},
		{"wrong-contract", "CONTRACT_HASH", func(r *GrantAnchorRequest) { r.ContractB64 = base64.StdEncoding.EncodeToString([]byte(`{}`)) }},
		{"grant-tail", "CANONICAL_ENCODING", func(r *GrantAnchorRequest) {
			raw, _ := base64.StdEncoding.DecodeString(r.SignedGrantB64)
			r.SignedGrantB64 = base64.StdEncoding.EncodeToString(append(raw, '\n'))
		}},
		{"bad-grant-signature", "GRANT_SIGNATURE", func(r *GrantAnchorRequest) {
			s := *f.signed.SignedGrant
			s.Signature = strings.Repeat("00", 64)
			raw, _ := json.Marshal(s)
			r.SignedGrantB64 = base64.StdEncoding.EncodeToString(raw)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n.reset("")
			e, code := anchorCmd(t, n, anchor)
			mustOK(t, e, code)
			r := anchor
			tc.mutate(&r)
			n.reset("")
			e, code = anchorCmd(t, n, r)
			mustRefuse(t, e, code, tc.code)
			if len(n.trace()) != 0 {
				t.Fatal("invalid grant bytes contacted node")
			}
		})
	}
	// A well-formed but separately pinned config cannot anchor this regtest grant.
	var cfg Config
	if failure := inputFile(n.config, &cfg); failure != nil {
		t.Fatal(failure.Code)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.Network, c.Node.GenesisHash = "main", MainGenesis },
		func(c *Config) { c.Node.GenesisHash = fixtureTip },
	} {
		bad := cfg
		change(&bad)
		n.reset("")
		e, code, _ := runCLI(t, "grant", "anchor", "--config", writeInput(t, bad), "--request", writeInput(t, anchor), "--json")
		mustRefuse(t, e, code, "NETWORK_PIN")
		if len(n.trace()) != 0 {
			t.Fatal("wrong network pin contacted node")
		}
	}
}
