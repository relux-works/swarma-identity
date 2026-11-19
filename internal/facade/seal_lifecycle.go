package facade

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

const SealPlanSchema = "swarma-identity/seal-plan/1"

type SealPlanRequest struct {
	Schema             string       `json:"schema"`
	Network            string       `json:"network"`
	SignedGrantB64     string       `json:"signed_grant_b64"`
	ContractB64        string       `json:"contract_b64"`
	AmountSat          int64        `json:"amount_sat"`
	Funding            GrantFunding `json:"funding"`
	FundingPubkey      string       `json:"funding_pubkey"`
	MaxFeeSat          int64        `json:"max_fee_sat"`
	MaxFeeRateSatVByte int64        `json:"max_fee_rate_sat_vbyte"`
	MinConfirmations   int64        `json:"min_confirmations"`
}

type SealLifecycleResult struct {
	GrantID             string           `json:"grant_id"`
	State               string           `json:"state"`
	TxID                string           `json:"txid"`
	Transaction         GrantTransaction `json:"transaction"`
	Summary             string           `json:"summary"`
	BroadcastAttempted  bool             `json:"broadcast_attempted"`
	NeedsReconciliation bool             `json:"needs_reconciliation"`
	Confirmations       int64            `json:"confirmations"`
	ObservedTip         Tip              `json:"observed_tip"`
}

func sealPlan(request SealPlanRequest) (string, *GrantTransaction, *Failure) {
	if request.Schema != SealPlanSchema || pinnedGenesis(request.Network) == "" || request.AmountSat < minGrantSealAtoms || !amountValid(request.AmountSat) || request.MinConfirmations < 1 || request.MinConfirmations > 10000 {
		return "", nil, fail("BAD_INPUT")
	}
	if request.MaxFeeSat < 1 || !amountValid(request.MaxFeeSat) || request.MaxFeeRateSatVByte < 1 || request.MaxFeeRateSatVByte > 1000 || request.Funding.FeeRateSatVByte > request.MaxFeeRateSatVByte {
		return "", nil, refuse("SEAL_FEE_CAP")
	}
	raw, ok := grantBase64(request.SignedGrantB64)
	if !ok {
		return "", nil, fail("BAD_INPUT")
	}
	signed, err := rental.ParseSignedGrant(raw)
	if err != nil {
		return "", nil, rentalRefusal(err)
	}
	grant := signed.Grant
	if grant.Network != request.Network || grant.Genesis != pinnedGenesis(request.Network) {
		return "", nil, refuse("NETWORK_PIN")
	}
	contract, ok := grantBase64(request.ContractB64)
	if !ok {
		return "", nil, fail("BAD_INPUT")
	}
	if code := bindTrustContract(contract, trustGrantView{grant.Network, grant.AgentName, grant.LandlordName, grant.GranteeKey, grant.ContractSHA256, grant.Scope, grant.BudgetSat(), grant.NotBefore, grant.NotAfter, grant.Consent.ConsentEvent.Tags}); code != "" {
		return "", nil, refuse(code)
	}
	public, err := hex.DecodeString(request.FundingPubkey)
	if err != nil || len(public) != 33 || hex.EncodeToString(public) != request.FundingPubkey {
		return "", nil, refuse("FUNDING_NOT_OWNED")
	}
	key, err := btcec.ParsePubKey(public)
	if err != nil || !bytes.Equal(key.SerializeCompressed(), public) || request.Funding.ScriptHex != "0014"+hex.EncodeToString(btcutil.Hash160(public)) {
		return "", nil, refuse("FUNDING_NOT_OWNED")
	}
	script, err := rental.GrantSealScript(grant.IssuerKey)
	if err != nil {
		return "", nil, rentalRefusal(err)
	}
	funds, failure := grantFunding(request.Funding, script, &grant.Seal)
	if failure != nil {
		return "", nil, failure
	}
	plan, failure := funds.build(request.AmountSat, script, "seal", request.Funding.FeeRateSatVByte)
	if failure != nil {
		return "", nil, failure
	}
	if plan.FeeSat > request.MaxFeeSat {
		return "", nil, refuse("SEAL_FEE_CAP")
	}
	if grant.Seal.TxID != plan.UnsignedTxID || grant.Seal.Vout != 0 {
		return "", nil, refuse("SEAL_GRANT_MISMATCH")
	}
	return signed.ID(), plan, nil
}

func sealSummary(id string, plan *GrantTransaction) string {
	return fmt.Sprintf("Create v3 grant seal %s:0 for grant %s; %d atoms; fee %d atoms", plan.UnsignedTxID, id, plan.Outputs[0].AmountSat, plan.FeeSat)
}

func (journal *sealJournal) result() *SealLifecycleResult {
	return &SealLifecycleResult{journal.GrantID, journal.State, journal.Plan.UnsignedTxID, journal.Plan, sealSummary(journal.GrantID, &journal.Plan), journal.Attempted, journal.Attempted && journal.State == "accepted", journal.Confirmations, journal.ObservedTip}
}

func executeSeal(ctx context.Context, command string, args []string, deps keychainDeps) (string, any, *Failure) {
	names := []string{"journal"}
	switch command {
	case "seal plan":
		names = append(names, "request")
	case "seal sign":
		names = append(names, "label")
	case "seal broadcast":
		names = append(names, "config", "broadcast-config")
	case "seal observe":
		names = append(names, "config")
	}
	options, failure := keychainOptions(args, names...)
	if failure != nil {
		return "", nil, failure
	}
	for _, name := range names {
		if options[name] == "" {
			return "", nil, fail("BAD_INPUT")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var request *SealPlanRequest
	if command == "seal plan" {
		request = &SealPlanRequest{}
		if failure := inputFile(options["request"], request); failure != nil {
			return "", nil, failure
		}
	}
	journal, failure := openSealJournal(ctx, options["journal"], request)
	if failure != nil {
		return "", nil, failure
	}
	defer journal.guard.close()
	network := journal.Request.Network
	switch command {
	case "seal sign":
		failure = journal.sign(deps, options["label"])
	case "seal broadcast":
		if journal.Attempted {
			return network, journal.result(), nil
		}
		failure = journal.broadcast(ctx, options["config"], options["broadcast-config"])
	case "seal observe":
		failure = journal.observe(ctx, options["config"])
	}
	if failure != nil {
		return network, nil, failure
	}
	return network, journal.result(), nil
}

func (journal *sealJournal) reader(path string) (*Client, *Failure) {
	var config Config
	if failure := inputFile(path, &config); failure != nil {
		return nil, failure
	}
	if config.Network != journal.Request.Network || config.Node.GenesisHash != pinnedGenesis(journal.Request.Network) {
		return nil, refuse("NETWORK_PIN")
	}
	client, failure := NewClient(config)
	if failure != nil {
		return nil, failure
	}
	if client.user != "verifier" {
		client.Close()
		return nil, refuse("SEAL_READ_AUTH")
	}
	return client, nil
}

func sealRead(ctx context.Context, client *Client, method string, params []any) (json.RawMessage, *Failure) {
	if client.user != "verifier" {
		return nil, refuse("SEAL_READ_AUTH")
	}
	switch method {
	case "decoderawtransaction", "testmempoolaccept", "getrawtransaction", "getblockheader":
		return client.rpcCall(ctx, method, params)
	}
	return nil, fail("UNSUPPORTED_CAPABILITY")
}

func (journal *sealJournal) broadcaster(path string, reader *Client) (*Client, *Failure) {
	var config Config
	if failure := inputFile(path, &config); failure != nil {
		return nil, failure
	}
	if config.Node.RPCProfile != "namecoin-core-broadcast/1" || config.Network != reader.config.Network || config.Node.GenesisHash != reader.config.Node.GenesisHash || config.Node.RPCURL != reader.config.Node.RPCURL || config.Node.ID != reader.config.Node.ID || config.WatchWallet != nil {
		return nil, refuse("SEAL_BROADCAST_CONFIG")
	}
	config.Node.RPCProfile = "namecoin-core-read/1"
	client, failure := NewClient(config)
	if failure != nil {
		return nil, failure
	}
	if client.user == "verifier" || client.user == reader.user {
		client.Close()
		return nil, refuse("SEAL_BROADCAST_AUTH")
	}
	client.http.Transport.(*http.Transport).DisableKeepAlives = true
	return client, nil
}

func (journal *sealJournal) maxFeeRate() json.Number {
	rate := journal.Request.MaxFeeRateSatVByte
	return json.Number(fmt.Sprintf("%d.%05d", rate/100000, rate%100000))
}

func (journal *sealJournal) broadcast(ctx context.Context, readPath, writePath string) *Failure {
	if journal.State != "signed" && journal.State != "accepted" {
		return refuse("SEAL_NOT_SIGNED")
	}
	reader, failure := journal.reader(readPath)
	if failure != nil {
		return failure
	}
	defer reader.Close()
	writer, failure := journal.broadcaster(writePath, reader)
	if failure != nil {
		return failure
	}
	defer writer.Close()
	health, failure := reader.Health(ctx)
	if failure != nil {
		return failure
	}
	if health.InitialBlockDownload {
		return fail("NODE_UNSYNCED")
	}
	for _, input := range journal.Request.Funding.Inputs {
		raw, failure := reader.call(ctx, "gettxout", []any{input.TxID, input.Vout, true})
		if failure != nil {
			return failure
		}
		view, ok := object(raw)
		var script map[string]json.RawMessage
		var scriptHex, best string
		amount, valid := amountAtoms(view["value"])
		parentHash := wire.OutPoint{}
		hash, _ := chainhash.NewHashFromStr(input.TxID)
		parentHash.Hash = *hash
		parentHash.Index = input.Vout
		prevout, parentOK := prevTxOutput(input.PrevTxHex, parentHash)
		if !ok || !valid || !parentOK || !member(view, "bestblock", &best) || best != health.BlockHash || !member(view, "scriptPubKey", &script) || !member(script, "hex", &scriptHex) || amount != prevout.Value || scriptHex != journal.Request.Funding.ScriptHex {
			return refuse("SEAL_FUNDING_UNAVAILABLE")
		}
	}
	decoded, failure := sealRead(ctx, reader, "decoderawtransaction", []any{journal.SignedTxHex, true})
	if failure != nil {
		return failure
	}
	var transaction struct {
		TxID string `json:"txid"`
		Vout []struct {
			N      *uint32         `json:"n"`
			Value  json.RawMessage `json:"value"`
			Script struct {
				Hex string `json:"hex"`
			} `json:"scriptPubKey"`
		} `json:"vout"`
	}
	if json.Unmarshal(decoded, &transaction) != nil || transaction.TxID != journal.Plan.UnsignedTxID || len(transaction.Vout) != len(journal.Plan.Outputs) {
		return fail("PROVIDER_PROTOCOL")
	}
	for index, output := range transaction.Vout {
		amount, ok := amountAtoms(output.Value)
		want := journal.Plan.Outputs[index]
		if !ok || output.N == nil || *output.N != uint32(index) || output.Script.Hex != want.ScriptHex || amount != want.AmountSat {
			return fail("PROVIDER_PROTOCOL")
		}
	}
	raw, failure := sealRead(ctx, reader, "testmempoolaccept", []any{[]string{journal.SignedTxHex}, journal.maxFeeRate()})
	if failure != nil {
		return failure
	}
	var acceptance []struct {
		TxID    string `json:"txid"`
		Allowed *bool  `json:"allowed"`
		VSize   int    `json:"vsize"`
		Fees    struct {
			Base json.RawMessage `json:"base"`
		} `json:"fees"`
	}
	if json.Unmarshal(raw, &acceptance) != nil || len(acceptance) != 1 || acceptance[0].TxID != journal.Plan.UnsignedTxID || acceptance[0].Allowed == nil {
		return fail("PROVIDER_PROTOCOL")
	}
	if !*acceptance[0].Allowed {
		return refuse("SEAL_MEMPOOL_REJECTED")
	}
	fee, ok := amountAtoms(acceptance[0].Fees.Base)
	if !ok || fee != journal.Plan.FeeSat || acceptance[0].VSize < 1 || acceptance[0].VSize > journal.Plan.MaxSignedVBytes || fee > int64(acceptance[0].VSize)*journal.Request.MaxFeeRateSatVByte {
		return refuse("SEAL_FEE_CAP")
	}
	if failure := reader.sameTip(ctx, health.BlockHash); failure != nil {
		return failure
	}
	journal.State = "accepted"
	if failure := journal.save(); failure != nil {
		return failure
	}
	journal.Attempted = true
	if failure := journal.save(); failure != nil {
		return failure
	}
	raw, failure = writer.rpcCall(ctx, "sendrawtransaction", []any{journal.SignedTxHex, journal.maxFeeRate()})
	var txid string
	if failure != nil || json.Unmarshal(raw, &txid) != nil || txid != journal.Plan.UnsignedTxID {
		return refuse("SEAL_BROADCAST_UNCERTAIN")
	}
	journal.State = "broadcast"
	return journal.save()
}

func (journal *sealJournal) observe(ctx context.Context, path string) *Failure {
	if !journal.Attempted {
		return refuse("SEAL_BROADCAST_REQUIRED")
	}
	client, failure := journal.reader(path)
	if failure != nil {
		return failure
	}
	defer client.Close()
	health, failure := client.Health(ctx)
	if failure != nil {
		return failure
	}
	if health.InitialBlockDownload {
		return fail("NODE_UNSYNCED")
	}
	raw, failure := sealRead(ctx, client, "getrawtransaction", []any{journal.Plan.UnsignedTxID, true})
	if failure != nil {
		return failure
	}
	view, ok := object(raw)
	var transactionHex, txid, blockHash string
	if !ok || !member(view, "hex", &transactionHex) || transactionHex != journal.SignedTxHex || !member(view, "txid", &txid) || txid != journal.Plan.UnsignedTxID {
		return fail("PROVIDER_PROTOCOL")
	}
	depth := int64(0)
	if value, present := view["blockhash"]; present {
		if json.Unmarshal(value, &blockHash) != nil || !hashValid(blockHash) {
			return fail("PROVIDER_PROTOCOL")
		}
		header, failure := sealRead(ctx, client, "getblockheader", []any{blockHash, true})
		if failure != nil {
			return failure
		}
		block, ok := object(header)
		var height, confirmations int64
		var observed string
		if !ok || !member(block, "hash", &observed) || observed != blockHash || !member(block, "height", &height) || height < 0 || height > health.Blocks || !member(view, "confirmations", &confirmations) {
			return fail("PROVIDER_PROTOCOL")
		}
		active, failure := client.call(ctx, "getblockhash", []any{height})
		if failure != nil {
			return failure
		}
		if json.Unmarshal(active, &observed) != nil {
			return fail("PROVIDER_PROTOCOL")
		}
		if observed == blockHash {
			depth = health.Blocks - height + 1
			if depth != confirmations {
				return fail("SNAPSHOT_CHANGED")
			}
		}
	}
	if failure := client.sameTip(ctx, health.BlockHash); failure != nil {
		return failure
	}
	if journal.State == "accepted" {
		journal.State = "broadcast"
		if failure := journal.save(); failure != nil {
			return failure
		}
	}
	journal.State = "broadcast"
	if depth >= journal.Request.MinConfirmations {
		journal.State = "confirmed"
	}
	journal.Confirmations, journal.ObservedTip = depth, Tip{health.BlockHash, health.Blocks}
	return journal.save()
}
