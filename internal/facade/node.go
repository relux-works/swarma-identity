package facade

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const ScanSchema = "swarma-identity/scan/1"
const maxMoneyAtoms int64 = 21000000 * 100000000

type Tip struct {
	Hash   string `json:"hash"`
	Height int64  `json:"height"`
}

type HealthResult struct {
	NodeID               string  `json:"node_id"`
	BackendVersion       int     `json:"backend_version"`
	GenesisHash          string  `json:"genesis_hash"`
	BlockHash            string  `json:"block_hash"`
	Blocks               int64   `json:"blocks"`
	Headers              int64   `json:"headers"`
	InitialBlockDownload bool    `json:"initial_block_download"`
	VerificationProgress float64 `json:"verification_progress"`
	Connections          int64   `json:"connections"`
}

type NameResult struct {
	Name        string `json:"name"`
	ValueHex    string `json:"value_hex"`
	ExpiresIn   int64  `json:"expires_in"`
	Expired     bool   `json:"expired"`
	TxID        string `json:"txid"`
	Vout        uint32 `json:"vout"`
	Height      int64  `json:"height"`
	ObservedTip Tip    `json:"observed_tip"`
}

type ScanRequest struct {
	Schema      string   `json:"schema"`
	Network     string   `json:"network"`
	XPub        string   `json:"xpub"`
	Branches    []uint32 `json:"branches"`
	Start       uint32   `json:"start"`
	Count       uint32   `json:"count"`
	AddressType string   `json:"address_type"`
}

type ScanCoverage struct {
	Mode             string `json:"mode"`
	Scope            string `json:"scope"`
	ConfirmedOnly    bool   `json:"confirmed_only"`
	CompleteForRange bool   `json:"complete_for_range"`
	EntireXPub       bool   `json:"entire_xpub"`
	History          bool   `json:"history"`
	Mempool          bool   `json:"mempool"`
	Spendability     string `json:"spendability"`
	NameOutputs      string `json:"name_outputs"`
}

type ScanResult struct {
	Mode              string       `json:"mode"`
	AddressType       string       `json:"address_type"`
	Branches          []uint32     `json:"branches"`
	Start             uint32       `json:"start"`
	Count             uint32       `json:"count"`
	MatchedUTXOAtoms  int64        `json:"matched_utxo_nmc_atoms"`
	UTXOCount         int          `json:"utxo_count"`
	CoinbaseUTXOCount int          `json:"coinbase_utxo_count"`
	ObservedTip       Tip          `json:"observed_tip"`
	Coverage          ScanCoverage `json:"coverage"`
}

func object(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	err := json.Unmarshal(raw, &m)
	return m, err == nil && m != nil
}

// A consumed provider member must be present, non-null and correctly typed.
// Unknown provider members are deliberately not copied into product results.
func member(m map[string]json.RawMessage, key string, dst any) bool {
	b, ok := m[key]
	return ok && !bytes.Equal(bytes.TrimSpace(b), []byte("null")) && json.Unmarshal(b, dst) == nil
}

func hashValid(s string) bool {
	return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == ""
}

func (c *Client) Health(ctx context.Context) (*HealthResult, *Failure) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	networkRaw, f := c.call(ctx, "getnetworkinfo", nil)
	if f != nil {
		return nil, f
	}
	network, ok := object(networkRaw)
	h := &HealthResult{NodeID: c.config.Node.ID}
	if !ok || !member(network, "version", &h.BackendVersion) || !member(network, "connections", &h.Connections) || h.Connections < 0 {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	if h.BackendVersion != 280000 {
		return nil, fail("UNSUPPORTED_CAPABILITY")
	}
	chainRaw, f := c.call(ctx, "getblockchaininfo", nil)
	if f != nil {
		return nil, f
	}
	chain, ok := object(chainRaw)
	var chainName string
	if !ok || !member(chain, "chain", &chainName) || !member(chain, "bestblockhash", &h.BlockHash) || !member(chain, "blocks", &h.Blocks) || !member(chain, "headers", &h.Headers) || !member(chain, "initialblockdownload", &h.InitialBlockDownload) || !member(chain, "verificationprogress", &h.VerificationProgress) || !hashValid(h.BlockHash) || h.Blocks < 0 || h.Headers < h.Blocks || h.VerificationProgress < 0 || h.VerificationProgress > 1 {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	if chainName != c.config.Network {
		return nil, fail("WRONG_NETWORK")
	}
	genesisRaw, f := c.call(ctx, "getblockhash", []any{0})
	if f != nil {
		return nil, f
	}
	if json.Unmarshal(genesisRaw, &h.GenesisHash) != nil || !hashValid(h.GenesisHash) {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	if h.GenesisHash != c.config.Node.GenesisHash {
		return nil, fail("WRONG_NETWORK")
	}
	return h, nil
}

func (c *Client) sameTip(ctx context.Context, expected string) *Failure {
	raw, f := c.call(ctx, "getbestblockhash", nil)
	if f != nil {
		return f
	}
	var observed string
	if json.Unmarshal(raw, &observed) != nil || !hashValid(observed) {
		return fail("PROVIDER_PROTOCOL")
	}
	if observed != expected {
		return fail("SNAPSHOT_CHANGED")
	}
	return nil
}

func (c *Client) Name(ctx context.Context, name string) (*NameResult, *Failure) {
	if name == "" || len(name) > 255 || !utf8.ValidString(name) {
		return nil, fail("BAD_INPUT")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	h, f := c.Health(ctx)
	if f != nil {
		return nil, f
	}
	if h.InitialBlockDownload {
		return nil, fail("NODE_UNSYNCED")
	}
	n, f := c.readName(ctx, name)
	if f != nil {
		return nil, f
	}
	if f := c.sameTip(ctx, h.BlockHash); f != nil {
		return nil, f
	}
	if n.Height > h.Blocks {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	if n.Expired {
		return nil, fail("NAME_EXPIRED")
	}
	n.ObservedTip = Tip{Hash: h.BlockHash, Height: h.Blocks}
	return n, nil
}

// readName sends one explicit name_show and validates the consumed record. It
// takes no tip observation; callers bracket it with Health and sameTip.
func (c *Client) readName(ctx context.Context, name string) (*NameResult, *Failure) {
	raw, f := c.call(ctx, "name_show", []any{name, map[string]any{"nameEncoding": "utf8", "valueEncoding": "hex", "allowExpired": true}})
	if f != nil {
		return nil, f
	}
	m, ok := object(raw)
	n := &NameResult{}
	if !ok || !member(m, "name", &n.Name) || !member(m, "value", &n.ValueHex) || !member(m, "expires_in", &n.ExpiresIn) || !member(m, "expired", &n.Expired) || !member(m, "txid", &n.TxID) || !member(m, "vout", &n.Vout) || !member(m, "height", &n.Height) || n.Name != name || !hashValid(n.TxID) || n.Height < 0 || len(n.ValueHex) > 1040 {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	value, err := hex.DecodeString(n.ValueHex)
	if err != nil {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	n.ValueHex = hex.EncodeToString(value)
	if n.Expired != (n.ExpiresIn <= 0) {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	return n, nil
}

func (c *Client) Scan(ctx context.Context, r ScanRequest) (*ScanResult, *Failure) {
	if r.Schema != ScanSchema || r.Network != c.config.Network || r.AddressType != "p2wpkh" || len(r.Branches) != 2 || r.Branches[0] != 0 || r.Branches[1] != 1 {
		return nil, fail("BAD_INPUT")
	}
	ctx, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()
	preflight, preCancel := context.WithTimeout(ctx, 10*time.Second)
	defer preCancel()
	scripts := make(map[string]bool)
	for _, branch := range r.Branches {
		addresses, f := deriveRange(DeriveRequest{Schema: DeriveSchema, Network: r.Network, XPub: r.XPub, RelativePath: []uint32{branch}, Start: r.Start, Count: r.Count, AddressType: r.AddressType}, 1000)
		if f != nil {
			return nil, f
		}
		for _, a := range addresses {
			scripts[a.scriptHex] = true
		}
	}
	h, f := c.Health(preflight)
	if f != nil {
		return nil, f
	}
	if h.InitialBlockDownload {
		return nil, fail("NODE_UNSYNCED")
	}
	if preflight.Err() != nil {
		return nil, fail("RPC_UNAVAILABLE")
	}
	preCancel()
	descriptors := make([]any, 0, 2)
	for _, branch := range r.Branches {
		descriptors = append(descriptors, map[string]any{"desc": "wpkh(" + r.XPub + "/" + strconv.FormatUint(uint64(branch), 10) + "/*)", "range": []uint32{r.Start, r.Start + r.Count - 1}})
	}
	deadline, _ := ctx.Deadline()
	scanDeadline := time.Now().Add(285 * time.Second)
	if latest := deadline.Add(-5 * time.Second); latest.Before(scanDeadline) {
		scanDeadline = latest
	}
	if !scanDeadline.After(time.Now()) {
		return nil, fail("RPC_UNAVAILABLE")
	}
	scanCtx, scanCancel := context.WithDeadline(ctx, scanDeadline)
	raw, f := c.call(scanCtx, "scantxoutset", []any{"start", descriptors})
	scanCancel()
	if f != nil {
		return nil, f
	}
	m, ok := object(raw)
	var success bool
	var height int64
	var bestblock string
	var unspents []json.RawMessage
	if !ok || !member(m, "success", &success) || !success || !member(m, "height", &height) || height < 0 || !member(m, "bestblock", &bestblock) || !hashValid(bestblock) || !member(m, "unspents", &unspents) || unspents == nil {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	if height != h.Blocks || bestblock != h.BlockHash {
		return nil, fail("SNAPSHOT_CHANGED")
	}
	total, ok := amountAtoms(m["total_amount"])
	if !ok {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	result := &ScanResult{Mode: "utxo-scan", AddressType: r.AddressType, Branches: append([]uint32{}, r.Branches...), Start: r.Start, Count: r.Count, ObservedTip: Tip{Hash: bestblock, Height: height}, Coverage: ScanCoverage{Mode: "utxo-scan", Scope: "requested-descriptor-set", ConfirmedOnly: true, CompleteForRange: true, Spendability: "unassessed", NameOutputs: "excluded"}}
	seen := make(map[string]bool)
	for _, rawUTXO := range unspents {
		u, ok := object(rawUTXO)
		var txid, script string
		var vout uint32
		var outputHeight int64
		var coinbase bool
		if !ok || !member(u, "txid", &txid) || !hashValid(txid) || !member(u, "vout", &vout) || !member(u, "scriptPubKey", &script) || !scripts[script] || !member(u, "height", &outputHeight) || outputHeight < 1 || outputHeight > height || !member(u, "coinbase", &coinbase) {
			return nil, fail("PROVIDER_PROTOCOL")
		}
		outpoint := txid + ":" + strconv.FormatUint(uint64(vout), 10)
		amount, ok := amountAtoms(u["amount"])
		if !ok || seen[outpoint] || amount > maxMoneyAtoms-result.MatchedUTXOAtoms {
			return nil, fail("PROVIDER_PROTOCOL")
		}
		seen[outpoint] = true
		result.MatchedUTXOAtoms += amount
		result.UTXOCount++
		if coinbase {
			result.CoinbaseUTXOCount++
		}
	}
	if result.MatchedUTXOAtoms != total {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	postCtx, postCancel := context.WithTimeout(ctx, 5*time.Second)
	defer postCancel()
	if f := c.sameTip(postCtx, bestblock); f != nil {
		return nil, f
	}
	return result, nil
}

// Parse bounded JSON numbers exactly, without floating point or attacker-sized
// exponent allocation. Values must be integral after multiplying by 10^8.
func amountAtoms(raw json.RawMessage) (int64, bool) {
	s := string(bytes.TrimSpace(raw))
	if len(s) == 0 || len(s) > 40 || !json.Valid([]byte(s)) || (s[0] < '0' || s[0] > '9') {
		return 0, false
	}
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		e, err := strconv.Atoi(s[i+1:])
		if err != nil || e < -18 || e > 18 {
			return 0, false
		}
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Sign() < 0 {
		return 0, false
	}
	r.Mul(r, big.NewRat(100000000, 1))
	if !r.IsInt() || !r.Num().IsInt64() {
		return 0, false
	}
	n := r.Num().Int64()
	return n, n <= maxMoneyAtoms
}
