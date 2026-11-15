package facade

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental/oplocator"
)

const (
	GrantSealSchema   = "swarma-trust/seal/1"
	GrantAnchorSchema = "swarma-trust/anchor/1"

	// LIP-0004's pinned implementation profile (rental/grant_pool.go),
	// rather than a consensus limit or a denomination specified by the LIP.
	minGrantSealAtoms = 100000
	minGrantChange    = 1000
)

// GrantFunding carries explicit public wallet facts. Full parents bind amounts
// and scripts to txids; neither ownership nor current spendability is inferred.
type GrantFunding struct {
	ScriptHex       string              `json:"script_hex"`
	Inputs          []GrantFundingInput `json:"inputs"`
	FeeRateSatVByte int64               `json:"fee_rate_sat_vbyte"`
}

type GrantFundingInput struct {
	TxID      string `json:"txid"`
	Vout      uint32 `json:"vout"`
	PrevTxHex string `json:"prev_tx_hex"`
}

type GrantSealRequest struct {
	Schema       string       `json:"schema"`
	Network      string       `json:"network"`
	LandlordName string       `json:"landlord_name"`
	IssuerKey    string       `json:"issuer_key"`
	AmountSat    int64        `json:"amount_sat"`
	Funding      GrantFunding `json:"funding"`
}

type GrantAnchorRequest struct {
	Schema         string       `json:"schema"`
	SignedGrantB64 string       `json:"signed_grant_b64"`
	ContractB64    string       `json:"contract_b64"`
	Funding        GrantFunding `json:"funding"`
	// Optional public candidate to verify. It must be exactly the fresh
	// issuance frame; no alternate version, action or location is written.
	FrameHex string `json:"frame_hex,omitempty"`
}

type GrantTxOutput struct {
	Vout      uint32 `json:"vout"`
	AmountSat int64  `json:"amount_sat"`
	ScriptHex string `json:"script_hex"`
	Role      string `json:"role"`
}

type GrantTransaction struct {
	UnsignedTxHex   string          `json:"unsigned_tx_hex"`
	UnsignedTxID    string          `json:"unsigned_txid"`
	PSBTB64         string          `json:"psbt_b64"`
	Outputs         []GrantTxOutput `json:"outputs"`
	FeeSat          int64           `json:"fee_sat"`
	FeeRateSatVByte int64           `json:"fee_rate_sat_vbyte"`
	MaxSignedVBytes int             `json:"maximum_signed_vbytes"`
	RequiredReview  string          `json:"required_review"`
}

type GrantSealResult struct {
	DryRun      bool             `json:"dry_run"`
	Transaction GrantTransaction `json:"transaction"`
	Seal        rental.Point     `json:"seal"`
	IssuerKey   string           `json:"issuer_key"`
	ObservedTip Tip              `json:"observed_tip"`
}

type GrantSealObservation struct {
	Point          rental.Point `json:"point"`
	Confirmations  int64        `json:"confirmations"`
	AmountSat      int64        `json:"amount_sat"`
	ScriptHex      string       `json:"script_hex"`
	IncludeMempool bool         `json:"include_mempool"`
}

type GrantAnchorResult struct {
	DryRun      bool                 `json:"dry_run"`
	Transaction GrantTransaction     `json:"transaction"`
	GrantID     string               `json:"grant_id"`
	Commitment  string               `json:"commitment"`
	FrameHex    string               `json:"frame_hex"`
	Seal        GrantSealObservation `json:"seal"`
	ObservedTip Tip                  `json:"observed_tip"`
}

// SealGrant builds one unsigned seal plus funding change. It checks the
// selected node/version and active landlord's independently supplied key.
// It never reserves a seal, signs, broadcasts, or calls a wallet RPC.
func (c *Client) SealGrant(ctx context.Context, r GrantSealRequest) (*GrantSealResult, *Failure) {
	if r.Schema != GrantSealSchema || !v3Name(r.LandlordName) || !xOnlyKey(r.IssuerKey) {
		return nil, fail("BAD_INPUT")
	}
	if pinnedGenesis(r.Network) == "" || r.Network != c.config.Network || c.config.Node.GenesisHash != pinnedGenesis(r.Network) {
		return nil, refuse("NETWORK_PIN")
	}
	if r.AmountSat < minGrantSealAtoms || !amountValid(r.AmountSat) {
		return nil, refuse("SEAL_AMOUNT")
	}
	sealScript, err := rental.GrantSealScript(r.IssuerKey)
	if err != nil {
		return nil, rentalRefusal(err)
	}
	// Validate public wallet facts before contacting the node. No transaction
	// plan escapes until the issuer pin has been checked.
	funds, f := grantFunding(r.Funding, sealScript, nil)
	if f != nil {
		return nil, f
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	id, f := c.Identity(ctx, r.LandlordName)
	if f != nil {
		return nil, f
	}
	if id.Role != "landlord" {
		return nil, refuse("LANDLORD_NOT_V3")
	}
	if id.GrantKey != r.IssuerKey {
		return nil, refuse("LANDLORD_KEY_MISMATCH")
	}
	plan, f := funds.build(r.AmountSat, sealScript, "seal", r.Funding.FeeRateSatVByte)
	if f != nil {
		return nil, f
	}
	return &GrantSealResult{true, *plan, rental.Point{TxID: plan.UnsignedTxID, Vout: 0}, r.IssuerKey, id.ObservedTip}, nil
}

// AnchorGrant verifies the exact signed grant and its contract, then observes
// the current issuer and seal before constructing an unsigned issuance. This
// is a point-in-time pre-check, never a live-grant or broadcast receipt.
func (c *Client) AnchorGrant(ctx context.Context, r GrantAnchorRequest) (*GrantAnchorResult, *Failure) {
	if r.Schema != GrantAnchorSchema {
		return nil, fail("BAD_INPUT")
	}
	raw, ok := grantBase64(r.SignedGrantB64)
	if !ok {
		return nil, fail("BAD_INPUT")
	}
	signed, err := rental.ParseSignedGrant(raw)
	if err != nil {
		return nil, rentalRefusal(err)
	}
	g := signed.Grant
	if pinnedGenesis(g.Network) == "" || g.Network != c.config.Network || g.Genesis != pinnedGenesis(g.Network) || c.config.Node.GenesisHash != g.Genesis {
		return nil, refuse("NETWORK_PIN")
	}
	contract, ok := grantBase64(r.ContractB64)
	if !ok {
		return nil, fail("BAD_INPUT")
	}
	if code := bindTrustContract(contract, trustGrantView{g.Network, g.AgentName, g.LandlordName, g.GranteeKey, g.ContractSHA256, g.Scope, g.BudgetSat(), g.NotBefore, g.NotAfter, g.Consent.ConsentEvent.Tags}); code != "" {
		return nil, refuse(code)
	}
	commitment, err := rental.IssuanceCommitment(signed)
	if err != nil {
		return nil, rentalRefusal(err)
	}
	id := signed.ID()
	commit, _ := hex.DecodeString(commitment)
	pointer, _ := hex.DecodeString(id)
	frame, err := oplocator.Build(oplocator.ActionGrantIssuance, [32]byte(commit), oplocator.Locator{Type: oplocator.LocationBlob, Pointer: pointer})
	if err != nil {
		return nil, fail("INTERNAL")
	}
	if r.FrameHex != "" {
		candidate, err := hex.DecodeString(r.FrameHex)
		if err != nil || hex.EncodeToString(candidate) != r.FrameHex {
			return nil, refuse("ANCHOR_FRAME")
		}
		if f := checkGrantFrame(candidate, commitment, id); f != nil {
			return nil, f
		}
	}
	if f := checkGrantFrame(frame, commitment, id); f != nil {
		return nil, f
	}
	sealScript, err := rental.GrantSealScript(g.IssuerKey)
	if err != nil {
		return nil, rentalRefusal(err)
	}
	funds, f := grantFunding(r.Funding, sealScript, &g.Seal)
	if f != nil {
		return nil, f
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	issuer, tip, f := c.grantIssuer(ctx, g.LandlordName, g.AgentName)
	if f != nil {
		return nil, f
	}
	if issuer != g.IssuerKey {
		return nil, refuse("LANDLORD_KEY_MISMATCH")
	}
	seal, f := c.readGrantSeal(ctx, g.Seal, sealScript, tip)
	if f != nil {
		return nil, f
	}
	if f := c.sameTip(ctx, tip.Hash); f != nil {
		return nil, f
	}
	plan, f := funds.build(0, hex.EncodeToString(frame), "issuance-commitment", r.Funding.FeeRateSatVByte)
	if f != nil {
		return nil, f
	}
	return &GrantAnchorResult{true, *plan, id, commitment, hex.EncodeToString(frame), *seal, tip}, nil
}

func grantBase64(s string) ([]byte, bool) {
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	return raw, err == nil && len(raw) > 0 && len(raw) <= 32768 && base64.StdEncoding.EncodeToString(raw) == s
}

// checkGrantFrame narrows the generic LIP-0005 parser to fresh LIP-0004
// issuance; valid generic frames (including torrents/batches) are insufficient.
func checkGrantFrame(script []byte, commitment, id string) *Failure {
	if len(script) > 83 {
		return refuse("ANCHOR_FRAME_SIZE")
	}
	if len(script) >= 7 && bytes.Equal(script[:4], []byte{0x6a, 3, 0x53, 0x4c}) && script[5] >= 1 && script[5] <= 75 && len(script) == 6+int(script[5]) && script[6] != 1 {
		return refuse("ANCHOR_FRAME_VERSION")
	}
	m, err := oplocator.Parse(script)
	if err != nil || m.Legacy {
		return refuse("ANCHOR_FRAME")
	}
	if m.Action != oplocator.ActionGrantIssuance {
		return refuse("ANCHOR_FRAME_ACTION")
	}
	if m.Locator.Type != oplocator.LocationBlob || hex.EncodeToString(m.Locator.Pointer) != id {
		return refuse("ANCHOR_FRAME_LOCATOR")
	}
	if hex.EncodeToString(m.Commitment[:]) != commitment {
		return refuse("ANCHOR_FRAME_COMMITMENT")
	}
	return nil
}

func (c *Client) readGrantSeal(ctx context.Context, point rental.Point, script string, tip Tip) (*GrantSealObservation, *Failure) {
	raw, f := c.call(ctx, "gettxout", []any{point.TxID, point.Vout, true})
	if f != nil {
		return nil, f
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		// Core cannot distinguish absent from spent through this RPC.
		return nil, refuse("SEAL_MISSING_OR_SPENT")
	}
	m, ok := object(raw)
	var bestblock string
	var confirmations int64
	var coinbase bool
	var pk json.RawMessage
	if !ok || !member(m, "bestblock", &bestblock) || !hashValid(bestblock) || !member(m, "confirmations", &confirmations) || confirmations < 0 || confirmations > tip.Height+1 || !member(m, "coinbase", &coinbase) || !member(m, "scriptPubKey", &pk) {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	amount, valid := amountAtoms(m["value"])
	if !valid {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	if bestblock != tip.Hash {
		return nil, fail("SNAPSHOT_CHANGED")
	}
	if confirmations == 0 {
		return nil, refuse("SEAL_UNCONFIRMED")
	}
	p, ok := object(pk)
	var gotScript, kind string
	if !ok || !member(p, "hex", &gotScript) || !member(p, "type", &kind) {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	decoded, err := hex.DecodeString(gotScript)
	if err != nil || hex.EncodeToString(decoded) != gotScript {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	if kind != "pubkeyhash" || !txscript.IsPayToPubKeyHash(decoded) {
		return nil, refuse("SEAL_SCRIPT_TYPE")
	}
	if gotScript != script {
		return nil, refuse("SEAL_KEY_MISMATCH")
	}
	return &GrantSealObservation{point, confirmations, amount, gotScript, true}, nil
}

type grantFunds struct {
	tx      *wire.MsgTx
	parents []*wire.MsgTx
	total   int64
	change  []byte
}

func grantFunding(funding GrantFunding, sealScript string, seal *rental.Point) (*grantFunds, *Failure) {
	change, err := hex.DecodeString(funding.ScriptHex)
	if err != nil || hex.EncodeToString(change) != funding.ScriptHex || !txscript.IsPayToWitnessPubKeyHash(change) {
		return nil, refuse("FUNDING_POLICY")
	}
	if funding.FeeRateSatVByte < 1 || funding.FeeRateSatVByte > 1000 {
		return nil, refuse("FEE_RATE")
	}
	if len(funding.Inputs) < 1 || len(funding.Inputs) > 16 {
		return nil, refuse("FUNDING_INPUT")
	}
	p := &grantFunds{tx: wire.NewMsgTx(2), change: change}
	seen := map[wire.OutPoint]bool{}
	for _, in := range funding.Inputs {
		if !hashValid(in.TxID) {
			return nil, refuse("FUNDING_INPUT")
		}
		if seal != nil && in.TxID == seal.TxID && in.Vout == seal.Vout {
			return nil, refuse("ISSUANCE_SPENDS_SEAL")
		}
		hash, _ := chainhash.NewHashFromStr(in.TxID)
		op := wire.OutPoint{Hash: *hash, Index: in.Vout}
		if seen[op] {
			return nil, refuse("FUNDING_DUPLICATE_INPUT")
		}
		out, ok := prevTxOutput(in.PrevTxHex, op)
		if !ok {
			return nil, refuse("FUNDING_PREVOUT")
		}
		if hex.EncodeToString(out.PkScript) == sealScript {
			return nil, refuse("FUNDING_SEAL_SCRIPT")
		}
		if !bytes.Equal(out.PkScript, change) {
			return nil, refuse("FUNDING_SCRIPT_MISMATCH")
		}
		if out.Value < 1 || out.Value > maxMoneyAtoms-p.total {
			return nil, refuse("FUNDING_AMOUNT")
		}
		p.total += out.Value
		seen[op] = true
		raw, _ := hex.DecodeString(in.PrevTxHex)
		var parent wire.MsgTx
		if parent.Deserialize(bytes.NewReader(raw)) != nil {
			return nil, refuse("FUNDING_PREVOUT")
		}
		p.parents = append(p.parents, &parent)
		input := wire.NewTxIn(&op, nil, nil)
		input.Sequence = 0xfffffffe
		p.tx.AddTxIn(input)
	}
	return p, nil
}

func (p *grantFunds) build(amount int64, scriptHex, role string, rate int64) (*GrantTransaction, *Failure) {
	script, err := hex.DecodeString(scriptHex)
	if err != nil || !amountValid(amount) {
		return nil, fail("INTERNAL")
	}
	tx := p.tx.Copy()
	tx.AddTxOut(wire.NewTxOut(amount, script))
	tx.AddTxOut(wire.NewTxOut(0, p.change))
	// Native P2WPKH only: marker/flag 2 bytes and at most 108 witness bytes
	// per input (count, strict-DER low-S signature + ALL, compressed pubkey).
	// This is the same conservative bound used by the registration planner.
	vsize := (4*tx.SerializeSizeStripped() + 2 + 108*len(tx.TxIn) + 3) / 4
	if vsize > 4096 {
		return nil, refuse("PLAN_SIZE_BOUND")
	}
	fee := int64(vsize) * rate
	change := p.total - amount - fee
	if change < minGrantChange {
		return nil, refuse("FUNDING_OR_DUST_RESERVE")
	}
	tx.TxOut[1].Value = change
	packet, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, fail("INTERNAL")
	}
	for i, parent := range p.parents {
		packet.Inputs[i].NonWitnessUtxo = parent
		packet.Inputs[i].WitnessUtxo = parent.TxOut[tx.TxIn[i].PreviousOutPoint.Index]
		packet.Inputs[i].SighashType = txscript.SigHashAll
	}
	var raw, encoded bytes.Buffer
	if tx.SerializeNoWitness(&raw) != nil || packet.Serialize(&encoded) != nil {
		return nil, fail("INTERNAL")
	}
	outputs := []GrantTxOutput{{0, amount, scriptHex, role}, {1, change, hex.EncodeToString(p.change), "change"}}
	return &GrantTransaction{
		UnsignedTxHex: hex.EncodeToString(raw.Bytes()), UnsignedTxID: tx.TxHash().String(), PSBTB64: base64.StdEncoding.EncodeToString(encoded.Bytes()), Outputs: outputs,
		FeeSat: fee, FeeRateSatVByte: rate, MaxSignedVBytes: vsize,
		RequiredReview: "Unsigned dry run only. Independently recheck current funding prevouts, ownership, fee policy, reservations, seal and exact outputs before external signing. No broadcast or live-grant authority.",
	}, nil
}
