package registration

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrResult = errors.New("registration signer result refused")

type inputSignature struct {
	Index     uint32 `json:"index"`
	Pubkey    string `json:"pubkey"`
	Algorithm string `json:"algorithm"`
	Encoding  string `json:"encoding"`
	Sighash   string `json:"sighash"`
	Signature string `json:"signature"`
}
type publicReceipt struct {
	Schema                string           `json:"schema"`
	Status                string           `json:"status"`
	RequestID             string           `json:"request_id"`
	SittingID             string           `json:"sitting_id"`
	Slot                  string           `json:"slot"`
	PlanSHA256            string           `json:"plan_sha256"`
	ReservationPlanSHA256 string           `json:"reservation_plan_sha256"`
	ReviewSHA256          string           `json:"review_sha256"`
	Network               string           `json:"network"`
	Group                 string           `json:"group"`
	Account               string           `json:"account"`
	AccountPinSHA256      string           `json:"account_pin_sha256"`
	UnsignedTxID          string           `json:"unsigned_txid"`
	SignedPSBTSHA256      string           `json:"signed_psbt_sha256"`
	InputSignatures       []inputSignature `json:"input_signatures"`
	JournalSequence       uint64           `json:"journal_sequence"`
	JournalHeadSHA256     string           `json:"journal_head_sha256"`
}

// PublicResult deliberately calls the journal fields reported: untrusted JSON
// and an exact ack hash cannot authenticate a protected journal or presence.
type PublicResult struct {
	Transaction               VerifiedTransaction
	ResultSHA256              string
	ReportedJournalSequence   uint64
	ReportedJournalHeadSHA256 string
}

// CheckResult checks a complete result file and the exact success stdout from
// a zero-exit call. It performs public verification only and must not be used
// as custody authentication or permission to release a signed transaction.
// Original request expiry is not re-applied to a retained completed result.
func (p *Planner) CheckResult(request *SigningRequest, result, stdout []byte, exit int) (*PublicResult, error) {
	if request == nil || exit != 0 || len(result) == 0 || len(result) > 6<<20 {
		return nil, ErrResult
	}
	rawHash := digest(result)
	ack := fmt.Sprintf("{\"schema\":\"keyvault-namecoin-psbt-ack/2\",\"status\":\"SIGNED\",\"result_sha256\":\"%s\"}\n", rawHash)
	if !bytes.Equal(stdout, []byte(ack)) {
		return nil, ErrResult
	}
	obj, e := closedObject(result, 6<<20, "schema", "signed_psbt", "receipt")
	if e != nil || len(obj) != 3 {
		return nil, ErrResult
	}
	var schema, signed string
	if json.Unmarshal(obj["schema"], &schema) != nil || schema != "keyvault-namecoin-psbt-result/2" || json.Unmarshal(obj["signed_psbt"], &signed) != nil {
		return nil, ErrResult
	}
	fields, e := object(obj["receipt"], "schema", "status", "request_id", "sitting_id", "slot", "plan_sha256", "reservation_plan_sha256", "review_sha256", "network", "group", "account", "account_pin_sha256", "unsigned_txid", "signed_psbt_sha256", "input_signatures", "journal_sequence", "journal_head_sha256")
	if e != nil || len(fields) != 17 {
		return nil, ErrResult
	}
	var receipt publicReceipt
	if json.Unmarshal(obj["receipt"], &receipt) != nil || receipt.JournalSequence == 0 || !hexSize(receipt.JournalHeadSHA256, 32) {
		return nil, ErrResult
	}
	var signatures []json.RawMessage
	if json.Unmarshal(fields["input_signatures"], &signatures) != nil || len(signatures) > 128 {
		return nil, ErrResult
	}
	for _, sig := range signatures {
		m, e := object(sig, "index", "pubkey", "algorithm", "encoding", "sighash", "signature")
		if e != nil || len(m) != 6 {
			return nil, ErrResult
		}
	}
	verified, e := p.VerifySigned(request.plan, request.data.Slot, request.data.PSBT, signed)
	if e != nil {
		return nil, e
	}
	d := request.data
	if receipt.Schema != "keyvault-namecoin-psbt-receipt/2" || receipt.Status != "SIGNED" || receipt.RequestID != d.RequestID || receipt.SittingID != d.SittingID || receipt.Slot != d.Slot || receipt.PlanSHA256 != d.PlanSHA256 || receipt.ReservationPlanSHA256 != d.ReservationPlanSHA256 || receipt.ReviewSHA256 != request.ReviewSHA256() || receipt.Network != p.profile.Network || receipt.Group != p.pin.Group || receipt.Account != p.pin.Account || receipt.AccountPinSHA256 != p.pinHash || receipt.UnsignedTxID != verified.TxID || receipt.SignedPSBTSHA256 != verified.SignedPSBTSHA256 {
		return nil, ErrResult
	}
	packet, e := readPSBT(signed)
	if e != nil || len(receipt.InputSignatures) != len(packet.inputs) {
		return nil, ErrResult
	}
	for i, sig := range receipt.InputSignatures {
		if sig.Index != uint32(i) || sig.Algorithm != "secp256k1-ecdsa" || sig.Encoding != "strict-der-low-s" || sig.Sighash != "ALL" || !hexSize(sig.Pubkey, 33) || !hexSize(sig.Signature, len(sig.Signature)/2) {
			return nil, ErrResult
		}
		pub, _ := hex.DecodeString(sig.Pubkey)
		der, _ := hex.DecodeString(sig.Signature)
		if !bytes.Equal(packet.inputs[i][string(append([]byte{2}, pub...))], append(der, 1)) {
			return nil, ErrResult
		}
	}
	return &PublicResult{Transaction: *verified, ResultSHA256: rawHash, ReportedJournalSequence: receipt.JournalSequence, ReportedJournalHeadSHA256: receipt.JournalHeadSHA256}, nil
}
