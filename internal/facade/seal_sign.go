package facade

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/relux-works/swarma-identity/internal/keypolicy"
)

func (journal *sealJournal) signingTransaction() (*wire.MsgTx, [][]byte, *Failure) {
	raw, _ := hex.DecodeString(journal.Plan.UnsignedTxHex)
	transaction := wire.NewMsgTx(2)
	if transaction.DeserializeNoWitness(bytes.NewReader(raw)) != nil {
		return nil, nil, refuse("SEAL_SIGNED_TRANSACTION")
	}
	prevouts := txscript.NewMultiPrevOutFetcher(nil)
	for index, input := range journal.Request.Funding.Inputs {
		output, ok := prevTxOutput(input.PrevTxHex, transaction.TxIn[index].PreviousOutPoint)
		if !ok {
			return nil, nil, refuse("FUNDING_PREVOUT")
		}
		prevouts.AddPrevOut(transaction.TxIn[index].PreviousOutPoint, output)
	}
	hashes := txscript.NewTxSigHashes(transaction, prevouts)
	public, _ := hex.DecodeString(journal.Request.FundingPubkey)
	var digests [][]byte
	for index, input := range transaction.TxIn {
		output := prevouts.FetchPrevOutput(input.PreviousOutPoint)
		digest, err := txscript.CalcWitnessSigHash(p2pkhScript(public), hashes, txscript.SigHashAll, transaction, index, output.Value)
		if err != nil {
			return nil, nil, refuse("SEAL_SIGNED_TRANSACTION")
		}
		digests = append(digests, digest)
	}
	return transaction, digests, nil
}

func (journal *sealJournal) verifySigned() *Failure {
	raw, err := hex.DecodeString(journal.SignedTxHex)
	if err != nil || len(raw) > 65536 || hex.EncodeToString(raw) != journal.SignedTxHex {
		return refuse("SEAL_SIGNED_TRANSACTION")
	}
	transaction := wire.NewMsgTx(2)
	if transaction.Deserialize(bytes.NewReader(raw)) != nil {
		return refuse("SEAL_SIGNED_TRANSACTION")
	}
	var encoded, unsigned bytes.Buffer
	if transaction.Serialize(&encoded) != nil || !bytes.Equal(raw, encoded.Bytes()) || transaction.SerializeNoWitness(&unsigned) != nil || hex.EncodeToString(unsigned.Bytes()) != journal.Plan.UnsignedTxHex {
		return refuse("SEAL_SIGNED_TRANSACTION")
	}
	_, digests, failure := journal.signingTransaction()
	if failure != nil {
		return failure
	}
	publicBytes, _ := hex.DecodeString(journal.Request.FundingPubkey)
	public, _ := btcec.ParsePubKey(publicBytes)
	for index, input := range transaction.TxIn {
		if len(input.SignatureScript) != 0 || len(input.Witness) != 2 || !bytes.Equal(input.Witness[1], publicBytes) {
			return refuse("SEAL_SIGNED_TRANSACTION")
		}
		signature := input.Witness[0]
		if len(signature) < 2 || signature[len(signature)-1] != byte(txscript.SigHashAll) {
			return refuse("SEAL_SIGNED_TRANSACTION")
		}
		der := signature[:len(signature)-1]
		parsed, err := ecdsa.ParseDERSignature(der)
		if err != nil || !bytes.Equal(parsed.Serialize(), der) || !parsed.Verify(digests[index], public) {
			return refuse("SIGNATURE_VERIFY")
		}
	}
	weight := transaction.SerializeSizeStripped()*3 + transaction.SerializeSize()
	vsize := (weight + 3) / 4
	if vsize > journal.Plan.MaxSignedVBytes || journal.Plan.FeeSat > int64(vsize)*journal.Request.MaxFeeRateSatVByte {
		return refuse("SEAL_FEE_CAP")
	}
	return nil
}

func (journal *sealJournal) sign(deps keychainDeps, label string) *Failure {
	if deps.signer == nil {
		return fail("UNSUPPORTED_CAPABILITY")
	}
	if !validLabel(label) {
		return fail("BAD_INPUT")
	}
	if failure := refuseStaticGateKeyForGrant(label); failure != nil {
		return failure
	}
	if journal.State != "planned" {
		return nil
	}
	public, err := deps.signer.Public(label)
	if err != nil {
		return keychainFailure(err)
	}
	if hex.EncodeToString(public) != journal.Request.FundingPubkey {
		return refuse("FUNDING_NOT_OWNED")
	}
	access, inspectable, err := deps.signer.Access(label)
	if err != nil {
		return keychainFailure(err)
	}
	if _, err := access.SecurityFlags(); err != nil {
		return refuse("SEAL_SIGNER_POLICY")
	}
	transaction, digests, failure := journal.signingTransaction()
	if failure != nil {
		return failure
	}
	terminal, err := deps.terminal()
	if err != nil {
		return keychainRefuse("NO_TERMINAL")
	}
	if closer, ok := terminal.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	var display strings.Builder
	fmt.Fprintf(&display, "\n=== GRANT SEAL CREATION ===\n%s\nNetwork: %s (genesis %s)\nFunding key: %s\nLabel: %s\nAccess: %s\nPSBTv0: %s\n", sealSummary(journal.GrantID, &journal.Plan), journal.Request.Network, pinnedGenesis(journal.Request.Network), journal.Request.FundingPubkey, printable(label), access, journal.Plan.PSBTB64)
	if !inspectable {
		fmt.Fprintln(&display, "Native ACL flags: unavailable through public Security APIs; authenticated policy metadata is checked before signing.")
	}
	if access == keypolicy.OrPasscode {
		fmt.Fprintln(&display, "Each input asks for biometry or the device passcode/password separately.")
	} else {
		fmt.Fprintln(&display, "Each input asks for Touch ID separately.")
	}
	for index, input := range transaction.TxIn {
		prevout, _ := prevTxOutput(journal.Request.Funding.Inputs[index].PrevTxHex, input.PreviousOutPoint)
		fmt.Fprintf(&display, "Input %d: %s:%d; %d atoms; script %x; sequence %d\n", index, input.PreviousOutPoint.Hash, input.PreviousOutPoint.Index, prevout.Value, prevout.PkScript, input.Sequence)
	}
	for _, output := range journal.Plan.Outputs {
		fmt.Fprintf(&display, "Output %d (%s): %d atoms; script %s\n", output.Vout, output.Role, output.AmountSat, output.ScriptHex)
	}
	fmt.Fprintf(&display, "Fee: %d atoms; cap %d atoms and %d atoms/vbyte\nVersion: %d; locktime: %d; SIGHASH_ALL without ANYONECANPAY\nNo broadcast is authorized by signing.\n", journal.Plan.FeeSat, journal.Request.MaxFeeSat, journal.Request.MaxFeeRateSatVByte, transaction.Version, transaction.LockTime)
	fmt.Fprintf(&display, "Operator confirmation floor: %d (local policy, not a signed v3 grant member)\n", journal.Request.MinConfirmations)
	if terminal.Show(display.String()) != nil {
		return keychainRefuse("NO_TERMINAL")
	}
	approved, err := terminal.Confirm("Type SIGN to sign exactly the above, anything else declines: ")
	if err != nil || !approved {
		return keychainRefuse("CONFIRMATION_DECLINED")
	}
	for index, digest := range digests {
		signature, err := deps.signer.SignECDSA(label, fmt.Sprintf("Create grant seal %s input %d [access: %s]", journal.Plan.UnsignedTxID, index, access), digest, access)
		if err != nil {
			return keychainFailure(err)
		}
		transaction.TxIn[index].Witness = wire.TxWitness{append(append([]byte{}, signature...), byte(txscript.SigHashAll)), append([]byte{}, public...)}
	}
	var raw bytes.Buffer
	if transaction.Serialize(&raw) != nil {
		return fail("INTERNAL")
	}
	journal.SignedTxHex = hex.EncodeToString(raw.Bytes())
	if failure := journal.verifySigned(); failure != nil {
		return failure
	}
	journal.State = "signed"
	return journal.save()
}
