package facade

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// The Keychain grant key (G1-K). This package never touches the secret: the
// swarma-keychain binary injects a GrantKeySigner (internal/keysign). keygen
// prints only public data. sign re-derives every digest from the draft, shows
// every field on the terminal, requires a typed confirmation and only then
// asks the signer, once per signature, each under its own authentication.
// Every returned signature is verified here against the stored public key
// before it is output.
const (
	KeychainSignSchema = "swarma-keychain/sign/1"
	PurposeSealSpend   = "seal_spend_sighash" // legacy P2PKH SIGHASH_ALL digest
	confirmWord        = "SIGN"
	maxMoneySat        = 21_000_000 * 100_000_000
)

// Terminal is where the human reads the request and answers. Production uses
// the controlling terminal (/dev/tty), never stdin or stdout.
type Terminal interface {
	Show(text string) error
	Confirm(prompt string) (bool, error)
}

// GrantKeySigner is the custody seam. Public never prompts; each Sign call
// is one authentication and one signature.
type GrantKeySigner interface {
	Keygen(label string) ([]byte, error)
	Public(label string) ([]byte, error)
	SignSchnorr(label, reason string, digest []byte) ([]byte, error)
	SignECDSA(label, reason string, hash []byte) ([]byte, error)
}

type keychainDeps struct {
	signer   GrantKeySigner // nil in swarma-identity: keychain commands refuse
	terminal func() (Terminal, error)
}

type ttyTerminal struct{ f *os.File }

func openTTY() (Terminal, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &ttyTerminal{f}, nil
}

func (t *ttyTerminal) Show(text string) error { _, err := io.WriteString(t.f, text); return err }

// Confirm accepts only the exact confirmation word on one line.
func (t *ttyTerminal) Confirm(prompt string) (bool, error) {
	if _, err := io.WriteString(t.f, prompt); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(io.LimitReader(t.f, 64)).ReadString('\n')
	if err != nil && line == "" {
		return false, err
	}
	return strings.TrimRight(line, "\r\n") == confirmWord, nil
}

// keychainCodes are the signer's error codes (internal/keychain and
// internal/keysign errors are their code strings). facade does not import
// the Keychain store, so swarma-identity links none of it.
var keychainCodes = map[string]bool{"KEY_NOT_FOUND": true, "KEY_EXISTS": true, "AUTH_CANCELED": true, "AUTH_FAILED": true, "BIOMETRY_UNAVAILABLE": true,
	"KEYCHAIN_ENTITLEMENT": true, "KEY_ITEM_INVALID": true, "KEYCHAIN_ERROR": true, "KEYCHAIN_TEST_PATH": true, "SIGNATURE_VERIFY": true}

const errItem = "KEY_ITEM_INVALID"

func keychainFailure(err error) *Failure {
	code := "KEYCHAIN_ERROR"
	if err != nil && err.Error() == "KEYCHAIN_UNSUPPORTED" {
		return fail("UNSUPPORTED_CAPABILITY")
	}
	if err != nil && keychainCodes[err.Error()] {
		code = err.Error()
	}
	return &Failure{Code: code, Message: "The Keychain operation was refused or did not complete.", Exit: 3}
}

var labelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// validLabel is keychain.ValidLabel: 1..63 bytes of [a-z0-9._-].
func validLabel(label string) bool { return labelPattern.MatchString(label) }

// KeychainPublic is the public data of one grant key. Nothing else about the
// key is ever output.
type KeychainPublic struct {
	Label            string `json:"label"`
	Network          string `json:"network"`
	XOnlyKey         string `json:"xonly_key"`
	CompressedPubkey string `json:"compressed_pubkey"`
	P2PKHAddress     string `json:"p2pkh_address"`
}

func publicOf(label, network string, pub *btcec.PublicKey) (KeychainPublic, *Failure) {
	params, ok := networkParams(network)
	if !ok {
		return KeychainPublic{}, fail("BAD_INPUT")
	}
	compressed := pub.SerializeCompressed()
	addr, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(compressed), params)
	if err != nil {
		return KeychainPublic{}, fail("INTERNAL")
	}
	return KeychainPublic{label, network, hex.EncodeToString(schnorr.SerializePubKey(pub)), hex.EncodeToString(compressed), addr.EncodeAddress()}, nil
}

// KeychainKeygen creates a new grant key under a label that must not exist
// and returns its public data only.
func KeychainKeygen(deps keychainDeps, label, network string) (*KeychainPublic, *Failure) {
	if !validLabel(label) {
		return nil, fail("BAD_INPUT")
	}
	if _, ok := networkParams(network); !ok {
		return nil, fail("BAD_INPUT")
	}
	if deps.signer == nil {
		return nil, fail("UNSUPPORTED_CAPABILITY")
	}
	compressed, err := deps.signer.Keygen(label)
	if err != nil {
		return nil, keychainFailure(err)
	}
	pub, err := btcec.ParsePubKey(compressed)
	if err != nil || len(compressed) != 33 {
		return nil, keychainFailure(errors.New(errItem))
	}
	out, f := publicOf(label, network, pub)
	if f != nil {
		return nil, f
	}
	return &out, nil
}

// KeychainSignRequest is the file-exchange input: the draft record PR 8's
// grant commands pass along, the digests they asked the landlord to sign, the
// grant-hash inputs when the grant digest is requested, and an optional seal
// spend. Every digest is re-derived from the draft before anything is shown.
type KeychainSignRequest struct {
	Schema       string          `json:"schema"`
	Draft        GrantDraft      `json:"draft"`
	ToSign       []SigningDigest `json:"to_sign"`
	ConsentEvent *rental.Event   `json:"consent_event,omitempty"`
	LandlordSig  string          `json:"landlord_sig,omitempty"`
	SealSpend    *SealSpend      `json:"seal_spend,omitempty"`
}

type KeychainSignature struct {
	Purpose   string `json:"purpose"`
	Digest    string `json:"digest"`
	Signature string `json:"signature"`
}

type SealSpendSignature struct {
	InputIndex  uint32 `json:"input_index"`
	SighashType string `json:"sighash_type"`
	Sighash     string `json:"sighash"`
	Signature   string `json:"signature"` // DER || 0x01, hex
}

type KeychainSignResult struct {
	Key        KeychainPublic      `json:"key"`
	Signatures []KeychainSignature `json:"signatures"`
	SealSpend  *SealSpendSignature `json:"seal_spend,omitempty"`
}

// signItem is one approved signature: what is shown, what is signed.
type signItem struct {
	purpose string
	digest  []byte
}

func keychainRefuse(code string) *Failure {
	return &Failure{Code: code, Message: "The signing request is refused before any key is read.", Exit: 3}
}

// bindDigests checks each requested digest against the draft. A digest that
// is not re-derived from the shown fields is refused.
func bindDigests(r KeychainSignRequest, raw []byte, xonly string) ([]signItem, *Failure) {
	d := r.Draft
	if d.IssuerKey != xonly {
		return nil, keychainRefuse("KEY_MISMATCH")
	}
	seen := map[string]bool{}
	var items []signItem
	for _, s := range r.ToSign {
		if s.Signer != "landlord" || s.Key != xonly || seen[s.Purpose] || !lowerHex(s.Digest, 32) {
			return nil, keychainRefuse("DIGEST_BINDING")
		}
		seen[s.Purpose] = true
		var want string
		switch s.Purpose {
		case PurposeContract:
			want = d.ContractSHA256
		case PurposeGrant:
			if r.ConsentEvent == nil || r.LandlordSig == "" {
				return nil, keychainRefuse("DIGEST_BINDING")
			}
			if f := checkConsent(d, raw, *r.ConsentEvent); f != nil {
				return nil, f
			}
			if !sigValid(d.IssuerKey, d.ContractSHA256, r.LandlordSig) {
				return nil, refuse("LANDLORD_SIGNATURE")
			}
			g, f := assembleGrant(d, raw, *r.ConsentEvent, r.LandlordSig, d.IssuerKey)
			if f != nil {
				return nil, f
			}
			hash, err := g.SigningHash()
			if err != nil {
				return nil, rentalRefusal(err)
			}
			want = hash
		default:
			return nil, keychainRefuse("DIGEST_BINDING")
		}
		if s.Digest != want {
			return nil, keychainRefuse("DIGEST_BINDING")
		}
		b, _ := hex.DecodeString(s.Digest)
		items = append(items, signItem{s.Purpose, b})
	}
	if r.ToSign == nil || (len(items) == 0 && r.SealSpend == nil) {
		return nil, fail("BAD_INPUT")
	}
	return items, nil
}

// printable renders free text for the terminal: control and non-ASCII bytes
// are escaped so a request cannot redraw or hide what is shown.
func printable(s string) string {
	q := strconv.QuoteToASCII(s)
	return q[1 : len(q)-1]
}

func utc(sec int64) string { return time.Unix(sec, 0).UTC().Format(time.RFC3339) }

// renderSignRequest is every field the human approves. The confirmation
// covers exactly this text.
func renderSignRequest(r KeychainSignRequest, tc TrustContract, key KeychainPublic, items []signItem, spend *sealSpendPlan) string {
	d := r.Draft
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("\n=== SWARMA GRANT KEY: SIGNING REQUEST ===\n")
	w("Keychain label     : %s\n", key.Label)
	w("Signing key x-only : %s\n", key.XOnlyKey)
	w("Signing key P2PKH  : %s\n", key.P2PKHAddress)
	w("Network            : %s (genesis %s)\n", d.Network, d.Genesis)
	w("Landlord           : %s\n", d.LandlordName)
	w("Agent              : %s\n", d.AgentName)
	w("Grantee key        : %s\n", d.GranteeKey)
	if d.GranteeName != "" {
		w("Grantee name       : %s\n", d.GranteeName)
	}
	w("Scope              : %s\n", strings.Join(d.Scope, ", "))
	w("Budget             : %d sat\n", d.Budget)
	w("Window             : %d (%s) .. %d (%s)\n", d.NotBefore, utc(d.NotBefore), d.NotAfter, utc(d.NotAfter))
	w("Contract SHA-256   : %s\n", d.ContractSHA256)
	w("Contract actions   : %s\n", printable(strings.Join(tc.Actions, ", ")))
	w("Contract repos     : %s\n", printable(strings.Join(tc.Repos, ", ")))
	w("Contract note      : \"%s\"\n", printable(tc.Note))
	w("Seal outpoint      : %s:%d\n", d.Seal.TxID, d.Seal.Vout)
	for i, it := range items {
		w("Signature %d        : BIP-340, purpose %s\n", i+1, it.purpose)
		w("  digest           : %x\n", it.digest)
	}
	if spend != nil {
		renderSealSpend(w, spend)
	}
	n := len(items)
	if spend != nil {
		n++
	}
	w("Each of the %d signature(s) asks for Touch ID separately.\n", n)
	return b.String()
}

// renderSealSpend shows every field the legacy SIGHASH_ALL digest commits
// to — transaction version, each input's outpoint and sequence, the signed
// input's prevout script (its script code), each output's value and script,
// the locktime and the sighash type — and, though the digest does not commit
// to them, each prevout's amount and script, the totals and the fee.
func renderSealSpend(w func(string, ...any), spend *sealSpendPlan) {
	tx := spend.tx
	w("Seal spend         : ECDSA P2PKH, input %d\n", spend.index)
	w("  unsigned txid    : %s\n", tx.TxHash())
	w("  version          : %d\n", tx.Version)
	w("  amounts          : %s\n", spend.amountSource)
	for i, in := range tx.TxIn {
		mark := ""
		if uint32(i) == spend.index {
			mark = "  <- SIGNED BY THIS KEY"
		}
		prev := spend.prevouts[i]
		source := "amount as supplied"
		if prev.verified {
			source = "amount from previous tx"
		}
		w("  input %-3d        : %s:%d  sequence %d (0x%08x)%s\n", i, in.PreviousOutPoint.Hash, in.PreviousOutPoint.Index, in.Sequence, in.Sequence, mark)
		w("    prevout        : %d sat (%s)  %s\n", prev.amount, source, prev.shown)
		w("    prevout script : %x\n", prev.script)
	}
	for i, out := range tx.TxOut {
		w("  output %-3d       : %d sat  %s\n", i, out.Value, spend.outputs[i])
		w("    script         : %x\n", out.PkScript)
	}
	w("  total in         : %d sat\n", spend.totalIn)
	w("  total out        : %d sat\n", spend.totalOut)
	w("  fee              : %d sat\n", spend.totalIn-spend.totalOut)
	w("  locktime         : %d\n", tx.LockTime)
	w("  sighash type     : SIGHASH_ALL (0x%02x)\n", sighashAll)
	w("  sighash          : %x\n", spend.sighash)
}

func (deps keychainDeps) sign(label string, r KeychainSignRequest) (*KeychainSignResult, string, *Failure) {
	if r.Schema != KeychainSignSchema || !validLabel(label) {
		return nil, "", fail("BAD_INPUT")
	}
	raw, tc, f := checkDraft(r.Draft)
	network := selectedNetwork(pinnedNetwork(r.Draft.Network))
	if f != nil {
		return nil, network, f
	}
	if deps.signer == nil {
		return nil, network, fail("UNSUPPORTED_CAPABILITY")
	}
	stored, err := deps.signer.Public(label)
	if err != nil {
		return nil, network, keychainFailure(err)
	}
	pub, err := btcec.ParsePubKey(stored)
	if err != nil || len(stored) != 33 {
		return nil, network, keychainFailure(errors.New(errItem))
	}
	key, f := publicOf(label, r.Draft.Network, pub)
	if f != nil {
		return nil, network, f
	}
	items, f := bindDigests(r, raw, key.XOnlyKey)
	if f != nil {
		return nil, network, f
	}
	var spend *sealSpendPlan
	if r.SealSpend != nil {
		if spend, f = planSealSpend(*r.SealSpend, r.Draft, stored, r.Draft.Network); f != nil {
			return nil, network, f
		}
	}
	term, err := deps.terminal()
	if err != nil {
		return nil, network, keychainRefuse("NO_TERMINAL")
	}
	if err := term.Show(renderSignRequest(r, tc, key, items, spend)); err != nil {
		return nil, network, keychainRefuse("NO_TERMINAL")
	}
	ok, err := term.Confirm("Type " + confirmWord + " to sign exactly the above, anything else declines: ")
	if err != nil || !ok {
		return nil, network, keychainRefuse("CONFIRMATION_DECLINED")
	}
	result := &KeychainSignResult{Key: key, Signatures: []KeychainSignature{}}
	for _, it := range items {
		reason := fmt.Sprintf("sign %s %x… for %s", it.purpose, it.digest[:8], r.Draft.LandlordName)
		sig, err := deps.signer.SignSchnorr(label, reason, it.digest)
		if err != nil {
			return nil, network, keychainFailure(err)
		}
		digest := hex.EncodeToString(it.digest)
		if !rental.VerifySignature(key.XOnlyKey, digest, hex.EncodeToString(sig)) {
			return nil, network, keychainRefuse("SIGNATURE_VERIFY")
		}
		result.Signatures = append(result.Signatures, KeychainSignature{it.purpose, digest, hex.EncodeToString(sig)})
	}
	if spend != nil {
		reason := fmt.Sprintf("sign seal spend %s input %d for %s", spend.tx.TxHash(), spend.index, r.Draft.LandlordName)
		der, err := deps.signer.SignECDSA(label, reason, spend.sighash)
		if err != nil {
			return nil, network, keychainFailure(err)
		}
		full := append(append([]byte{}, der...), sighashAll)
		if !spend.verify(full, pub) {
			return nil, network, keychainRefuse("SIGNATURE_VERIFY")
		}
		result.SealSpend = &SealSpendSignature{spend.index, "ALL", hex.EncodeToString(spend.sighash), hex.EncodeToString(full)}
	}
	return result, network, nil
}

// keychainSignCommand runs keychain sign with its file input.
func keychainSignCommand(deps keychainDeps, label, requestPath string) (string, any, *Failure) {
	var r KeychainSignRequest
	if f := inputFile(requestPath, &r); f != nil {
		return "", nil, f
	}
	result, network, f := deps.sign(label, r)
	if f != nil {
		return network, nil, f
	}
	return network, result, nil
}

// assembleGrant is the v3 grant SignGrant builds from a checked draft, the
// grantee's consent event and the landlord's contract signature.
func assembleGrant(d GrantDraft, raw []byte, consent rental.Event, landlordSig, issuer string) (rental.Grant, *Failure) {
	g := rental.Grant{Version: 3, Network: d.Network, Genesis: d.Genesis, AgentName: d.AgentName, LandlordName: d.LandlordName, IssuerKey: issuer, GranteeKey: d.GranteeKey, GranteeName: d.GranteeName, ContractSHA256: d.ContractSHA256, Scope: slices.Clone(d.Scope), NotBefore: d.NotBefore, NotAfter: d.NotAfter, Seal: d.Seal, Consent: rental.GrantConsent{ContractSHA256: d.ContractSHA256, ConsentEvent: consent, LandlordSig: landlordSig}}
	if d.Budget != 0 {
		budget := d.Budget
		g.Budget = &budget
	}
	if code := bindTrustContract(raw, trustGrantView{g.Network, g.AgentName, g.LandlordName, g.GranteeKey, g.ContractSHA256, g.Scope, g.BudgetSat(), g.NotBefore, g.NotAfter, g.Consent.ConsentEvent.Tags}); code != "" {
		return rental.Grant{}, refuse(code)
	}
	return g, nil
}
