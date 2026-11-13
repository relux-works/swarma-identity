package facade

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"strings"

	reg "github.com/relux-works/swarma-identity/internal/registration"
)

const regPrefix = "swarma-identity/registration-"

type regProfile struct {
	Schema  string     `json:"schema"`
	Network string     `json:"network"`
	Genesis string     `json:"genesis"`
	Policy  reg.Policy `json:"policy"`
}
type regPin struct {
	Schema      string `json:"schema"`
	Group       string `json:"group"`
	Account     string `json:"account"`
	XPub        string `json:"account_xpub"`
	Fingerprint string `json:"master_fingerprint"`
	Path        string `json:"account_path"`
}
type regFunding struct {
	Hex  string `json:"tx_hex"`
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
	Path string `json:"path"`
}
type regName struct {
	Name  string `json:"name"`
	Path  string `json:"name_output_path"`
	Value string `json:"fixed_value_hex"`
}
type regSavedName struct {
	Name  string `json:"name"`
	Path  string `json:"name_output_path"`
	Value string `json:"fixed_value_hex"`
	Rand  string `json:"rand_hex"`
}
type regReserve struct {
	Schema  string     `json:"schema"`
	Funding regFunding `json:"funding"`
	Names   []regName  `json:"registrations"`
	Change  []string   `json:"change_paths"`
	Fees    []string   `json:"fees_atoms"`
}
type regReservationState struct {
	Schema     string         `json:"schema"`
	PreparedAt uint64         `json:"prepared_at"`
	Funding    regFunding     `json:"funding"`
	Names      []regSavedName `json:"registrations"`
	Change     []string       `json:"change_paths"`
	Fees       []string       `json:"fees_atoms"`
}
type regParent struct {
	Bundle     string `json:"request_bundle"`
	BundleHash string `json:"request_bundle_sha256"`
	Result     string `json:"result"`
	ResultHash string `json:"result_sha256"`
	Stdout     string `json:"stdout"`
	StdoutHash string `json:"stdout_sha256"`
	Exit       uint8  `json:"process_exit"`
}
type regReveal struct {
	Schema          string      `json:"schema"`
	Reservation     string      `json:"reservation_bundle"`
	ReservationHash string      `json:"reservation_bundle_sha256"`
	Parents         []regParent `json:"parents"`
	Pin             string      `json:"reveal_values_pin"`
	PinHash         string      `json:"reveal_values_pin_sha256"`
	Change          []string    `json:"change_paths"`
	Fees            []string    `json:"fees_atoms"`
}
type regRevealState struct {
	Schema          string      `json:"schema"`
	Reservation     string      `json:"reservation_bundle"`
	ReservationHash string      `json:"reservation_bundle_sha256"`
	Parents         []regParent `json:"parents"`
	Pin             string      `json:"reveal_values_pin"`
	PinHash         string      `json:"reveal_values_pin_sha256"`
	Change          []string    `json:"change_paths"`
	Fees            []string    `json:"fees_atoms"`
	PreparedAt      uint64      `json:"prepared_at"`
}
type regRequest struct {
	Schema   string `json:"schema"`
	Plan     string `json:"plan_bundle"`
	PlanHash string `json:"plan_bundle_sha256"`
	Slot     string `json:"slot"`
	ValidFor uint64 `json:"valid_for_seconds"`
}
type regRequestState struct {
	Schema      string `json:"schema"`
	Plan        string `json:"plan_bundle"`
	PlanHash    string `json:"plan_bundle_sha256"`
	Slot        string `json:"slot"`
	PreparedAt  uint64 `json:"prepared_at"`
	RequestID   string `json:"request_id"`
	SittingID   string `json:"sitting_id"`
	ExpiresAt   uint64 `json:"expires_at"`
	RequestHash string `json:"request_sha256"`
	ReviewHash  string `json:"review_sha256"`
}
type regCheck struct {
	Schema     string `json:"schema"`
	Bundle     string `json:"request_bundle"`
	BundleHash string `json:"request_bundle_sha256"`
	Result     string `json:"result"`
	ResultHash string `json:"result_sha256"`
	Stdout     string `json:"stdout"`
	StdoutHash string `json:"stdout_sha256"`
	Exit       uint8  `json:"process_exit"`
}
type regPublicResult struct {
	Schema     string `json:"schema"`
	TxID       string `json:"txid"`
	SignedHash string `json:"signed_psbt_sha256"`
	ResultHash string `json:"result_sha256"`
	Fee        string `json:"fee_atoms"`
	Weight     uint32 `json:"weight"`
	VSize      uint32 `json:"vsize"`
	Sequence   uint64 `json:"reported_journal_sequence"`
	Head       string `json:"reported_journal_head_sha256"`
}
type regFile struct {
	Name string `json:"name"`
	Size uint64 `json:"size_bytes"`
	Hash string `json:"sha256"`
}
type regBundle struct {
	Schema      string    `json:"schema"`
	Kind        string    `json:"kind"`
	ProfileHash string    `json:"profile_sha256"`
	PinHash     string    `json:"account_pin_sha256"`
	Files       []regFile `json:"files"`
}
type regSuccess struct {
	Hash  string    `json:"bundle_sha256"`
	Files []regFile `json:"files"`
}
type regTransaction struct {
	Slot     string `json:"slot"`
	TxID     string `json:"txid"`
	File     string `json:"psbt_file"`
	Unsigned uint32 `json:"unsigned_vsize"`
	Min      uint32 `json:"signed_vsize_min"`
	Max      uint32 `json:"signed_vsize_max"`
}
type regTransactions struct {
	Schema       string           `json:"schema"`
	Transactions []regTransaction `json:"transactions"`
}

var regPayloads = map[string][]string{
	"account-pin":    {"account-pin.json"},
	"reservation":    {"profile.json", "account-pin.json", "funding.hex", "reservation-state.json", "reservation-manifest.json", "A.psbt", "B.psbt", "transaction-index.json"},
	"reveal":         {"profile.json", "account-pin.json", "reveal-state.json", "reveal-values-pin.json", "reveal-manifest.json", "C.psbt", "D.psbt", "transaction-index.json"},
	"request":        {"profile.json", "account-pin.json", "request-state.json", "request.json", "review-frame.bin"},
	"checked-result": {"profile.json", "account-pin.json", "verification-state.json", "verified-transaction.hex", "public-result.json"},
}

func regCap(name string) int {
	switch name {
	case "profile.json":
		return 4 << 20
	case "account-pin.json", "reveal-values-pin.json":
		return 16384
	case "funding.hex", "request.json", "A.psbt", "B.psbt", "C.psbt", "D.psbt":
		return 8 << 20
	case "reservation-manifest.json", "reveal-manifest.json":
		return 1 << 20
	case "review-frame.bin":
		return 2 << 20
	case "verified-transaction.hex":
		return 8 << 20
	default:
		return 65536
	}
}
func regDigest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func regHex(s string, n int) bool {
	if len(s) != 2*n || strings.ToLower(s) != s {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}
func regDecimal(s string) (uint64, bool) {
	n, e := strconv.ParseUint(s, 10, 64)
	return n, e == nil && strconv.FormatUint(n, 10) == s
}
func regIdentity(s, purpose string) bool {
	parts := strings.Split(s, "/")
	if len(parts) != 2 || len(parts[0]) < 1 || len(parts[0]) > 40 || !strings.HasPrefix(parts[1], purpose+"@") {
		return false
	}
	for _, c := range parts[0] {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	n, e := strconv.ParseUint(strings.TrimPrefix(parts[1], purpose+"@"), 10, 31)
	return e == nil && n > 0 && strconv.FormatUint(n, 10) == strings.TrimPrefix(parts[1], purpose+"@")
}
func regDecode(b []byte, v any) bool {
	return len(b) > 0 && validateJSON(b) == nil && closedObject(b, reflect.TypeOf(v).Elem()) == nil && json.Unmarshal(b, v) == nil
}
func regCanonical(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic("non-serializable registration record")
	}
	return append(b, '\n')
}
func regState(b []byte, v any, schema string) bool {
	if len(b) > 65536 || !regDecode(b, v) {
		return false
	}
	return string(regCanonical(v)) == string(b) && reflect.ValueOf(v).Elem().FieldByName("Schema").String() == regPrefix+schema+"/1"
}
func regTime(n uint64) bool { return n <= math.MaxInt64 }
func regFailure(code string) *Failure {
	f := fail(code)
	switch code {
	case "REGISTRATION_POLICY_REFUSED":
		f.Exit = 3
		f.Message = "The registration policy was refused."
	case "REGISTRATION_PARENT_REFUSED":
		f.Exit = 3
		f.Message = "The registration predecessor context was refused."
	case "REGISTRATION_RESULT_REFUSED":
		f.Exit = 3
		f.Message = "The registration result was refused."
	case "REGISTRATION_FILES":
		f.Exit = 1
		f.Message = "The registration files could not be admitted or committed."
	}
	return f
}
