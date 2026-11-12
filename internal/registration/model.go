// Package registration constructs unsigned, wallet-free Namecoin registration
// plans. Public construction grants no signing, custody or broadcast authority.
package registration

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const (
	PlanSchema     = "swarma-identity/namecoin-registration-plan/2"
	MainnetGenesis = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"
	RegtestGenesis = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
	nameAmount     = uint64(1000000)
	maxMoney       = uint64(21000000 * 100000000)
)

var (
	ErrInput   = errors.New("invalid registration input")
	ErrFunding = errors.New("registration funding mismatch")
	ErrPolicy  = errors.New("registration policy refused")
	ErrValue   = errors.New("registration value refused")
	ErrParents = errors.New("registration parent reference mismatch")
)

// Profile is selected by the trusted caller, never from request network fields.
// Regtest is admitted only by explicitly selecting its immutable fixture profile.
type Profile struct {
	Network, Genesis string
	Policy           Policy
}

type Policy struct {
	Revision                string `json:"revision"`
	PerTxFeeCapAtoms        string `json:"per_tx_fee_cap_atoms"`
	TotalFeeCapAtoms        string `json:"total_fee_cap_atoms"`
	MinFeeRateAtomsPerKVB   string `json:"min_fee_rate_atoms_per_kvb"`
	MaxFeeRateAtomsPerKVB   string `json:"max_fee_rate_atoms_per_kvb"`
	DustRelayFeeAtomsPerKVB string `json:"dust_relay_fee_atoms_per_kvb"`
	CreatedAt               uint64 `json:"created_at"`
	ReleaseNotAfter         uint64 `json:"release_not_after"`
	FinalConfirmations      uint32 `json:"final_confirmations"`
	ReleaseMode             string `json:"release_mode"`
}

type Funding struct {
	TxHex, TxID string
	Vout        uint32
	Path        string
}
type Registration struct {
	Name, RandHex, NameOutputPath string
	FixedValue                    []byte
}
type ReservationInput struct {
	Funding       Funding
	Registrations [2]Registration
	ChangePaths   [2]string
	Fees          [2]uint64
}

// ParentReference carries public linkage only. Its identifiers/hash must later
// match the signer's independently protected completed results. Caller JSON and
// a public hash do not prove completion, presence or receipt authenticity.
type ParentReference struct {
	Slot             string `json:"slot"`
	RequestID        string `json:"request_id"`
	SittingID        string `json:"sitting_id"`
	UnsignedTxID     string `json:"unsigned_txid"`
	SignedPSBTSHA256 string `json:"signed_psbt_sha256"`
}
type RevealInput struct {
	Parents     [2]ParentReference
	ValuesPin   []byte
	ChangePaths [2]string
	Fees        [2]uint64
}

type accountPin struct {
	Schema            string `json:"schema"`
	Group             string `json:"group"`
	Account           string `json:"account"`
	AccountXPub       string `json:"account_xpub"`
	MasterFingerprint string `json:"master_fingerprint"`
	AccountPath       string `json:"account_path"`
}
type planBase struct {
	Schema           string `json:"schema"`
	Kind             string `json:"kind"`
	Network          string `json:"network"`
	Genesis          string `json:"genesis"`
	Group            string `json:"group"`
	Account          string `json:"account"`
	AccountPinSHA256 string `json:"account_pin_sha256"`
}
type planFunding struct {
	TxHex string `json:"tx_hex"`
	TxID  string `json:"txid"`
	Vout  uint32 `json:"vout"`
}
type futureValue struct {
	State       string `json:"state"`
	ValueHex    string `json:"value_hex,omitempty"`
	ValueSHA256 string `json:"value_sha256,omitempty"`
}
type reservedName struct {
	NameHex         string      `json:"name_hex"`
	RandHex         string      `json:"rand_hex"`
	NameOutputPath  string      `json:"name_output_path"`
	ReservationSlot string      `json:"reservation_slot"`
	RevealSlot      string      `json:"reveal_slot"`
	FutureValue     futureValue `json:"future_value"`
}
type concreteName struct {
	NameHex         string `json:"name_hex"`
	ValueHex        string `json:"value_hex"`
	ValueSHA256     string `json:"value_sha256"`
	RandHex         string `json:"rand_hex"`
	NameOutputPath  string `json:"name_output_path"`
	ReservationSlot string `json:"reservation_slot"`
	RevealSlot      string `json:"reveal_slot"`
}
type planInput struct {
	PrevTxHex string `json:"prev_tx_hex"`
	TxID      string `json:"txid"`
	Vout      uint32 `json:"vout"`
	Path      string `json:"path"`
}
type planOutput struct {
	Vout uint32 `json:"vout"`
	Path string `json:"path"`
	Kind string `json:"kind"`
}
type planTransaction struct {
	Slot          string       `json:"slot"`
	UnsignedTxHex string       `json:"unsigned_tx_hex"`
	UnsignedTxID  string       `json:"unsigned_txid"`
	Inputs        []planInput  `json:"inputs"`
	Outputs       []planOutput `json:"outputs"`
	FeeAtoms      string       `json:"fee_atoms"`
}
type reservationManifest struct {
	planBase
	Funding       planFunding       `json:"funding"`
	Registrations []reservedName    `json:"registrations"`
	Transactions  []planTransaction `json:"transactions"`
	Policy        Policy            `json:"policy"`
}
type revealManifest struct {
	planBase
	ReservationPlanSHA256 string            `json:"reservation_plan_sha256"`
	ParentResults         []ParentReference `json:"parent_results"`
	Registrations         []concreteName    `json:"registrations"`
	Transactions          []planTransaction `json:"transactions"`
	Policy                Policy            `json:"policy"`
}

type PreparedTransaction struct {
	Slot, UnsignedTxHex, TxID, PSBT string
	// The signed interval is a conservative plan bound, not an observation of
	// a finalized transaction. Release must recheck its actual signed size.
	UnsignedVSize, SignedVSizeMin, SignedVSizeMax uint32
}

// Plan retains immutable construction state. Copies returned to callers cannot
// change the predecessor used to construct a reveal successor.
type Plan struct {
	raw          []byte
	digest       string
	transactions []PreparedTransaction
	reservation  *reservationManifest
}

func (p *Plan) Manifest() []byte { return append([]byte(nil), p.raw...) }
func (p *Plan) Hash() string     { return p.digest }
func (p *Plan) Transactions() []PreparedTransaction {
	return append([]PreparedTransaction(nil), p.transactions...)
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func freeze(v any, txs []PreparedTransaction) (*Plan, error) {
	b, e := json.Marshal(v)
	if e != nil || len(b) > 1<<20 {
		return nil, ErrInput
	}
	frame := append([]byte(PlanSchema), 0)
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(b)))
	frame = append(frame, b...)
	return &Plan{raw: b, digest: digest(frame), transactions: txs}, nil
}
