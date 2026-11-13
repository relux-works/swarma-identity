package facade

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	reg "github.com/relux-works/swarma-identity/internal/registration"
)

func regFlags(command string, args []string) (map[string]string, *Failure) {
	required := []string{"request", "out-dir", "json"}
	if command != "registration account-pin" {
		required = append(required, "profile", "profile-sha256", "account-pin", "account-pin-sha256")
	}
	allowed := map[string]bool{}
	for _, name := range required {
		allowed["--"+name] = true
	}
	values := map[string]string{}
	for i := 0; i < len(args); i++ {
		flag := args[i]
		if !allowed[flag] {
			return nil, regFailure("BAD_INPUT")
		}
		if _, seen := values[flag]; seen {
			return nil, regFailure("BAD_INPUT")
		}
		if flag == "--json" {
			values[flag] = "true"
			continue
		}
		i++
		if i >= len(args) || strings.HasPrefix(args[i], "--") {
			return nil, regFailure("BAD_INPUT")
		}
		values[flag] = args[i]
	}
	if len(values) != len(required) {
		return nil, regFailure("BAD_INPUT")
	}
	for flag, value := range values {
		if flag == "--json" {
			continue
		}
		if strings.HasSuffix(flag, "-sha256") {
			if !regHex(value, 32) {
				return nil, regFailure("BAD_INPUT")
			}
		} else if !regAbs(value) {
			return nil, regFailure("BAD_INPUT")
		}
	}
	return values, nil
}
func regProfileAdmission(raw []byte) (regProfile, *Failure) {
	var profile regProfile
	if !regDecode(raw, &profile) || profile.Schema != regPrefix+"profile/1" || !regTime(profile.Policy.CreatedAt) || !regTime(profile.Policy.ReleaseNotAfter) {
		return profile, regFailure("BAD_INPUT")
	}
	p := profile.Policy
	values := []string{p.PerTxFeeCapAtoms, p.TotalFeeCapAtoms, p.MinFeeRateAtomsPerKVB, p.MaxFeeRateAtomsPerKVB, p.DustRelayFeeAtomsPerKVB}
	numbers := make([]uint64, 5)
	for i, v := range values {
		n, ok := regDecimal(v)
		if !ok {
			return profile, regFailure("BAD_INPUT")
		}
		numbers[i] = n
	}
	valid := (profile.Network == "namecoin-mainnet" && profile.Genesis == reg.MainnetGenesis) || (profile.Network == "namecoin-regtest" && profile.Genesis == reg.RegtestGenesis)
	valid = valid && len(p.Revision) > 0 && len(p.Revision) <= 128 && utf8.ValidString(p.Revision) && p.ReleaseNotAfter > p.CreatedAt && p.ReleaseNotAfter-p.CreatedAt <= 86400 && p.FinalConfirmations > 0 && (p.ReleaseMode == "all-four-before-release" || p.ReleaseMode == "two-stage")
	for _, c := range p.Revision {
		valid = valid && c >= 32 && c != 127
	}
	for _, n := range numbers {
		valid = valid && n > 0 && n <= 21000000*100000000
	}
	valid = valid && numbers[0] <= 100000 && numbers[1] <= 400000 && numbers[1] >= numbers[0] && numbers[2] <= numbers[3]
	if !valid {
		return profile, regFailure("REGISTRATION_POLICY_REFUSED")
	}
	return profile, nil
}
func regPinAdmission(raw []byte, schema string) (regPin, *Failure) {
	var pin regPin
	if !regDecode(raw, &pin) || pin.Schema != schema || !regIdentity(pin.Group, "recovery") || !regIdentity(pin.Account, "namecoin") || !regHex(pin.Fingerprint, 4) || pin.Path != "m/84h/7h/0h" || len(pin.XPub) > 120 {
		return pin, regFailure("BAD_INPUT")
	}
	decoded := base58.Decode(pin.XPub)
	if len(decoded) != 82 || binary.BigEndian.Uint32(decoded[:4]) != 0x0488b21e || decoded[4] != 3 || binary.BigEndian.Uint32(decoded[9:13]) != 1<<31 || (decoded[45] != 2 && decoded[45] != 3) {
		return pin, regFailure("BAD_INPUT")
	}
	key, e := hdkeychain.NewKeyFromString(pin.XPub)
	if e != nil || key.IsPrivate() {
		return pin, regFailure("BAD_INPUT")
	}
	if _, e = key.ECPubKey(); e != nil {
		return pin, regFailure("BAD_INPUT")
	}
	return pin, nil
}
func regLibraryFailure(e error) *Failure {
	switch {
	case errors.Is(e, reg.ErrPolicy):
		return regFailure("REGISTRATION_POLICY_REFUSED")
	case errors.Is(e, reg.ErrParents):
		return regFailure("REGISTRATION_PARENT_REFUSED")
	case errors.Is(e, reg.ErrResult), errors.Is(e, reg.ErrSignature):
		return regFailure("REGISTRATION_RESULT_REFUSED")
	case errors.Is(e, reg.ErrInput), errors.Is(e, reg.ErrFunding), errors.Is(e, reg.ErrValue), errors.Is(e, reg.ErrPSBT):
		return regFailure("BAD_INPUT")
	default:
		return regFailure("INTERNAL")
	}
}
func regFreshTime(profile regProfile) (uint64, *Failure) {
	now := time.Now().Unix()
	if now < 0 || uint64(now) < profile.Policy.CreatedAt || uint64(now) >= profile.Policy.ReleaseNotAfter {
		return 0, regFailure("REGISTRATION_POLICY_REFUSED")
	}
	return uint64(now), nil
}
func regRandom(size int) (string, *Failure) {
	b := make([]byte, size)
	if _, e := rand.Read(b); e != nil {
		return "", regFailure("INTERNAL")
	}
	return hex.EncodeToString(b), nil
}

func executeRegistration(ctx context.Context, command string, args []string) (string, any, *Failure) {
	flags, f := regFlags(command, args)
	if f != nil {
		return "", nil, f
	}
	session := &regSession{freezer: newRegFreezer(), active: map[string]bool{}}
	network := ""
	if command != "registration account-pin" {
		raw, f := session.freezer.read(flags["--profile"], 4<<20, flags["--profile-sha256"], "profile", true)
		if f != nil {
			return "", nil, f
		}
		profile, f := regProfileAdmission(raw)
		if f != nil {
			return "", nil, f
		}
		session.profile = profile
		session.profileRaw = raw
		session.profileHash = regDigest(raw)
		network = profile.Network
		pinRaw, f := session.freezer.read(flags["--account-pin"], 16384, flags["--account-pin-sha256"], "pin")
		if f != nil {
			return network, nil, f
		}
		if _, f := regPinAdmission(pinRaw, "keyvault-namecoin-account-pin/1"); f != nil {
			return network, nil, f
		}
		planner, e := reg.NewPlanner(pinRaw, reg.Profile{Network: profile.Network, Genesis: profile.Genesis, Policy: profile.Policy})
		if e != nil {
			return network, nil, regLibraryFailure(e)
		}
		session.pinRaw = pinRaw
		session.pinHash = regDigest(pinRaw)
		session.planner = planner
	}
	raw, f := session.freezer.read(flags["--request"], 65536, "", "construction")
	if f != nil {
		return network, nil, f
	}
	var payload map[string][]byte
	var kind string
	switch command {
	case "registration account-pin":
		pin, f := regPinAdmission(raw, regPrefix+"account-pin/1")
		if f != nil {
			return "", nil, f
		}
		pin.Schema = "keyvault-namecoin-account-pin/1"
		pinRaw, e := json.Marshal(pin)
		if e != nil {
			return "", nil, regFailure("INTERNAL")
		}
		session.pinHash = regDigest(pinRaw)
		payload = map[string][]byte{"account-pin.json": pinRaw}
		kind = "account-pin"
	case "registration reserve":
		payload, f = session.reserve(raw)
		kind = "reservation"
	case "registration reveal":
		payload, f = session.reveal(raw)
		kind = "reveal"
	case "registration request":
		payload, f = session.prepare(raw)
		kind = "request"
	case "registration check-result":
		payload, f = session.checkResult(raw)
		kind = "checked-result"
	default:
		return network, nil, regFailure("BAD_INPUT")
	}
	if f != nil {
		return network, nil, f
	}
	success, f := regCommit(ctx, flags["--out-dir"], kind, session.profileHash, session.pinHash, payload)
	return network, success, f
}
func (s *regSession) basePayload() map[string][]byte {
	return map[string][]byte{"profile.json": s.profileRaw, "account-pin.json": s.pinRaw}
}
func regPlanPayload(payload map[string][]byte, plan *reg.Plan, kind string) {
	payload[kind+"-manifest.json"] = plan.Manifest()
	index := regTransactions{Schema: regPrefix + "transactions/1", Transactions: []regTransaction{}}
	for _, tx := range plan.Transactions() {
		name := tx.Slot + ".psbt"
		payload[name] = []byte(tx.PSBT)
		index.Transactions = append(index.Transactions, regTransaction{tx.Slot, tx.TxID, name, tx.UnsignedVSize, tx.SignedVSizeMin, tx.SignedVSizeMax})
	}
	payload["transaction-index.json"] = regCanonical(index)
}
func (s *regSession) reserve(raw []byte) (map[string][]byte, *Failure) {
	var request regReserve
	if !regDecode(raw, &request) || request.Schema != regPrefix+"reserve/1" || len(request.Names) != 2 || !regAbs(request.Funding.Hex) {
		return nil, regFailure("BAD_INPUT")
	}
	funding, f := s.freezer.read(request.Funding.Hex, 8<<20, "", "funding.hex")
	if f != nil {
		return nil, f
	}
	state := regReservationState{Schema: regPrefix + "reservation-state/1", Funding: request.Funding, Names: []regSavedName{}, Change: request.Change, Fees: request.Fees}
	state.Funding.Hex = "funding.hex"
	// Generate exactly one opening per name. On any refusal no output is created;
	// a committed state is the only source for subsequent reconstruction.
	for _, row := range request.Names {
		opening, f := regRandom(20)
		if f != nil {
			return nil, f
		}
		state.Names = append(state.Names, regSavedName{row.Name, row.Path, row.Value, opening})
	}
	in, ok := regReservationInput(state, funding)
	if !ok {
		return nil, regFailure("BAD_INPUT")
	}
	now, f := regFreshTime(s.profile)
	if f != nil {
		return nil, f
	}
	state.PreparedAt = now
	plan, e := s.planner.Reserve(in, now)
	if e != nil {
		return nil, regLibraryFailure(e)
	}
	payload := s.basePayload()
	payload["funding.hex"] = funding
	payload["reservation-state.json"] = regCanonical(state)
	regPlanPayload(payload, plan, "reservation")
	return payload, nil
}
func (s *regSession) reveal(raw []byte) (map[string][]byte, *Failure) {
	var r regReveal
	if !regDecode(raw, &r) || r.Schema != regPrefix+"reveal/1" || !regAbs(r.Pin) || !regHex(r.PinHash, 32) {
		return nil, regFailure("BAD_INPUT")
	}
	pin, f := s.freezer.read(r.Pin, 16384, r.PinHash, "reveal-values-pin.json")
	if f != nil {
		return nil, f
	}
	in, reservation, f := s.revealInput(r.Reservation, r.ReservationHash, r.Parents, pin, r.Change, r.Fees, 0)
	if f != nil {
		return nil, f
	}
	now, f := regFreshTime(s.profile)
	if f != nil {
		return nil, f
	}
	plan, e := s.planner.Reveal(reservation, in, now)
	if e != nil {
		return nil, regLibraryFailure(e)
	}
	state := regRevealState{regPrefix + "reveal-state/1", r.Reservation, r.ReservationHash, r.Parents, "reveal-values-pin.json", r.PinHash, r.Change, r.Fees, now}
	payload := s.basePayload()
	payload["reveal-state.json"] = regCanonical(state)
	payload["reveal-values-pin.json"] = pin
	regPlanPayload(payload, plan, "reveal")
	return payload, nil
}
func (s *regSession) prepare(raw []byte) (map[string][]byte, *Failure) {
	var r regRequest
	if !regDecode(raw, &r) || r.Schema != regPrefix+"request/1" || !regSlot(r.Slot) || r.ValidFor < 1 || r.ValidFor > 600 {
		return nil, regFailure("BAD_INPUT")
	}
	kind := "reservation"
	if r.Slot == "C" || r.Slot == "D" {
		kind = "reveal"
	}
	plan, f := s.plan(r.Plan, r.PlanHash, 1, kind)
	if f != nil {
		return nil, f
	}
	now, f := regFreshTime(s.profile)
	if f != nil {
		return nil, f
	}
	if !regDispatchMargin(r.ValidFor, s.profile.Policy.ReleaseNotAfter-now) {
		return nil, regFailure("REGISTRATION_POLICY_REFUSED")
	}
	requestID, f := regRandom(32)
	if f != nil {
		return nil, f
	}
	sittingID, f := regRandom(32)
	if f != nil {
		return nil, f
	}
	ids := reg.RequestIDs{RequestID: requestID, SittingID: sittingID, ExpiresAt: now + r.ValidFor}
	var unsigned string
	for _, tx := range plan.Transactions() {
		if tx.Slot == r.Slot {
			unsigned = tx.PSBT
		}
	}
	request, e := s.planner.PrepareRequest(plan, r.Slot, unsigned, ids, now)
	if e != nil {
		return nil, regLibraryFailure(e)
	}
	requestRaw := request.Bytes()
	if f := regEmissionSize(requestRaw); f != nil {
		return nil, f
	}
	payload := s.basePayload()
	payload["request.json"] = requestRaw
	payload["review-frame.bin"] = request.ReviewFrame()
	payload["request-state.json"] = regCanonical(regRequestState{regPrefix + "request-state/1", r.Plan, r.PlanHash, r.Slot, now, requestID, sittingID, ids.ExpiresAt, regDigest(requestRaw), regDigest(request.ReviewFrame())})
	if !regEmissionMargin(ids.ExpiresAt, s.profile.Policy.ReleaseNotAfter, time.Now()) {
		return nil, regFailure("REGISTRATION_POLICY_REFUSED")
	}
	return payload, nil
}

// Only fresh emission uses the dispatch ceilings. Historical restoration keeps
// its independent local limits. Inspect the exact once-generated request bytes.
func regEmissionSize(raw []byte) *Failure {
	if len(raw) > 2097152 {
		return regFailure("REGISTRATION_FILES")
	}
	var request struct {
		PSBT string `json:"psbt"`
	}
	if json.Unmarshal(raw, &request) != nil {
		return regFailure("INTERNAL")
	}
	psbt, err := base64.StdEncoding.Strict().DecodeString(request.PSBT)
	if err != nil {
		return regFailure("INTERNAL")
	}
	if len(psbt) > 1048576 {
		return regFailure("REGISTRATION_FILES")
	}
	return nil
}

// Compare the frozen request endpoint first, then release, at one actual final
// instant. Ordering precedes unsigned subtraction; fractional time is not rounded.
func regEmissionMargin(expiresAt, releaseNotAfter uint64, now time.Time) bool {
	seconds := now.Unix()
	if seconds < 0 {
		return false
	}
	for _, end := range []uint64{expiresAt, releaseNotAfter} {
		if !regTime(end) || end <= uint64(seconds) {
			return false
		}
		remaining := end - uint64(seconds)
		if remaining < 30 || (remaining == 30 && now.Nanosecond() != 0) {
			return false
		}
	}
	return true
}
func (s *regSession) checkResult(raw []byte) (map[string][]byte, *Failure) {
	var r regCheck
	if !regDecode(raw, &r) || r.Schema != regPrefix+"check-result/1" {
		return nil, regFailure("BAD_INPUT")
	}
	_, verified, f := s.check(regParent{r.Bundle, r.BundleHash, r.Result, r.ResultHash, r.Stdout, r.StdoutHash, r.Exit}, 1)
	if f != nil {
		return nil, f
	}
	tx := verified.Transaction
	payload := s.basePayload()
	r.Schema = regPrefix + "verification-state/1"
	payload["verification-state.json"] = regCanonical(r)
	payload["verified-transaction.hex"] = []byte(tx.Hex)
	payload["public-result.json"] = regCanonical(regPublicResult{regPrefix + "public-result/1", tx.TxID, tx.SignedPSBTSHA256, verified.ResultSHA256, strconv.FormatUint(tx.FeeAtoms, 10), tx.Weight, tx.VSize, verified.ReportedJournalSequence, verified.ReportedJournalHeadSHA256})
	return payload, nil
}

// Both margins use the same actual clock captured by prepare after admission.
func regDispatchMargin(validFor, releaseRemaining uint64) bool {
	return validFor >= 30 && releaseRemaining >= 30
}
