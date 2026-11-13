package facade

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"

	reg "github.com/relux-works/swarma-identity/internal/registration"
)

type regSession struct {
	freezer              *regFreezer
	planner              *reg.Planner
	profile              regProfile
	profileRaw, pinRaw   []byte
	profileHash, pinHash string
	active               map[string]bool
}
type regLoadedBundle struct {
	kind  string
	files map[string][]byte
}
type regOriginalRequest struct {
	request *reg.SigningRequest
	plan    *reg.Plan
	state   regRequestState
}

func (s *regSession) bundle(path, hash string, depth int, allowed ...string) (*regLoadedBundle, *Failure) {
	if !regAbs(path) || filepath.Base(path) != "bundle.json" || !regHex(hash, 32) {
		return nil, regFailure("BAD_INPUT")
	}
	if depth > 5 || s.active[path] {
		return nil, regFailure("REGISTRATION_PARENT_REFUSED")
	}
	held, failure := regHoldBundle(path)
	if failure != nil {
		return nil, failure
	}
	defer held.close()
	raw, f := s.freezer.read(path, 65536, hash, "bundle")
	if f != nil {
		return nil, f
	}
	var index regBundle
	if !regState(raw, &index, "bundle") || len(regPayloads[index.Kind]) == 0 || !regHex(index.ProfileHash, 32) || !regHex(index.PinHash, 32) {
		return nil, regFailure("BAD_INPUT")
	}
	names := regPayloads[index.Kind]
	if len(index.Files) != len(names) {
		return nil, regFailure("BAD_INPUT")
	}
	files := map[string][]byte{}
	for i, row := range index.Files {
		if row.Name != names[i] || !regHex(row.Hash, 32) {
			return nil, regFailure("BAD_INPUT")
		}
		if row.Size > uint64(regCap(row.Name)) {
			return nil, regFailure("REGISTRATION_FILES")
		}
		role := row.Name
		if row.Name == "profile.json" {
			role = "profile"
		}
		if row.Name == "account-pin.json" {
			role = "pin"
		}
		b, f := s.freezer.read(filepath.Join(filepath.Dir(path), row.Name), regCap(row.Name), row.Hash, role)
		if f != nil {
			return nil, f
		}
		if uint64(len(b)) != row.Size {
			return nil, regFailure("REGISTRATION_FILES")
		}
		files[row.Name] = b
	}
	if !regSourceDirectorySafe(held) {
		return nil, regFailure("REGISTRATION_FILES")
	}
	// All payload admissions precede semantic binding to independently selected
	// profile/pin snapshots. The index is never authority for selecting them.
	goodKind := false
	for _, kind := range allowed {
		goodKind = goodKind || index.Kind == kind
	}
	if !goodKind || index.ProfileHash != s.profileHash || index.PinHash != s.pinHash || !bytes.Equal(files["profile.json"], s.profileRaw) || !bytes.Equal(files["account-pin.json"], s.pinRaw) {
		return nil, regFailure("REGISTRATION_PARENT_REFUSED")
	}
	return &regLoadedBundle{index.Kind, files}, nil
}

func regFees(change, fees []string) ([2]string, [2]uint64, bool) {
	var paths [2]string
	var amounts [2]uint64
	if len(change) != 2 || len(fees) != 2 {
		return paths, amounts, false
	}
	for i := range 2 {
		n, ok := regDecimal(fees[i])
		if !ok || !regDerivation(change[i]) {
			return paths, amounts, false
		}
		paths[i] = change[i]
		amounts[i] = n
	}
	return paths, amounts, true
}
func regDerivation(path string) bool {
	const prefix = "m/84h/7h/0h/"
	if len(path) <= len(prefix) || path[:len(prefix)] != prefix {
		return false
	}
	rest := path[len(prefix):]
	for i, c := range rest {
		if c == '/' {
			branch, e := strconv.ParseUint(rest[:i], 10, 1)
			n, ok := regDecimal(rest[i+1:])
			return e == nil && strconv.FormatUint(branch, 10) == rest[:i] && ok && n < 1<<31
		}
	}
	return false
}
func regReservationInput(state regReservationState, rawFunding []byte) (reg.ReservationInput, bool) {
	var in reg.ReservationInput
	paths, fees, ok := regFees(state.Change, state.Fees)
	if !ok || len(state.Names) != 2 || state.Funding.Hex != "funding.hex" || !regHex(state.Funding.TxID, 32) || !regDerivation(state.Funding.Path) || len(rawFunding) > 8<<20 || !regHex(string(rawFunding), len(rawFunding)/2) || len(rawFunding) == 0 {
		return in, false
	}
	in.Funding = reg.Funding{TxHex: string(rawFunding), TxID: state.Funding.TxID, Vout: state.Funding.Vout, Path: state.Funding.Path}
	in.ChangePaths = paths
	in.Fees = fees
	for i, row := range state.Names {
		if !regHex(row.Rand, 20) || !regHex(row.Value, len(row.Value)/2) || len(row.Value) > 1040 || !regDerivation(row.Path) {
			return in, false
		}
		v, _ := hex.DecodeString(row.Value)
		in.Registrations[i] = reg.Registration{Name: row.Name, RandHex: row.Rand, NameOutputPath: row.Path, FixedValue: v}
	}
	return in, true
}
func regStoredTransactions(files map[string][]byte, first byte) ([2]reg.PreparedTransaction, *Failure) {
	var out [2]reg.PreparedTransaction
	var index regTransactions
	if !regState(files["transaction-index.json"], &index, "transactions") || len(index.Transactions) != 2 {
		return out, regFailure("BAD_INPUT")
	}
	// The manifest carries original unsigned hex; it is not trusted for the
	// resulting transaction identity. Restore* recomputes and compares all fields.
	var m struct {
		Transactions []struct {
			Slot string `json:"slot"`
			Hex  string `json:"unsigned_tx_hex"`
		} `json:"transactions"`
	}
	manifest := files["reservation-manifest.json"]
	if first == 'C' {
		manifest = files["reveal-manifest.json"]
	}
	if !regManifestSyntax(manifest) || json.Unmarshal(manifest, &m) != nil || len(m.Transactions) != 2 {
		return out, regFailure("REGISTRATION_PARENT_REFUSED")
	}
	for i, row := range index.Transactions {
		slot := string(first + byte(i))
		name := slot + ".psbt"
		if row.Slot != slot || row.File != name || !regHex(row.TxID, 32) {
			return out, regFailure("BAD_INPUT")
		}
		psbt := files[name]
		decoded, e := base64.StdEncoding.Strict().DecodeString(string(psbt))
		if e != nil || len(decoded) > 4<<20 || base64.StdEncoding.EncodeToString(decoded) != string(psbt) {
			return out, regFailure("BAD_INPUT")
		}
		out[i] = reg.PreparedTransaction{Slot: slot, UnsignedTxHex: m.Transactions[i].Hex, TxID: row.TxID, PSBT: string(psbt), UnsignedVSize: row.Unsigned, SignedVSizeMin: row.Min, SignedVSizeMax: row.Max}
	}
	return out, nil
}

// Manifests are reconstructed and compared by the public library, rather than
// decoded into an alternate authority-bearing Plan.
func regManifestSyntax(raw []byte) bool {
	return len(raw) > 0 && len(raw) <= 1<<20 && validateJSON(raw) == nil
}

func (s *regSession) plan(path, hash string, depth int, kind string) (*reg.Plan, *Failure) {
	allowed := []string{kind}
	if kind == "" {
		allowed = []string{"reservation", "reveal"}
	}
	bundle, f := s.bundle(path, hash, depth, allowed...)
	if f != nil {
		return nil, f
	}
	s.active[path] = true
	defer delete(s.active, path)
	files := bundle.files
	if bundle.kind == "reservation" {
		var state regReservationState
		if !regState(files["reservation-state.json"], &state, "reservation-state") || !regTime(state.PreparedAt) {
			return nil, regFailure("BAD_INPUT")
		}
		in, ok := regReservationInput(state, files["funding.hex"])
		if !ok {
			return nil, regFailure("BAD_INPUT")
		}
		txs, f := regStoredTransactions(files, 'A')
		if f != nil {
			return nil, f
		}
		plan, e := s.planner.RestoreReservation(in, state.PreparedAt, files["reservation-manifest.json"], txs)
		if e != nil {
			return nil, regFailure("REGISTRATION_PARENT_REFUSED")
		}
		return plan, nil
	}
	var state regRevealState
	if !regState(files["reveal-state.json"], &state, "reveal-state") || !regTime(state.PreparedAt) || state.Pin != "reveal-values-pin.json" || !regHex(state.PinHash, 32) {
		return nil, regFailure("BAD_INPUT")
	}
	if regDigest(files["reveal-values-pin.json"]) != state.PinHash {
		return nil, regFailure("REGISTRATION_FILES")
	}
	in, reservation, f := s.revealInput(state.Reservation, state.ReservationHash, state.Parents, files["reveal-values-pin.json"], state.Change, state.Fees, depth)
	if f != nil {
		return nil, f
	}
	txs, f := regStoredTransactions(files, 'C')
	if f != nil {
		return nil, f
	}
	plan, e := s.planner.RestoreReveal(reservation, in, state.PreparedAt, files["reveal-manifest.json"], txs)
	if e != nil {
		return nil, regFailure("REGISTRATION_PARENT_REFUSED")
	}
	return plan, nil
}
func (s *regSession) originalRequest(path, hash string, depth int) (*regOriginalRequest, *Failure) {
	bundle, f := s.bundle(path, hash, depth, "request")
	if f != nil {
		return nil, f
	}
	s.active[path] = true
	defer delete(s.active, path)
	var state regRequestState
	if !regState(bundle.files["request-state.json"], &state, "request-state") || !regTime(state.PreparedAt) || !regTime(state.ExpiresAt) || !regHex(state.RequestID, 32) || !regHex(state.SittingID, 32) || !regHex(state.RequestHash, 32) || !regHex(state.ReviewHash, 32) || !regSlot(state.Slot) {
		return nil, regFailure("BAD_INPUT")
	}
	if regDigest(bundle.files["request.json"]) != state.RequestHash || regDigest(bundle.files["review-frame.bin"]) != state.ReviewHash {
		return nil, regFailure("REGISTRATION_FILES")
	}
	kind := "reservation"
	if state.Slot == "C" || state.Slot == "D" {
		kind = "reveal"
	}
	plan, f := s.plan(state.Plan, state.PlanHash, depth+1, kind)
	if f != nil {
		return nil, f
	}
	r, e := s.planner.RestoreSigningRequest(plan, reg.RetainedRequest{Slot: state.Slot, PreparedAt: state.PreparedAt, IDs: reg.RequestIDs{RequestID: state.RequestID, SittingID: state.SittingID, ExpiresAt: state.ExpiresAt}, Request: bundle.files["request.json"], ReviewFrame: bundle.files["review-frame.bin"]})
	if e != nil {
		return nil, regFailure("REGISTRATION_PARENT_REFUSED")
	}
	return &regOriginalRequest{r, plan, state}, nil
}
func regSlot(slot string) bool { return slot == "A" || slot == "B" || slot == "C" || slot == "D" }
func (s *regSession) check(parent regParent, depth int) (*regOriginalRequest, *reg.PublicResult, *Failure) {
	if !regAbs(parent.Bundle) || !regAbs(parent.Result) || !regAbs(parent.Stdout) || !regHex(parent.BundleHash, 32) || !regHex(parent.ResultHash, 32) || !regHex(parent.StdoutHash, 32) {
		return nil, nil, regFailure("BAD_INPUT")
	}
	// Freeze transport before reconstruction/result checks, preserving file errors.
	result, f := s.freezer.read(parent.Result, 6<<20, parent.ResultHash, "result")
	if f != nil {
		return nil, nil, f
	}
	stdout, f := s.freezer.read(parent.Stdout, 256, parent.StdoutHash, "stdout")
	if f != nil {
		return nil, nil, f
	}
	original, f := s.originalRequest(parent.Bundle, parent.BundleHash, depth)
	if f != nil {
		return nil, nil, f
	}
	verified, e := s.planner.CheckResult(original.request, result, stdout, int(parent.Exit))
	if e != nil {
		return nil, nil, regFailure("REGISTRATION_RESULT_REFUSED")
	}
	return original, verified, nil
}
func (s *regSession) revealInput(path, hash string, parents []regParent, pin []byte, change, fees []string, depth int) (reg.RevealInput, *reg.Plan, *Failure) {
	var in reg.RevealInput
	paths, amounts, ok := regFees(change, fees)
	if !ok || len(parents) != 2 {
		return in, nil, regFailure("BAD_INPUT")
	}
	reservation, f := s.plan(path, hash, depth+1, "reservation")
	if f != nil {
		return in, nil, f
	}
	for i, parent := range parents {
		original, verified, f := s.check(parent, depth+1)
		if f != nil {
			return in, nil, f
		}
		slot := string('A' + byte(i))
		if original.state.Slot != slot || original.plan.Hash() != reservation.Hash() {
			return in, nil, regFailure("REGISTRATION_PARENT_REFUSED")
		}
		in.Parents[i] = reg.ParentReference{Slot: slot, RequestID: original.state.RequestID, SittingID: original.state.SittingID, UnsignedTxID: verified.Transaction.TxID, SignedPSBTSHA256: verified.Transaction.SignedPSBTSHA256}
	}
	in.ValuesPin = append([]byte(nil), pin...)
	in.ChangePaths = paths
	in.Fees = amounts
	return in, reservation, nil
}
