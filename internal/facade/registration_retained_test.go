package facade

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
	reg "github.com/relux-works/swarma-identity/internal/registration"
)

func regTestFrozen(t *testing.T, mode string) (*regTestEnv, string, regParent) {
	t.Helper()
	e := newRegTestEnv(t, mode, false)
	p := regTestPlanner(t, e)
	var m struct {
		Registrations []struct {
			Rand string `json:"rand_hex"`
		} `json:"registrations"`
	}
	json.Unmarshal(regTestRead(t, "../registration/testdata/core28/"+mode+"/reservation-manifest.json"), &m)
	state := regReservationState{Schema: regPrefix + "reservation-state/1", PreparedAt: e.profile.Policy.CreatedAt + 60, Funding: e.reserve.Funding, Names: []regSavedName{}, Change: e.reserve.Change, Fees: e.reserve.Fees}
	state.Funding.Hex = "funding.hex"
	for i, n := range e.reserve.Names {
		state.Names = append(state.Names, regSavedName{n.Name, n.Path, n.Value, m.Registrations[i].Rand})
	}
	funding := regTestRead(t, e.reserve.Funding.Hex)
	in, ok := regReservationInput(state, funding)
	if !ok {
		t.Fatal("fixture input")
	}
	plan, err := p.Reserve(in, state.PreparedAt)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string][]byte{"profile.json": e.profileRaw, "account-pin.json": e.pin, "reservation-state.json": regCanonical(state), "funding.hex": funding}
	regPlanPayload(payload, plan, "reservation")
	reservationDir := filepath.Join(e.dir, "original-reservation")
	success, f := regCommit(context.Background(), reservationDir, "reservation", regDigest(e.profileRaw), regDigest(e.pin), payload)
	if f != nil {
		t.Fatal(f)
	}
	reservation := filepath.Join(reservationDir, "bundle.json")
	var vectors map[string]struct {
		RequestID string `json:"request_id"`
		SittingID string `json:"sitting_id"`
		ExpiresAt uint64 `json:"expires_at"`
		Result    string `json:"result_format_only"`
	}
	json.Unmarshal(regTestRead(t, "../registration/testdata/core28/"+mode+"/wire-vectors.json"), &vectors)
	v := vectors["A"]
	request, err := p.PrepareRequest(plan, "A", plan.Transactions()[0].PSBT, reg.RequestIDs{RequestID: v.RequestID, SittingID: v.SittingID, ExpiresAt: v.ExpiresAt}, state.PreparedAt)
	if err != nil {
		t.Fatal(err)
	}
	saved := regRequestState{regPrefix + "request-state/1", reservation, success.Hash, "A", state.PreparedAt, v.RequestID, v.SittingID, v.ExpiresAt, regDigest(request.Bytes()), request.ReviewSHA256()}
	requestDir := filepath.Join(e.dir, "original-request")
	success, f = regCommit(context.Background(), requestDir, "request", regDigest(e.profileRaw), regDigest(e.pin), map[string][]byte{"profile.json": e.profileRaw, "account-pin.json": e.pin, "request-state.json": regCanonical(saved), "request.json": request.Bytes(), "review-frame.bin": request.ReviewFrame()})
	if f != nil {
		t.Fatal(f)
	}
	result := []byte(v.Result)
	stdout := []byte(fmt.Sprintf("{\"schema\":\"keyvault-namecoin-psbt-ack/2\",\"status\":\"SIGNED\",\"result_sha256\":\"%s\"}\n", regDigest(result)))
	rpath, spath := filepath.Join(e.dir, "original-result.json"), filepath.Join(e.dir, "original-stdout.txt")
	regTestWrite(t, rpath, result)
	regTestWrite(t, spath, stdout)
	return e, reservation, regParent{filepath.Join(requestDir, "bundle.json"), success.Hash, rpath, regDigest(result), spath, regDigest(stdout), 0}
}
func regTestReseal(t *testing.T, indexPath string) string {
	t.Helper()
	var index regBundle
	if json.Unmarshal(regTestRead(t, indexPath), &index) != nil {
		t.Fatal("index")
	}
	for i := range index.Files {
		b := regTestRead(t, filepath.Join(filepath.Dir(indexPath), index.Files[i].Name))
		index.Files[i].Hash = regDigest(b)
		index.Files[i].Size = uint64(len(b))
	}
	regTestWrite(t, indexPath, regCanonical(index))
	return regTestBundleHash(t, indexPath)
}
func regTestEditState(t *testing.T, path string, edit func(*regRequestState)) {
	t.Helper()
	var state regRequestState
	if json.Unmarshal(regTestRead(t, path), &state) != nil {
		t.Fatal("state")
	}
	edit(&state)
	regTestWrite(t, path, regCanonical(state))
}

// Both immutable Core result fixtures verify through restored file contexts
// after expiry. Fresh requests still refuse the actual expired policy window.
func TestRegistrationExpiredOriginal(t *testing.T) {
	for _, mode := range []string{"two-stage", "all-four-before-release"} {
		t.Run(mode, func(t *testing.T) {
			e, reservation, parent := regTestFrozen(t, mode)
			_, en, exit := e.run(t, "check-result", "expired-completed", regTestCheck(parent))
			regTestSuccess(t, en, exit)
			out, en, exit := e.run(t, "request", "fresh-expired", regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "A", 600})
			regTestRefusal(t, en, exit, "REGISTRATION_POLICY_REFUSED", out)
		})
	}
}

// Recomputed file/index hashes force these mutations through the semantic
// restoration gate. A changed frame/ID/expiry/Plan never yields an output;
// omitted original custody and stale hashes remain FILES refusals.
func TestRegistrationRetainedSubstitution(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		edit       func(*testing.T, string, *regParent)
	}{
		{"frame", "REGISTRATION_PARENT_REFUSED", func(t *testing.T, reservation string, p *regParent) {
			path := filepath.Join(filepath.Dir(p.Bundle), "review-frame.bin")
			b := regTestRead(t, path)
			b[0] ^= 1
			regTestWrite(t, path, b)
			regTestEditState(t, filepath.Join(filepath.Dir(p.Bundle), "request-state.json"), func(s *regRequestState) { s.ReviewHash = regDigest(b) })
			p.BundleHash = regTestReseal(t, p.Bundle)
		}},
		{"id", "REGISTRATION_PARENT_REFUSED", func(t *testing.T, r string, p *regParent) {
			regTestEditState(t, filepath.Join(filepath.Dir(p.Bundle), "request-state.json"), func(s *regRequestState) { s.RequestID = strings.Repeat("cd", 32) })
			p.BundleHash = regTestReseal(t, p.Bundle)
		}},
		{"account-pin", "REGISTRATION_PARENT_REFUSED", func(t *testing.T, r string, p *regParent) {
			path := filepath.Join(filepath.Dir(p.Bundle), "account-pin.json")
			raw := regTestRead(t, path)
			changed := bytes.Replace(raw, []byte(`"group":"fixture/recovery@1"`), []byte(`"group":"other/recovery@1"`), 1)
			if bytes.Equal(raw, changed) {
				t.Fatal("pin substitution not applied")
			}
			regTestWrite(t, path, changed)
			p.BundleHash = regTestReseal(t, p.Bundle)
		}},
		{"pin-bytes", "REGISTRATION_PARENT_REFUSED", func(t *testing.T, r string, p *regParent) {
			// Whitespace preserves valid pin semantics, but not the independently
			// selected exact snapshot. Reseal payload commitments to reach binding.
			path := filepath.Join(filepath.Dir(p.Bundle), "account-pin.json")
			regTestWrite(t, path, append(regTestRead(t, path), ' '))
			p.BundleHash = regTestReseal(t, p.Bundle)
		}},
		{"expiry", "REGISTRATION_PARENT_REFUSED", func(t *testing.T, r string, p *regParent) {
			regTestEditState(t, filepath.Join(filepath.Dir(p.Bundle), "request-state.json"), func(s *regRequestState) { s.ExpiresAt++ })
			p.BundleHash = regTestReseal(t, p.Bundle)
		}},
		{"missing-context", "REGISTRATION_FILES", func(t *testing.T, r string, p *regParent) {
			if err := os.Rename(filepath.Join(filepath.Dir(r), "funding.hex"), filepath.Join(filepath.Dir(r), "missing.hex")); err != nil {
				t.Fatal(err)
			}
		}},
		{"manifest", "REGISTRATION_PARENT_REFUSED", func(t *testing.T, r string, p *regParent) {
			path := filepath.Join(filepath.Dir(r), "reservation-manifest.json")
			b := append(regTestRead(t, path), ' ')
			regTestWrite(t, path, b)
			hash := regTestReseal(t, r)
			regTestEditState(t, filepath.Join(filepath.Dir(p.Bundle), "request-state.json"), func(s *regRequestState) { s.PlanHash = hash })
			p.BundleHash = regTestReseal(t, p.Bundle)
		}},
		{"opening", "REGISTRATION_PARENT_REFUSED", func(t *testing.T, r string, p *regParent) {
			path := filepath.Join(filepath.Dir(r), "reservation-state.json")
			var s regReservationState
			json.Unmarshal(regTestRead(t, path), &s)
			s.Names[0].Rand = strings.Repeat("cd", 20)
			regTestWrite(t, path, regCanonical(s))
			hash := regTestReseal(t, r)
			regTestEditState(t, filepath.Join(filepath.Dir(p.Bundle), "request-state.json"), func(s *regRequestState) { s.PlanHash = hash })
			p.BundleHash = regTestReseal(t, p.Bundle)
		}},
		{"transaction-metadata", "REGISTRATION_PARENT_REFUSED", func(t *testing.T, r string, p *regParent) {
			path := filepath.Join(filepath.Dir(r), "transaction-index.json")
			var s regTransactions
			json.Unmarshal(regTestRead(t, path), &s)
			s.Transactions[0].Min++
			regTestWrite(t, path, regCanonical(s))
			hash := regTestReseal(t, r)
			regTestEditState(t, filepath.Join(filepath.Dir(p.Bundle), "request-state.json"), func(s *regRequestState) { s.PlanHash = hash })
			p.BundleHash = regTestReseal(t, p.Bundle)
		}},
		{"stale-frame-hash", "REGISTRATION_FILES", func(t *testing.T, r string, p *regParent) {
			path := filepath.Join(filepath.Dir(p.Bundle), "review-frame.bin")
			b := regTestRead(t, path)
			b[0] ^= 1
			regTestWrite(t, path, b)
		}},
		{"cycle", "REGISTRATION_PARENT_REFUSED", func(t *testing.T, r string, p *regParent) {
			regTestEditState(t, filepath.Join(filepath.Dir(p.Bundle), "request-state.json"), func(s *regRequestState) { s.Plan = p.Bundle; s.PlanHash = p.BundleHash })
			p.BundleHash = regTestReseal(t, p.Bundle)
		}},
		{"type", "REGISTRATION_PARENT_REFUSED", func(t *testing.T, r string, p *regParent) {
			regTestEditState(t, filepath.Join(filepath.Dir(p.Bundle), "request-state.json"), func(s *regRequestState) { s.Slot = "C" })
			p.BundleHash = regTestReseal(t, p.Bundle)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, r, parent := regTestFrozen(t, "two-stage")
			_, en, exit := e.run(t, "check-result", "control", regTestCheck(parent))
			regTestSuccess(t, en, exit)
			tc.edit(t, r, &parent)
			if tc.name == "frame" {
				s := regTestSession(t, e)
				if restored, f := s.originalRequest(parent.Bundle, parent.BundleHash, 1); restored != nil || f == nil || f.Code != "REGISTRATION_PARENT_REFUSED" {
					t.Fatal("restored frame mismatch admitted")
				}
			}
			out, en, exit := e.run(t, "check-result", "refused", regTestCheck(parent))
			regTestRefusal(t, en, exit, tc.code, out)
		})
	}
}

// Invalid ACK, process exit and actual signature each refuse as RESULT after
// complete reconstruction. Hash-valid but forged receipt metadata cannot stand
// in for verified signatures. Source buffers stay unchanged after checking.
func TestRegistrationResultRefusals(t *testing.T) {
	for _, variant := range []string{"ack", "exit", "signature", "receipt"} {
		t.Run(variant, func(t *testing.T) {
			e, _, p := regTestFrozen(t, "two-stage")
			_, en, exit := e.run(t, "check-result", "valid", regTestCheck(p))
			regTestSuccess(t, en, exit)
			switch variant {
			case "ack":
				regTestWrite(t, p.Stdout, append(regTestRead(t, p.Stdout), ' '))
				p.StdoutHash = regTestBundleHash(t, p.Stdout)
			case "exit":
				p.Exit = 1
			default:
				var result map[string]any
				json.Unmarshal(regTestRead(t, p.Result), &result)
				if variant == "signature" {
					b, _ := base64.StdEncoding.DecodeString(result["signed_psbt"].(string))
					packet, err := psbt.NewFromRawBytes(bytes.NewReader(b), false)
					if err != nil {
						t.Fatal(err)
					}
					packet.Inputs[0].PartialSigs[0].Signature[10] ^= 1
					var signed bytes.Buffer
					packet.Serialize(&signed)
					result["signed_psbt"] = base64.StdEncoding.EncodeToString(signed.Bytes())
				} else {
					result["receipt"].(map[string]any)["request_id"] = strings.Repeat("aa", 32)
				}
				b := regCanonical(result)
				regTestWrite(t, p.Result, b)
				p.ResultHash = regDigest(b)
				stdout := []byte(fmt.Sprintf("{\"schema\":\"keyvault-namecoin-psbt-ack/2\",\"status\":\"SIGNED\",\"result_sha256\":\"%s\"}\n", p.ResultHash))
				regTestWrite(t, p.Stdout, stdout)
				p.StdoutHash = regDigest(stdout)
			}
			before := regTestRead(t, p.Result)
			out, en, exit := e.run(t, "check-result", "bad", regTestCheck(p))
			regTestRefusal(t, en, exit, "REGISTRATION_RESULT_REFUSED", out)
			if !bytes.Equal(before, regTestRead(t, p.Result)) {
				t.Fatal("result input mutated")
			}
		})
	}
}

// Exact 6 MiB public consumer transport succeeds with recomputed ACK and outer
// whitespace, not a claimed natural canonical producer maximum. One byte over
// is FILES before parsing; <=256-byte invalid ACK is RESULT, 257 is FILES.
func TestRegistrationResultBounds(t *testing.T) {
	e, _, p := regTestFrozen(t, "two-stage")
	original := regTestRead(t, p.Result)
	for _, size := range []int{(6 << 20) - 1, 6 << 20, (6 << 20) + 1} {
		b := append(append([]byte(nil), original...), bytes.Repeat([]byte(" "), size-len(original))...)
		regTestWrite(t, p.Result, b)
		p.ResultHash = regDigest(b)
		stdout := []byte(fmt.Sprintf("{\"schema\":\"keyvault-namecoin-psbt-ack/2\",\"status\":\"SIGNED\",\"result_sha256\":\"%s\"}\n", p.ResultHash))
		regTestWrite(t, p.Stdout, stdout)
		p.StdoutHash = regDigest(stdout)
		out, en, exit := e.run(t, "check-result", fmt.Sprintf("result-%d", size), regTestCheck(p))
		if size <= 6<<20 {
			regTestSuccess(t, en, exit)
		} else {
			regTestRefusal(t, en, exit, "REGISTRATION_FILES", out)
		}
	}
	regTestWrite(t, p.Result, original)
	p.ResultHash = regDigest(original)
	for _, size := range []int{255, 256, 257} {
		b := bytes.Repeat([]byte(" "), size)
		regTestWrite(t, p.Stdout, b)
		p.StdoutHash = regDigest(b)
		out, en, exit := e.run(t, "check-result", fmt.Sprintf("stdout-%d", size), regTestCheck(p))
		code := "REGISTRATION_RESULT_REFUSED"
		if size > 256 {
			code = "REGISTRATION_FILES"
		}
		regTestRefusal(t, en, exit, code, out)
	}
}

// The depth bound is path depth, not total graph edges; the complete C/D file
// flow proves sharing. A valid reservation at depth five passes, six refuses.
func TestRegistrationGraphDepth(t *testing.T) {
	e, reservation, _ := regTestFrozen(t, "two-stage")
	s := regTestSession(t, e)
	hash := regTestBundleHash(t, reservation)
	if p, f := s.plan(reservation, hash, 5, "reservation"); f != nil || p == nil {
		t.Fatal(f)
	}
	if p, f := s.plan(reservation, hash, 6, "reservation"); p != nil || f == nil || f.Code != "REGISTRATION_PARENT_REFUSED" {
		t.Fatal("depth bound not applied")
	}
}

// No automatic reconstruction may replace original raw request serialization.
// A harmless admitted representation survives, but a one-byte frame mismatch
// fails even after both stored commitments have been updated.
func TestRegistrationOriginalRawRequest(t *testing.T) {
	e, _, p := regTestFrozen(t, "two-stage")
	requestPath := filepath.Join(filepath.Dir(p.Bundle), "request.json")
	raw := append([]byte(" \n"), regTestRead(t, requestPath)...)
	regTestWrite(t, requestPath, raw)
	regTestEditState(t, filepath.Join(filepath.Dir(p.Bundle), "request-state.json"), func(s *regRequestState) { s.RequestHash = regDigest(raw) })
	p.BundleHash = regTestReseal(t, p.Bundle)
	s := regTestSession(t, e)
	original, f := s.originalRequest(p.Bundle, p.BundleHash, 1)
	if f != nil || !bytes.Equal(original.request.Bytes(), raw) {
		t.Fatalf("original representation lost: %v", f)
	}
	// Original result correlates to the review frame, not raw JSON serialization.
	_, en, exit := e.run(t, "check-result", "representation", regTestCheck(p))
	regTestSuccess(t, en, exit)
}
