package facade

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	reg "github.com/relux-works/swarma-identity/internal/registration"
)

// Materialize original expired public fixture contexts; these helpers make no
// signing call and use only the existing published Core results and requests.
func regTestFrozenParents(t *testing.T) (*regTestEnv, string, []regParent, regReveal, []regParent) {
	t.Helper()
	e, reservation, a := regTestFrozen(t, "two-stage")
	s := regTestSession(t, e)
	plan, f := s.plan(reservation, regTestBundleHash(t, reservation), 1, "reservation")
	if f != nil {
		t.Fatal(f)
	}
	var vectors map[string]struct {
		RequestID string `json:"request_id"`
		SittingID string `json:"sitting_id"`
		ExpiresAt uint64 `json:"expires_at"`
		Result    string `json:"result_format_only"`
	}
	if err := json.Unmarshal(regTestRead(t, "../registration/testdata/core28/two-stage/wire-vectors.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	when := e.profile.Policy.CreatedAt + 60
	request := func(plan *reg.Plan, bundle, slot string) regParent {
		v := vectors[slot]
		var psbt string
		for _, tx := range plan.Transactions() {
			if tx.Slot == slot {
				psbt = tx.PSBT
			}
		}
		r, err := s.planner.PrepareRequest(plan, slot, psbt, reg.RequestIDs{v.RequestID, v.SittingID, v.ExpiresAt}, when)
		if err != nil {
			t.Fatal(err)
		}
		state := regRequestState{regPrefix + "request-state/1", bundle, regTestBundleHash(t, bundle), slot, when, v.RequestID, v.SittingID, v.ExpiresAt, regDigest(r.Bytes()), r.ReviewSHA256()}
		dir := filepath.Join(e.dir, "retained-request-"+slot)
		_, failure := regCommit(context.Background(), dir, "request", regDigest(e.profileRaw), regDigest(e.pin), map[string][]byte{"profile.json": e.profileRaw, "account-pin.json": e.pin, "request-state.json": regCanonical(state), "request.json": r.Bytes(), "review-frame.bin": r.ReviewFrame()})
		if failure != nil {
			t.Fatal(failure)
		}
		result := []byte(v.Result)
		stdout := []byte("{\"schema\":\"keyvault-namecoin-psbt-ack/2\",\"status\":\"SIGNED\",\"result_sha256\":\"" + regDigest(result) + "\"}\n")
		rpath, spath := filepath.Join(e.dir, slot+"-retained-result.json"), filepath.Join(e.dir, slot+"-retained-stdout.txt")
		regTestWrite(t, rpath, result)
		regTestWrite(t, spath, stdout)
		return regParent{filepath.Join(dir, "bundle.json"), regTestBundleHash(t, filepath.Join(dir, "bundle.json")), rpath, regDigest(result), spath, regDigest(stdout), 0}
	}
	parents := []regParent{a, request(plan, reservation, "B")}
	pin := regTestRead(t, "../registration/testdata/core28/two-stage/trusted-reveal-values-pin.json")
	pinPath := filepath.Join(e.dir, "original-reveal-pin.json")
	regTestWrite(t, pinPath, pin)
	revealInput := regReveal{regPrefix + "reveal/1", reservation, regTestBundleHash(t, reservation), parents, pinPath, regDigest(pin), []string{"m/84h/7h/0h/1/3", "m/84h/7h/0h/1/4"}, []string{"100000", "100000"}}
	in, restored, failure := s.revealInput(reservation, revealInput.ReservationHash, parents, pin, revealInput.Change, revealInput.Fees, 0)
	if failure != nil {
		t.Fatal(failure)
	}
	reveal, err := s.planner.Reveal(restored, in, when)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reveal.Manifest(), regTestRead(t, "../registration/testdata/core28/two-stage/reveal-manifest.json")) {
		t.Fatal("retained reveal differs from frozen original")
	}
	state := regRevealState{regPrefix + "reveal-state/1", reservation, revealInput.ReservationHash, parents, "reveal-values-pin.json", regDigest(pin), revealInput.Change, revealInput.Fees, when}
	payload := s.basePayload()
	payload["reveal-state.json"] = regCanonical(state)
	payload["reveal-values-pin.json"] = pin
	regPlanPayload(payload, reveal, "reveal")
	dir := filepath.Join(e.dir, "original-reveal")
	if _, f := regCommit(context.Background(), dir, "reveal", s.profileHash, s.pinHash, payload); f != nil {
		t.Fatal(f)
	}
	bundle := filepath.Join(dir, "bundle.json")
	return e, bundle, parents, revealInput, []regParent{request(reveal, bundle, "C"), request(reveal, bundle, "D")}
}

// F3 requires retained A/B results to verify against their own original
// requests before reveal reconstruction, including behind C/D check-result.
// Swap only result+ACK with all their hashes updated; original contexts remain
// valid. Expired authentic C/D controls succeed; substitutions produce RESULT
// and no output, rather than silently using caller-provided parent references.
func TestRegistrationRetainedParentResults(t *testing.T) {
	for _, slot := range []string{"A", "B", "A-id", "B-id"} {
		for _, command := range []string{"reveal", "C", "D"} {
			t.Run(slot+"/"+command, func(t *testing.T) {
				e, bundle, parents, reveal, children := regTestFrozenParents(t)
				for i, child := range children {
					_, en, exit := e.run(t, "check-result", "valid-"+string(rune('C'+i)), regTestCheck(child))
					regTestSuccess(t, en, exit)
				}
				// The historical reveal context itself is a valid positive control;
				// fresh reveal would instead fail the current expired policy window.
				if got, f := regTestSession(t, e).plan(bundle, regTestBundleHash(t, bundle), 1, "reveal"); got == nil || f != nil {
					t.Fatal("valid retained reveal refused")
				}
				i := int(slot[0] - 'A')
				other := parents[1-i]
				if len(slot) == 1 {
					parents[i].Result, parents[i].ResultHash = other.Result, other.ResultHash
					parents[i].Stdout, parents[i].StdoutHash = other.Stdout, other.StdoutHash
				} else {
					// A different request's result claim must not substitute for this
					// parent's receipt, even with valid signatures and exact ACK/hash.
					var result map[string]any
					if err := json.Unmarshal(regTestRead(t, parents[i].Result), &result); err != nil {
						t.Fatal(err)
					}
					result["receipt"].(map[string]any)["request_id"] = "abababababababababababababababababababababababababababababababab"
					raw := regCanonical(result)
					regTestWrite(t, parents[i].Result, raw)
					parents[i].ResultHash = regDigest(raw)
					ack := []byte("{\"schema\":\"keyvault-namecoin-psbt-ack/2\",\"status\":\"SIGNED\",\"result_sha256\":\"" + parents[i].ResultHash + "\"}\n")
					regTestWrite(t, parents[i].Stdout, ack)
					parents[i].StdoutHash = regDigest(ack)
				}
				var out string
				var en Envelope
				var exit int
				if command == "reveal" {
					reveal.Parents = parents
					out, en, exit = e.run(t, "reveal", "substituted", reveal)
				} else {
					path := filepath.Join(filepath.Dir(bundle), "reveal-state.json")
					var state regRevealState
					if !regState(regTestRead(t, path), &state, "reveal-state") {
						t.Fatal("reveal state")
					}
					state.Parents = parents
					regTestWrite(t, path, regCanonical(state))
					hash := regTestReseal(t, bundle)
					child := children[int(command[0]-'C')]
					regTestEditState(t, filepath.Join(filepath.Dir(child.Bundle), "request-state.json"), func(s *regRequestState) { s.PlanHash = hash })
					child.BundleHash = regTestReseal(t, child.Bundle)
					out, en, exit = e.run(t, "check-result", "substituted", regTestCheck(child))
				}
				regTestRefusal(t, en, exit, "REGISTRATION_RESULT_REFUSED", out)
			})
		}
	}
}
