package facade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixture roots resolve a symlinked Go temporary-directory path before product
// admission. The product's no-follow refusal still applies to supplied paths.
func TestRegistrationResolvedTempFixture(t *testing.T) {
	dir := regTestDir(t)
	real, alias := filepath.Join(dir, "real"), filepath.Join(dir, "alias")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTMPDIR", alias)
	// A child T has not yet cached its TempDir root before GOTMPDIR changed.
	t.Run("symlinked", func(t *testing.T) {
		e := newRegTestEnv(t, "two-stage", true)
		resolved, err := filepath.EvalSymlinks(e.dir)
		if err != nil || resolved != e.dir {
			t.Fatal("fixture retained symlinked temp root")
		}
		_, en, exit := e.run(t, "reserve", "resolved", e.reserve)
		regTestSuccess(t, en, exit)
	})
}

// Claim: a source bundle directory must be current-user 0700 (F2). A 0755
// directory with otherwise valid contents is refused as FILES; 0700 is the control.
func TestRegistrationSourceDirMode(t *testing.T) {
	e := newRegTestEnv(t, "two-stage", true)
	reservation, en, exit := e.run(t, "reserve", "reservation", e.reserve)
	regTestSuccess(t, en, exit)
	_, en, exit = e.run(t, "request", "control", regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "A", 600})
	regTestSuccess(t, en, exit)
	if err := os.Chmod(filepath.Dir(reservation), 0755); err != nil {
		t.Fatal(err)
	}
	out, en, exit := e.run(t, "request", "wide", regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "A", 600})
	regTestRefusal(t, en, exit, "REGISTRATION_FILES", out)
}

// Claim: a request slot whose kind differs from the referenced bundle kind is a
// typed-reference refusal (PARENT), not a later PSBT/slot BAD_INPUT.
func TestRegistrationRequestKind(t *testing.T) {
	e := newRegTestEnv(t, "two-stage", true)
	reservation, en, exit := e.run(t, "reserve", "reservation", e.reserve)
	regTestSuccess(t, en, exit)
	_, en, exit = e.run(t, "request", "valid-kind", regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "A", 600})
	regTestSuccess(t, en, exit)
	out, en, exit := e.run(t, "request", "wrong-kind", regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "C", 600})
	regTestRefusal(t, en, exit, "REGISTRATION_PARENT_REFUSED", out)
}

// Claim (F2 precedence): with a missing result file AND a hash-valid substituted
// request context, the earlier file admission failure (FILES) is reported.
func TestRegistrationPrecedenceFilesFirst(t *testing.T) {
	for _, missing := range []string{"result", "stdout"} {
		t.Run(missing, func(t *testing.T) {
			e, _, p := regTestFrozen(t, "two-stage")
			_, en, exit := e.run(t, "check-result", "control", regTestCheck(p))
			regTestSuccess(t, en, exit)
			regTestEditState(t, filepath.Join(filepath.Dir(p.Bundle), "request-state.json"), func(s *regRequestState) { s.RequestID = strings.Repeat("cd", 32) })
			p.BundleHash = regTestReseal(t, p.Bundle)
			// First prove the substitution alone reaches the intended semantic gate.
			out, en, exit := e.run(t, "check-result", "substituted", regTestCheck(p))
			regTestRefusal(t, en, exit, "REGISTRATION_PARENT_REFUSED", out)
			path := p.Result
			if missing == "stdout" {
				path = p.Stdout
			}
			if err := os.Rename(path, path+".moved"); err != nil {
				t.Fatal(err)
			}
			out, en, exit = e.run(t, "check-result", "precedence", regTestCheck(p))
			regTestRefusal(t, en, exit, "REGISTRATION_FILES", out)
		})
	}
}

// Claim (F2/F3): the stored request_sha256 is verified against request.json even
// when the changed representation is semantically admitted and the index resealed.
func TestRegistrationStaleRequestHash(t *testing.T) {
	e, _, p := regTestFrozen(t, "two-stage")
	_, en, exit := e.run(t, "check-result", "control", regTestCheck(p))
	regTestSuccess(t, en, exit)
	requestPath := filepath.Join(filepath.Dir(p.Bundle), "request.json")
	regTestWrite(t, requestPath, append([]byte(" "), regTestRead(t, requestPath)...))
	p.BundleHash = regTestReseal(t, p.Bundle)
	out, en, exit := e.run(t, "check-result", "stale-request-hash", regTestCheck(p))
	regTestRefusal(t, en, exit, "REGISTRATION_FILES", out)
}

// Claim (F2): the account-pin digest flag mismatch is FILES (not POLICY) and the
// already validated profile network is reported.
func TestRegistrationPinDigestMismatch(t *testing.T) {
	e := newRegTestEnv(t, "two-stage", true)
	_, good, goodExit := e.run(t, "reserve", "control", e.reserve)
	regTestSuccess(t, good, goodExit)
	input := filepath.Join(e.dir, "reserve.json")
	regTestWrite(t, input, regTestJSON(t, e.reserve))
	out := filepath.Join(e.dir, "pin-mismatch")
	args := e.args("reserve", input, out)
	for i := range args {
		if args[i] == "--account-pin-sha256" {
			args[i+1] = strings.Repeat("00", 32)
		}
	}
	en, exit := regTestInvoke(t, args)
	regTestRefusal(t, en, exit, "REGISTRATION_FILES", filepath.Join(out, "bundle.json"))
	if en.Network != e.profile.Network {
		t.Fatal("validated profile network not reported")
	}
}

// Claim: an escaped spelling of a duplicate member name is still a duplicate.
func TestRegistrationEscapedDuplicateKey(t *testing.T) {
	e := newRegTestEnv(t, "two-stage", true)
	_, good, goodExit := e.run(t, "reserve", "control", e.reserve)
	regTestSuccess(t, good, goodExit)
	raw := regTestJSON(t, e.reserve)
	bad := append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"\u0073chema":"x"}`)...)
	input := filepath.Join(e.dir, "dup.json")
	regTestWrite(t, input, bad)
	out := filepath.Join(e.dir, "dup")
	en, exit := regTestInvoke(t, e.args("reserve", input, out))
	regTestRefusal(t, en, exit, "BAD_INPUT", filepath.Join(out, "bundle.json"))
}
