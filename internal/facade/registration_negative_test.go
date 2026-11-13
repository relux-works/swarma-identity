package facade

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func regTestInvoke(t *testing.T, args []string) (Envelope, int) {
	t.Helper()
	var out, err bytes.Buffer
	exit := Run(context.Background(), args, &out, &err)
	var e Envelope
	if json.Unmarshal(out.Bytes(), &e) != nil || err.Len() != 0 {
		t.Fatalf("unbounded refusal %q %q", out.Bytes(), err.Bytes())
	}
	regTestEnvelopeWire(t, out.Bytes())
	return e, exit
}

// Closed argv refuses overrides, inline/missing/duplicate flags and positionals
// for all five commands, alongside a valid account-pin construction control.
func TestRegistrationClosedArgv(t *testing.T) {
	e := newRegTestEnv(t, "two-stage", true)
	var pin regPin
	json.Unmarshal(e.pin, &pin)
	pin.Schema = regPrefix + "account-pin/1"
	_, en, exit := e.run(t, "account-pin", "valid-pin", pin)
	regTestSuccess(t, en, exit)
	for _, command := range []string{"account-pin", "reserve", "reveal", "request", "check-result"} {
		input := filepath.Join(e.dir, "args.json")
		regTestWrite(t, input, regTestJSON(t, pin))
		out := filepath.Join(e.dir, "refused-"+command)
		good := e.args(command, input, out)
		for i, edit := range []func([]string) []string{
			func(a []string) []string { return append(a, "--now", "1") }, func(a []string) []string { return append(a, "--config", "x") }, func(a []string) []string { return append(a, "--signer", "x") }, func(a []string) []string { return append(a, "--seed", "x") }, func(a []string) []string { return append(a, "--json") }, func(a []string) []string { return append(a, "leftover") }, func(a []string) []string { return append(a, "--request", input) },
			func(a []string) []string { a[2] = "--request=" + input; return a }, func(a []string) []string { a[3] = "relative"; return a }, func(a []string) []string { a[3] = filepath.Dir(input) + "/./args.json"; return a }, func(a []string) []string { a[6] = "--json=true"; return a }, func(a []string) []string { return a[:len(a)-1] },
		} {
			t.Run(fmt.Sprintf("%s-%d", command, i), func(t *testing.T) {
				en, exit := regTestInvoke(t, edit(append([]string(nil), good...)))
				regTestRefusal(t, en, exit, "BAD_INPUT", filepath.Join(out, "bundle.json"))
			})
		}
	}
}

// Recursive closure/scalars reject malformed records without output. A valid
// reserve and a maximum-size whitespace-padded construction are controls.
func TestRegistrationClosedRecords(t *testing.T) {
	e := newRegTestEnv(t, "two-stage", true)
	_, en, exit := e.run(t, "reserve", "valid-reserve", e.reserve)
	regTestSuccess(t, en, exit)
	raw := regTestJSON(t, e.reserve)
	cases := map[string][]byte{
		"duplicate":      append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"schema":"other"}`)...),
		"unknown":        append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"extra":1}`)...),
		"case":           bytes.Replace(raw, []byte(`"schema"`), []byte(`"Schema"`), 1),
		"null":           bytes.Replace(raw, []byte(`"registrations":[`), []byte(`"registrations":[null,`), 1),
		"vout-exp":       bytes.Replace(raw, []byte(`"vout":0`), []byte(`"vout":0e0`), 1),
		"vout-negative":  bytes.Replace(raw, []byte(`"vout":0`), []byte(`"vout":-0`), 1),
		"vout-float":     bytes.Replace(raw, []byte(`"vout":0`), []byte(`"vout":0.0`), 1),
		"bad-utf8":       append(append([]byte{}, raw...), 0xff),
		"surrogate":      bytes.Replace(raw, []byte(`"id/`), []byte(`"\ud800`), 1),
		"fixed-value":    bytes.Replace(raw, []byte(e.reserve.Names[1].Value), []byte(hex.EncodeToString([]byte("arbitrary"))), 1),
		"leading-amount": bytes.Replace(raw, []byte(`"100000"`), []byte(`"0100000"`), 1),
		"quoted-vout":    bytes.Replace(raw, []byte(`"vout":0`), []byte(`"vout":"0"`), 1),
		"short-array":    bytes.Replace(raw, regTestJSON(t, e.reserve.Change), regTestJSON(t, e.reserve.Change[:1]), 1),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			input := filepath.Join(e.dir, name+".json")
			regTestWrite(t, input, b)
			out := filepath.Join(e.dir, "bad-"+name)
			en, exit := regTestInvoke(t, e.args("reserve", input, out))
			regTestRefusal(t, en, exit, "BAD_INPUT", filepath.Join(out, "bundle.json"))
		})
	}
	for _, size := range []int{65535, 65536, 65537} {
		b := append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), size-len(raw))...)
		input := filepath.Join(e.dir, fmt.Sprintf("size%d.json", size))
		regTestWrite(t, input, b)
		out := filepath.Join(e.dir, fmt.Sprintf("size%d", size))
		en, exit := regTestInvoke(t, e.args("reserve", input, out))
		if size <= 65536 {
			regTestSuccess(t, en, exit)
		} else {
			regTestRefusal(t, en, exit, "REGISTRATION_FILES", filepath.Join(out, "bundle.json"))
		}
	}
}

// Profile hash/static-policy admission precedes pin and construction reads;
// syntactically malformed scalars stay BAD_INPUT, and a 128-byte revision is
// admitted beside the wire's 129-byte refusal. No selection is inferred.
func TestRegistrationSelectionPrecedence(t *testing.T) {
	e := newRegTestEnv(t, "two-stage", true)
	input := filepath.Join(e.dir, "bad-construction.json")
	regTestWrite(t, input, []byte("bad"))
	out := filepath.Join(e.dir, "selection-out")
	args := e.args("reserve", input, out)
	for i := range args {
		if args[i] == "--profile-sha256" {
			args[i+1] = strings.Repeat("00", 32)
		}
	}
	en, exit := regTestInvoke(t, args)
	regTestRefusal(t, en, exit, "REGISTRATION_POLICY_REFUSED", filepath.Join(out, "bundle.json"))
	if en.Network != "" {
		t.Fatal("unvalidated network")
	}
	for _, tc := range []struct {
		name, code string
		edit       func(*regProfile)
	}{
		{"revision128", "BAD_INPUT", func(p *regProfile) { p.Policy.Revision = strings.Repeat("r", 128) }}, // valid profile reaches malformed construction
		{"revision129", "REGISTRATION_POLICY_REFUSED", func(p *regProfile) { p.Policy.Revision = strings.Repeat("r", 129) }},
		{"total-below-per", "REGISTRATION_POLICY_REFUSED", func(p *regProfile) { p.Policy.TotalFeeCapAtoms = "99999" }},
		{"wrong-network", "REGISTRATION_POLICY_REFUSED", func(p *regProfile) { p.Network = "other" }},
		{"amount-noncanonical", "BAD_INPUT", func(p *regProfile) { p.Policy.PerTxFeeCapAtoms = "01" }},
		{"signed-time-overflow", "BAD_INPUT", func(p *regProfile) { p.Policy.CreatedAt = 1 << 63 }},
	} {
		p := e.profile
		tc.edit(&p)
		raw := regTestJSON(t, p)
		regTestWrite(t, e.profilePath, raw)
		args = e.args("reserve", input, out)
		for i := range args {
			if args[i] == "--profile-sha256" {
				args[i+1] = regDigest(raw)
			}
		}
		en, exit := regTestInvoke(t, args)
		regTestRefusal(t, en, exit, tc.code, filepath.Join(out, "bundle.json"))
	}
	regTestWrite(t, e.profilePath, e.profileRaw)
	for _, tc := range []func(*regPin){func(p *regPin) { p.Group = "Fixture/recovery@1" }, func(p *regPin) { p.Account = "fixture/namecoin@01" }, func(p *regPin) { p.Path = "m/84h/7h/1h" }, func(p *regPin) { p.XPub = p.XPub[:len(p.XPub)-1] + "0" }, func(p *regPin) { p.Fingerprint = "ABCDEF00" }} {
		var pin regPin
		json.Unmarshal(e.pin, &pin)
		tc(&pin)
		raw := regTestJSON(t, pin)
		regTestWrite(t, e.pinPath, raw)
		args = e.args("reserve", input, out)
		for i := range args {
			if args[i] == "--account-pin-sha256" {
				args[i+1] = regDigest(raw)
			}
		}
		en, exit := regTestInvoke(t, args)
		regTestRefusal(t, en, exit, "BAD_INPUT", filepath.Join(out, "bundle.json"))
		if en.Network != e.profile.Network {
			t.Fatal("known profile network lost")
		}
	}
}

// Field types and canonical integers are closed for request/check-result,
// including actual Unix exit 0..255. A genuine original check is the control.
func TestRegistrationRequestScalars(t *testing.T) {
	e, reservation, p := regTestFrozen(t, "two-stage")
	_, en, exit := e.run(t, "check-result", "valid-scalar", regTestCheck(p))
	regTestSuccess(t, en, exit)
	for _, tc := range []struct {
		name, command string
		raw           []byte
	}{
		{"exit-string", "check-result", bytes.Replace(regTestJSON(t, regTestCheck(p)), []byte(`"process_exit":0`), []byte(`"process_exit":"0"`), 1)},
		{"exit-negative", "check-result", bytes.Replace(regTestJSON(t, regTestCheck(p)), []byte(`"process_exit":0`), []byte(`"process_exit":-0`), 1)},
		{"exit-overflow", "check-result", bytes.Replace(regTestJSON(t, regTestCheck(p)), []byte(`"process_exit":0`), []byte(`"process_exit":256`), 1)},
		{"exit-exponent", "check-result", bytes.Replace(regTestJSON(t, regTestCheck(p)), []byte(`"process_exit":0`), []byte(`"process_exit":0e0`), 1)},
		{"lifetime-string", "request", regTestJSON(t, map[string]any{"schema": regPrefix + "request/1", "plan_bundle": reservation, "plan_bundle_sha256": regTestBundleHash(t, reservation), "slot": "A", "valid_for_seconds": "600"})},
		{"lifetime-zero", "request", regTestJSON(t, regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "A", 0})},
		{"lifetime-overflow", "request", regTestJSON(t, regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "A", 601})},
		{"directory-reference", "request", regTestJSON(t, regRequest{regPrefix + "request/1", filepath.Dir(reservation), regTestBundleHash(t, reservation), "A", 600})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := filepath.Join(e.dir, tc.name+".json")
			regTestWrite(t, input, tc.raw)
			out := filepath.Join(e.dir, tc.name)
			en, exit := regTestInvoke(t, e.args(tc.command, input, out))
			regTestRefusal(t, en, exit, "BAD_INPUT", filepath.Join(out, "bundle.json"))
		})
	}
	// Policy syntax at the allowed revision boundary is independently admitted.
	profile := e.profile
	profile.Policy.Revision = strings.Repeat("r", 128)
	if _, f := regProfileAdmission(regTestJSON(t, profile)); f != nil {
		t.Fatal("128-byte profile revision refused")
	}
}

// A refusing stdout writer gets one attempt and the existing fixed diagnostic;
// a writable fresh output is the nearby control. A completed bundle is retained
// even when its envelope cannot be delivered, and retry cannot overwrite it.
func TestRegistrationOutputWriterFailure(t *testing.T) {
	e := newRegTestEnv(t, "two-stage", true)
	var pin regPin
	json.Unmarshal(e.pin, &pin)
	pin.Schema = regPrefix + "account-pin/1"
	_, en, exit := e.run(t, "account-pin", "writable", pin)
	regTestSuccess(t, en, exit)
	input := filepath.Join(e.dir, "writer-input.json")
	regTestWrite(t, input, regTestJSON(t, pin))
	out := filepath.Join(e.dir, "writer-output")
	writer := &nostrRefusingWriter{}
	var diagnostics bytes.Buffer
	exit = Run(context.Background(), e.args("account-pin", input, out), writer, &diagnostics)
	if exit != 1 || writer.calls != 1 || diagnostics.String() != "Could not write the result.\n" {
		t.Fatal("registration writer fallback differs")
	}
	before := regTestRead(t, filepath.Join(out, "bundle.json"))
	en, exit = regTestInvoke(t, e.args("account-pin", input, out))
	if exit != 1 || en.Error == nil || en.Error.Code != "REGISTRATION_FILES" || !bytes.Equal(before, regTestRead(t, filepath.Join(out, "bundle.json"))) {
		t.Fatal("writer failure output was overwritten")
	}
}
