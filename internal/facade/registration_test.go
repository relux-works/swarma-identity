package facade

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	reg "github.com/relux-works/swarma-identity/internal/registration"
)

type regTestEnv struct {
	dir, profilePath, pinPath string
	profile                   regProfile
	pin, profileRaw           []byte
	reserve                   regReserve
}

func regTestRead(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func regTestWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func regTestJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func regTestDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
func newRegTestEnv(t *testing.T, mode string, live bool) *regTestEnv {
	t.Helper()
	dir := regTestDir(t)
	pin := regTestRead(t, "../registration/testdata/core28/account-pin.json")
	var m struct {
		Network string     `json:"network"`
		Genesis string     `json:"genesis"`
		Policy  reg.Policy `json:"policy"`
		Funding struct {
			Hex  string `json:"tx_hex"`
			TxID string `json:"txid"`
			Vout uint32 `json:"vout"`
		} `json:"funding"`
		Registrations []struct {
			Name  string `json:"name_hex"`
			Path  string `json:"name_output_path"`
			Value struct {
				Hex string `json:"value_hex"`
			} `json:"future_value"`
		} `json:"registrations"`
		Transactions []struct {
			Inputs []struct {
				Path string `json:"path"`
			} `json:"inputs"`
			Outputs []struct {
				Path string `json:"path"`
			} `json:"outputs"`
			Fee string `json:"fee_atoms"`
		} `json:"transactions"`
	}
	if e := json.Unmarshal(regTestRead(t, "../registration/testdata/core28/"+mode+"/reservation-manifest.json"), &m); e != nil {
		t.Fatal(e)
	}
	profile := regProfile{regPrefix + "profile/1", m.Network, m.Genesis, m.Policy}
	if live {
		profile.Policy.CreatedAt = uint64(time.Now().Unix()) - 60
		profile.Policy.ReleaseNotAfter = profile.Policy.CreatedAt + 86400
	}
	env := &regTestEnv{dir: dir, profilePath: filepath.Join(dir, "selected-profile.json"), pinPath: filepath.Join(dir, "selected-pin.json"), profile: profile, pin: pin}
	env.profileRaw = regTestJSON(t, profile)
	regTestWrite(t, env.profilePath, env.profileRaw)
	regTestWrite(t, env.pinPath, pin)
	funding := filepath.Join(dir, "funding.hex")
	regTestWrite(t, funding, []byte(m.Funding.Hex))
	env.reserve = regReserve{regPrefix + "reserve/1", regFunding{funding, m.Funding.TxID, m.Funding.Vout, m.Transactions[0].Inputs[0].Path}, []regName{}, []string{}, []string{}}
	for i, n := range m.Registrations {
		name, e := hex.DecodeString(n.Name)
		if e != nil {
			t.Fatal(e)
		}
		env.reserve.Names = append(env.reserve.Names, regName{string(name), n.Path, n.Value.Hex})
		env.reserve.Change = append(env.reserve.Change, m.Transactions[i].Outputs[1].Path)
		env.reserve.Fees = append(env.reserve.Fees, m.Transactions[i].Fee)
	}
	return env
}
func (e *regTestEnv) args(command, request, out string) []string {
	a := []string{"registration", command, "--request", request, "--out-dir", out, "--json"}
	if command != "account-pin" {
		a = append(a, "--profile", e.profilePath, "--profile-sha256", regDigest(e.profileRaw), "--account-pin", e.pinPath, "--account-pin-sha256", regDigest(e.pin))
	}
	return a
}
func (e *regTestEnv) run(t *testing.T, command, label string, v any) (string, Envelope, int) {
	t.Helper()
	input := filepath.Join(e.dir, label+"-input.json")
	regTestWrite(t, input, regTestJSON(t, v))
	out := filepath.Join(e.dir, label)
	var stdout, stderr bytes.Buffer
	exit := Run(context.Background(), e.args(command, input, out), &stdout, &stderr)
	var envelope Envelope
	if json.Unmarshal(stdout.Bytes(), &envelope) != nil || stderr.Len() != 0 {
		t.Fatalf("bad envelope %q / %q", stdout.Bytes(), stderr.Bytes())
	}
	if !bytes.HasSuffix(stdout.Bytes(), []byte("\n")) || bytes.Count(stdout.Bytes(), []byte("\n")) != 1 {
		t.Fatal("envelope line")
	}
	regTestEnvelopeWire(t, stdout.Bytes())
	if envelope.OK {
		regTestBundleWire(t, command, filepath.Join(out, "bundle.json"), stdout.Bytes())
	}
	return filepath.Join(out, "bundle.json"), envelope, exit
}
func regTestSuccess(t *testing.T, e Envelope, exit int) {
	t.Helper()
	if exit != 0 || !e.OK || e.Error != nil {
		t.Fatalf("exit %d: %+v", exit, e.Error)
	}
}
func regTestRefusal(t *testing.T, e Envelope, exit int, code string, out string) {
	t.Helper()
	f := regFailure(code)
	if exit != f.Exit || e.OK || e.Result != nil || e.Error == nil || e.Error.Code != code || e.Error.Message != f.Message || e.Error.Retryable {
		t.Fatalf("wrong refusal exit=%d envelope=%+v", exit, e)
	}
	if _, err := os.Lstat(filepath.Dir(out)); !os.IsNotExist(err) {
		t.Fatalf("refusal created output: %v", err)
	}
}
func regTestBundleHash(t *testing.T, path string) string {
	t.Helper()
	return regDigest(regTestRead(t, path))
}
func regTestPlanner(t *testing.T, e *regTestEnv) *reg.Planner {
	t.Helper()
	p, err := reg.NewPlanner(e.pin, reg.Profile{Network: e.profile.Network, Genesis: e.profile.Genesis, Policy: e.profile.Policy})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func regTestSession(t *testing.T, e *regTestEnv) *regSession {
	t.Helper()
	return &regSession{freezer: newRegFreezer(), planner: regTestPlanner(t, e), profile: e.profile, profileRaw: e.profileRaw, pinRaw: e.pin, profileHash: regDigest(e.profileRaw), pinHash: regDigest(e.pin), active: map[string]bool{}}
}

// Test-only signing derives published BIP32 vector 1 authority in memory, only
// for isolated synthetic bundles. Product CLI exposes no key/signing option.
func regTestSign(t *testing.T, requestPath string) []byte {
	t.Helper()
	var r struct {
		RequestID       string `json:"request_id"`
		SittingID       string `json:"sitting_id"`
		Slot            string `json:"slot"`
		Network         string `json:"network"`
		PSBT            string `json:"psbt"`
		Plan            string `json:"plan_manifest_utf8"`
		PlanHash        string `json:"plan_sha256"`
		ReservationHash string `json:"reservation_plan_sha256"`
	}
	if err := json.Unmarshal(regTestRead(t, requestPath), &r); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(r.PSBT)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	fetch := txscript.NewMultiPrevOutFetcher(nil)
	for i, in := range packet.Inputs {
		outpoint := packet.UnsignedTx.TxIn[i].PreviousOutPoint
		fetch.AddPrevOut(outpoint, in.NonWitnessUtxo.TxOut[outpoint.Index])
	}
	hashes := txscript.NewTxSigHashes(packet.UnsignedTx, fetch)
	signatures := []map[string]any{}
	for i := range packet.Inputs {
		in := &packet.Inputs[i]
		d := in.Bip32Derivation[0]
		key := master
		for _, index := range d.Bip32Path {
			key, err = key.Derive(index)
			if err != nil {
				t.Fatal(err)
			}
		}
		priv, err := key.ECPrivKey()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(priv.PubKey().SerializeCompressed(), d.PubKey) {
			t.Fatal("test vector origin mismatch")
		}
		prev := fetch.FetchPrevOutput(packet.UnsignedTx.TxIn[i].PreviousOutPoint)
		program := prev.PkScript[len(prev.PkScript)-22:]
		h, err := txscript.CalcWitnessSigHash(program, hashes, txscript.SigHashAll, packet.UnsignedTx, i, prev.Value)
		if err != nil {
			t.Fatal(err)
		}
		der := ecdsa.Sign(priv, h).Serialize()
		in.PartialSigs = []*psbt.PartialSig{{PubKey: d.PubKey, Signature: append(append([]byte(nil), der...), 1)}}
		signatures = append(signatures, map[string]any{"index": i, "pubkey": hex.EncodeToString(d.PubKey), "algorithm": "secp256k1-ecdsa", "encoding": "strict-der-low-s", "sighash": "ALL", "signature": hex.EncodeToString(der)})
	}
	var signed bytes.Buffer
	if err := packet.Serialize(&signed); err != nil {
		t.Fatal(err)
	}
	var plan struct {
		Group   string `json:"group"`
		Account string `json:"account"`
		PinHash string `json:"account_pin_sha256"`
	}
	if err := json.Unmarshal([]byte(r.Plan), &plan); err != nil {
		t.Fatal(err)
	}
	frame := regTestRead(t, filepath.Join(filepath.Dir(requestPath), "review-frame.bin"))
	return regCanonical(map[string]any{"schema": "keyvault-namecoin-psbt-result/2", "signed_psbt": base64.StdEncoding.EncodeToString(signed.Bytes()), "receipt": map[string]any{"schema": "keyvault-namecoin-psbt-receipt/2", "status": "SIGNED", "request_id": r.RequestID, "sitting_id": r.SittingID, "slot": r.Slot, "plan_sha256": r.PlanHash, "reservation_plan_sha256": r.ReservationHash, "review_sha256": regDigest(frame), "network": r.Network, "group": plan.Group, "account": plan.Account, "account_pin_sha256": plan.PinHash, "unsigned_txid": packet.UnsignedTx.TxHash().String(), "signed_psbt_sha256": regDigest(signed.Bytes()), "input_signatures": signatures, "journal_sequence": 1, "journal_head_sha256": strings.Repeat("ab", 32)}})
}
func regTestParent(t *testing.T, env *regTestEnv, bundle, label string) regParent {
	t.Helper()
	result := regTestSign(t, filepath.Join(filepath.Dir(bundle), "request.json"))
	stdout := []byte(fmt.Sprintf("{\"schema\":\"keyvault-namecoin-psbt-ack/2\",\"status\":\"SIGNED\",\"result_sha256\":\"%s\"}\n", regDigest(result)))
	rpath, spath := filepath.Join(env.dir, label+"-result.json"), filepath.Join(env.dir, label+"-stdout.txt")
	regTestWrite(t, rpath, result)
	regTestWrite(t, spath, stdout)
	return regParent{bundle, regTestBundleHash(t, bundle), rpath, regDigest(result), spath, regDigest(stdout), 0}
}
func regTestCheck(p regParent) regCheck {
	return regCheck{regPrefix + "check-result/1", p.Bundle, p.BundleHash, p.Result, p.ResultHash, p.Stdout, p.StdoutHash, p.Exit}
}

// Every command runs through the public facade with explicit file pins, actual
// clock and OS randomness in both release modes. Synthetic signatures support
// public verification only; shared reservation references are a valid DAG.
func TestRegistrationFileFlow(t *testing.T) {
	for _, mode := range []string{"two-stage", "all-four-before-release"} {
		t.Run(mode, func(t *testing.T) {
			e := newRegTestEnv(t, mode, true)
			var pin regPin
			if json.Unmarshal(e.pin, &pin) != nil {
				t.Fatal("pin fixture")
			}
			pin.Schema = regPrefix + "account-pin/1"
			pb, en, exit := e.run(t, "account-pin", "pin", pin)
			regTestSuccess(t, en, exit)
			if en.Network != "" || !bytes.Equal(regTestRead(t, filepath.Join(filepath.Dir(pb), "account-pin.json")), e.pin) {
				t.Fatal("pin changed")
			}
			reservation, en, exit := e.run(t, "reserve", "reservation", e.reserve)
			regTestSuccess(t, en, exit)
			var saved regReservationState
			if !regState(regTestRead(t, filepath.Join(filepath.Dir(reservation), "reservation-state.json")), &saved, "reservation-state") {
				t.Fatal("saved reservation")
			}
			if saved.Names[0].Rand == saved.Names[1].Rand || !regHex(saved.Names[0].Rand, 20) {
				t.Fatal("openings")
			}
			parents := []regParent{}
			for _, slot := range []string{"A", "B"} {
				bundle, en, exit := e.run(t, "request", "request-"+slot, regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), slot, 600})
				regTestSuccess(t, en, exit)
				parent := regTestParent(t, e, bundle, slot)
				parents = append(parents, parent)
				checked, en, exit := e.run(t, "check-result", "checked-"+slot, regTestCheck(parent))
				regTestSuccess(t, en, exit)
				var output regPublicResult
				if !regState(regTestRead(t, filepath.Join(filepath.Dir(checked), "public-result.json")), &output, "public-result") {
					t.Fatal("public result")
				}
				if output.Sequence != 1 || strings.Contains(string(regTestRead(t, checked)), "native") {
					t.Fatal("public claims")
				}
			}
			var request struct {
				PlanHash string `json:"plan_sha256"`
			}
			json.Unmarshal(regTestRead(t, filepath.Join(filepath.Dir(parents[0].Bundle), "request.json")), &request)
			rows := []map[string]string{}
			for _, n := range saved.Names {
				value := n.Value
				if value == "" {
					value = saved.Names[1].Value
				}
				v, _ := hex.DecodeString(value)
				rows = append(rows, map[string]string{"name_hex": hex.EncodeToString([]byte(n.Name)), "value_hex": value, "value_sha256": regDigest(v)})
			}
			pinPath := filepath.Join(e.dir, "reveal-pin.json")
			pinRaw := regTestJSON(t, map[string]any{"schema": "keyvault-namecoin-reveal-values/1", "reservation_plan_sha256": request.PlanHash, "registrations": rows})
			regTestWrite(t, pinPath, pinRaw)
			reveal, en, exit := e.run(t, "reveal", "reveal", regReveal{regPrefix + "reveal/1", reservation, regTestBundleHash(t, reservation), parents, pinPath, regDigest(pinRaw), []string{"m/84h/7h/0h/1/2", "m/84h/7h/0h/1/3"}, []string{"100000", "100000"}})
			regTestSuccess(t, en, exit)
			for _, slot := range []string{"C", "D"} {
				bundle, en, exit := e.run(t, "request", "request-"+slot, regRequest{regPrefix + "request/1", reveal, regTestBundleHash(t, reveal), slot, 600})
				regTestSuccess(t, en, exit)
				parent := regTestParent(t, e, bundle, slot)
				_, en, exit = e.run(t, "check-result", "checked-"+slot, regTestCheck(parent))
				regTestSuccess(t, en, exit)
			}
		})
	}
}

func regTestWireKeys(t *testing.T, raw []byte, want string) map[string]json.RawMessage {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatal("wire object missing")
	}
	keys := []string{}
	fields := map[string]json.RawMessage{}
	for d.More() {
		tok, err = d.Token()
		if err != nil {
			t.Fatal(err)
		}
		key, ok := tok.(string)
		if !ok {
			t.Fatal("wire key")
		}
		keys = append(keys, key)
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			t.Fatal(err)
		}
		fields[key] = value
	}
	if strings.Join(keys, ",") != want {
		t.Fatalf("registration wire keys: got %v want %s", keys, want)
	}
	return fields
}
func regTestEnvelopeWire(t *testing.T, raw []byte) {
	t.Helper()
	fields := regTestWireKeys(t, raw, "schema,ok,command,network,result,error")
	var ok bool
	json.Unmarshal(fields["ok"], &ok)
	if !ok {
		regTestWireKeys(t, fields["error"], "code,message,retryable")
		return
	}
	result := regTestWireKeys(t, fields["result"], "bundle_sha256,files")
	var files []json.RawMessage
	if json.Unmarshal(result["files"], &files) != nil {
		t.Fatal("wire files")
	}
	for _, row := range files {
		regTestWireKeys(t, row, "name,size_bytes,sha256")
	}
}

// These literal payload orders and field orders are the public file contract,
// independently checked against every successful CLI output and disk index.
func regTestBundleWire(t *testing.T, command, indexPath string, stdout []byte) {
	t.Helper()
	raw := regTestRead(t, indexPath)
	fields := regTestWireKeys(t, raw, "schema,kind,profile_sha256,account_pin_sha256,files")
	var rows []json.RawMessage
	json.Unmarshal(fields["files"], &rows)
	names := []string{}
	for _, row := range rows {
		record := regTestWireKeys(t, row, "name,size_bytes,sha256")
		var name, hash string
		var size uint64
		json.Unmarshal(record["name"], &name)
		json.Unmarshal(record["sha256"], &hash)
		json.Unmarshal(record["size_bytes"], &size)
		b := regTestRead(t, filepath.Join(filepath.Dir(indexPath), name))
		if regDigest(b) != hash || uint64(len(b)) != size {
			t.Fatal("wire commitment mismatch")
		}
		names = append(names, name)
	}
	want := map[string]string{
		"account-pin":  "account-pin.json",
		"reserve":      "profile.json,account-pin.json,funding.hex,reservation-state.json,reservation-manifest.json,A.psbt,B.psbt,transaction-index.json",
		"reveal":       "profile.json,account-pin.json,reveal-state.json,reveal-values-pin.json,reveal-manifest.json,C.psbt,D.psbt,transaction-index.json",
		"request":      "profile.json,account-pin.json,request-state.json,request.json,review-frame.bin",
		"check-result": "profile.json,account-pin.json,verification-state.json,verified-transaction.hex,public-result.json",
	}[command]
	if strings.Join(names, ",") != want {
		t.Fatal("payload order differs from file contract")
	}
	var envelope struct {
		Result struct {
			Hash  string          `json:"bundle_sha256"`
			Files json.RawMessage `json:"files"`
		} `json:"result"`
	}
	json.Unmarshal(stdout, &envelope)
	if envelope.Result.Hash != regDigest(raw) || !bytes.Equal(envelope.Result.Files, fields["files"]) || !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatal("success does not bind exact index")
	}
}
