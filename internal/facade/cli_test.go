package facade

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeInput(t *testing.T, value any) string {
	t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(t.TempDir(), "input.json")
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	return p
}

// This checker covers machine-output shape and fixture secret disclosure. Its
// positive/negative control below proves it recognizes the intended violations.
func outputSafe(b []byte) bool {
	if bytes.Contains(b, []byte("fixture-password")) {
		return false
	}
	var e map[string]json.RawMessage
	if validateJSON(b) != nil || json.Unmarshal(b, &e) != nil || len(e) != 6 {
		return false
	}
	for _, k := range []string{"schema", "ok", "command", "network", "result", "error"} {
		if _, ok := e[k]; !ok {
			return false
		}
	}
	return true
}

func runCLI(t *testing.T, args ...string) (Envelope, int, []byte) {
	t.Helper()
	var out, diagnostics bytes.Buffer
	code := Run(context.Background(), args, &out, &diagnostics)
	if len(args) >= 2 && args[0] == "nostr" && (args[1] == "profile-prepare" || args[1] == "profile-verify") {
		if problem := nostrWireProblem(out.Bytes(), "nostr "+args[1]); problem != "" {
			t.Fatalf("invalid Nostr wire envelope: %s", problem)
		}
	}
	if diagnostics.Len() != 0 || !outputSafe(out.Bytes()) {
		t.Fatal("unsafe CLI output")
	}
	var e Envelope
	if json.Unmarshal(out.Bytes(), &e) != nil {
		t.Fatal("bad envelope")
	}
	if e.Schema != ResultSchema || e.OK != (code == 0) || (e.OK && e.Error != nil) || (!e.OK && (e.Error == nil || e.Result != nil)) {
		t.Fatal("inconsistent result")
	}
	return e, code, out.Bytes()
}

// The offline command works without config, node or signer and returns no xpub;
// malformed/private-shaped input and flag ambiguity stay sanitized failures.
func TestCLIOfflineAndRefusals(t *testing.T) {
	r := validDerivation(t)
	path := writeInput(t, r)
	e, code, raw := runCLI(t, "address", "derive", "--request", path, "--json")
	if code != 0 || e.Network != "main" || bytes.Contains(raw, []byte(r.XPub)) {
		t.Fatal("offline derivation failed or echoed input")
	}
	for _, args := range [][]string{
		{"address", "derive", "--request", path},
		{"address", "derive", "--request", path, "--json", "--json"},
		{"address", "derive", "--request", path, "--json", "--config", "fixture-password"},
		{"address", "derive", "--request", "fixture-password", "--json"},
		{"arbitrary", "fixture-password", "--json"},
		{"balance", "watch", "--mode", "wallet-visible", "--json"},
	} {
		e, code, _ := runCLI(t, args...)
		if code == 0 || e.Error == nil {
			t.Fatal("invalid command admitted")
		}
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte(`{"name":"fixture-password","name":"duplicate"}`), 0600)
	e, code, _ = runCLI(t, "name", "show", "--request", bad, "--config", "absent", "--json")
	if code != 2 || e.Error.Code != "BAD_INPUT" {
		t.Fatal("malformed request must fail before node preparation")
	}
}

// The real CLI/config/result path docks with the bounded fake node. Scan mode
// defaults explicitly to utxo-scan and emits the agreed finite coverage fields.
func TestCLIOnlineDocking(t *testing.T) {
	c, methods, done := nodeFixture(t, "", func() {})
	defer done()
	config := writeInput(t, c.config)
	name := writeInput(t, struct {
		Name string `json:"name"`
	}{"d/example"})
	r := validDerivation(t)
	scan := writeInput(t, ScanRequest{Schema: ScanSchema, Network: r.Network, XPub: r.XPub, Branches: []uint32{0, 1}, Count: 2, AddressType: "p2wpkh"})
	for _, args := range [][]string{
		{"node", "health", "--config", config, "--json"},
		{"name", "show", "--config", config, "--request", name, "--json"},
		{"balance", "watch", "--config", config, "--request", scan, "--json"},
	} {
		e, code, _ := runCLI(t, args...)
		if code != 0 {
			t.Fatalf("docking refused: %#v", e.Error)
		}
	}
	scans := 0
	for _, m := range *methods {
		if m == "scantxoutset" {
			scans++
		}
	}
	if scans != 1 {
		t.Fatal("scan replay")
	}
}

// Missing names keep their resource code/exit and a fixed clear diagnostic,
// without echoing the requested name or backend text. An active name still
// succeeds through the same complete CLI/config path.
func TestCLINameNotFoundMessage(t *testing.T) {
	for _, mode := range []string{"", "absent"} {
		t.Run(mode, func(t *testing.T) {
			c, _, done := nodeFixture(t, mode, func() {})
			defer done()
			config := writeInput(t, c.config)
			request := writeInput(t, struct {
				Name string `json:"name"`
			}{"d/example"})
			e, code, raw := runCLI(t, "name", "show", "--config", config, "--request", request, "--json")
			if mode == "" {
				if code != 0 || e.Error != nil || e.Result == nil {
					t.Fatal("active name control refused")
				}
				return
			}
			if code != 3 || e.Error == nil || e.Error.Code != "NAME_NOT_FOUND" || e.Error.Retryable || e.Error.Message != "The requested name was not found." || e.Result != nil || bytes.Contains(raw, []byte("d/example")) || bytes.Contains(raw, []byte("name never existed")) {
				t.Fatalf("wrong missing-name diagnostic: %#v", e.Error)
			}
		})
	}
}

// Complete public requests preserve every explicit path length and index. A null
// in any supported position must fail at input decoding (empty network), before
// selected configuration/credentials are prepared or any fixture RPC is sent.
func TestCLIExplicitIndexArrays(t *testing.T) {
	replaceArray := func(t *testing.T, request any, field string, value any) string {
		t.Helper()
		b, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(b, &fields); err != nil {
			t.Fatal(err)
		}
		fields[field], err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return writeInput(t, fields)
	}
	r := validDerivation(t)
	r.Count = 1
	for length := 0; length <= 8; length++ {
		t.Run(fmt.Sprintf("path-length-%d", length), func(t *testing.T) {
			path := make([]uint32, length)
			for i := range path {
				path[i] = uint32(i % 2)
			}
			request := replaceArray(t, r, "relative_path", path)
			e, code, raw := runCLI(t, "address", "derive", "--request", request, "--json")
			var got struct {
				Result struct {
					Addresses []Address `json:"addresses"`
				} `json:"result"`
			}
			if code != 0 || e.Error != nil || json.Unmarshal(raw, &got) != nil || len(got.Result.Addresses) != 1 || !slices.Equal(got.Result.Addresses[0].RelativePath, append(slices.Clone(path), r.Start)) {
				t.Fatal("valid explicit path changed or refused")
			}
			for position := range path {
				t.Run(fmt.Sprintf("null-at-%d", position), func(t *testing.T) {
					indices := make([]any, length)
					for i, index := range path {
						indices[i] = index
					}
					indices[position] = nil
					request := replaceArray(t, r, "relative_path", indices)
					e, code, _ := runCLI(t, "address", "derive", "--request", request, "--json")
					if code != 2 || e.Error.Code != "BAD_INPUT" || e.Network != "" {
						t.Fatal("null path component was not refused at input decoding")
					}
				})
			}
		})
	}

	c, methods, done := nodeFixture(t, "", func() {})
	defer done()
	config := writeInput(t, c.config) // watch_wallet is legitimately omitted.
	scan := ScanRequest{Schema: ScanSchema, Network: r.Network, XPub: r.XPub, Branches: []uint32{0, 1}, Count: 2, AddressType: "p2wpkh"}
	e, code, _ := runCLI(t, "balance", "watch", "--mode", "utxo-scan", "--config", config, "--request", writeInput(t, scan), "--json")
	if code != 0 || e.Error != nil || len(*methods) == 0 {
		t.Fatal("valid scan control refused or fixture not reached")
	}
	for position := range scan.Branches {
		t.Run(fmt.Sprintf("branch-null-at-%d", position), func(t *testing.T) {
			branches := []any{0, 1}
			branches[position] = nil
			request := replaceArray(t, scan, "branches", branches)
			before := len(*methods)
			e, code, _ := runCLI(t, "balance", "watch", "--mode", "utxo-scan", "--config", config, "--request", request, "--json")
			if code != 2 || e.Error.Code != "BAD_INPUT" || e.Network != "" || len(*methods) != before {
				t.Fatal("null branch reached configuration preparation or RPC")
			}
		})
	}
}

// The output checker must fail for the planted secret and malformed envelope,
// rather than passing because no command ran or because parsing crashed.
func TestOutputCheckerControls(t *testing.T) {
	good := []byte(`{"schema":"swarma-identity/result/1","ok":false,"command":"","network":"","result":null,"error":{"code":"BAD_INPUT","message":"fixed","retryable":false}}`)
	if !outputSafe(good) {
		t.Fatal("positive control refused")
	}
	if outputSafe([]byte(strings.Replace(string(good), "fixed", "fixture-password", 1))) || outputSafe([]byte(`{"ok":true}`)) {
		t.Fatal("planted violation was not detected")
	}
}
