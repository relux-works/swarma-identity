package facade

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const fixtureTip = "1111111111111111111111111111111111111111111111111111111111111111"

func nodeFixture(t *testing.T, mode string, cancel context.CancelFunc) (*Client, *[]string, func()) {
	t.Helper()
	methods := []string{}
	r := validDerivation(t)
	r.Count = 1
	addresses, f := Derive(r)
	if f != nil {
		t.Fatal(f.Code)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var q struct {
			ID     int               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			t.Error("bad RPC request")
			return
		}
		methods = append(methods, q.Method)
		var value any
		var rpcError any
		switch q.Method {
		case "getnetworkinfo":
			version := 280000
			if mode == "version" {
				version = 290000
			}
			value = map[string]any{"version": version, "connections": 10}
		case "getblockchaininfo":
			value = map[string]any{"chain": "main", "bestblockhash": fixtureTip, "blocks": 100, "headers": 100, "initialblockdownload": mode == "ibd", "verificationprogress": json.Number("1.0"), "pruned": true}
			if mode == "network" {
				value.(map[string]any)["chain"] = "test"
			}
			if mode == "null-sync" {
				value.(map[string]any)["initialblockdownload"] = nil
			}
		case "getblockhash":
			value = MainGenesis
			if mode == "genesis" {
				value = fixtureTip
			}
		case "getbestblockhash":
			value = fixtureTip
			if mode == "tip" || mode == "name-tip-advanced" || mode == "expired-moving" {
				value = strings.Repeat("2", 64)
			}
		case "name_show":
			if mode == "absent" {
				rpcError = map[string]any{"code": -4, "message": "name never existed: d/example"}
				break
			}
			var options map[string]any
			json.Unmarshal(q.Params[1], &options)
			if options["allowExpired"] != true || options["valueEncoding"] != "hex" || options["nameEncoding"] != "utf8" {
				t.Error("implicit name options")
			}
			value = map[string]any{"name": "d/example", "value": "ff007b7d", "expired": mode == "expired", "expires_in": 100, "txid": strings.Repeat("3", 64), "vout": 0, "height": 99}
			if mode == "expired" || mode == "expired-future" || mode == "expired-moving" {
				value.(map[string]any)["expired"] = true
				value.(map[string]any)["expires_in"] = -1
			}
			if mode == "name-tip-advanced" || mode == "name-height-future" || mode == "expired-future" || mode == "expired-moving" {
				value.(map[string]any)["height"] = 101
			}
			if mode == "expired-zero" {
				value.(map[string]any)["expired"] = true
				value.(map[string]any)["expires_in"] = 0
			}
			if mode == "inconsistent-expiry" {
				value.(map[string]any)["expires_in"] = 0
			}
			if mode == "large-name" {
				value.(map[string]any)["value"] = strings.Repeat("ff", 521)
			}
			if mode == "bad-value" {
				value.(map[string]any)["value"] = "zz"
			}
			if mode == "wrong-name" {
				value.(map[string]any)["name"] = "d/other"
			}
		case "scantxoutset":
			if mode == "busy" {
				rpcError = map[string]any{"code": -8, "message": "Scan already in progress, use action abort or status"}
				break
			}
			if mode == "uncertain" {
				cancel()
				return
			}
			var action string
			json.Unmarshal(q.Params[0], &action)
			if action != "start" {
				t.Error("non-start action")
			}
			var descriptors []map[string]json.RawMessage
			if json.Unmarshal(q.Params[1], &descriptors) != nil || len(descriptors) != 2 {
				t.Error("descriptor set")
			}
			for i, d := range descriptors {
				var desc string
				var limits []uint32
				json.Unmarshal(d["desc"], &desc)
				json.Unmarshal(d["range"], &limits)
				wantBranch := "0"
				if i == 1 {
					wantBranch = "1"
				}
				if desc != "wpkh("+validDerivation(t).XPub+"/"+wantBranch+"/*)" || len(limits) != 2 || limits[0] != 0 || limits[1] != 1 {
					t.Error("wrong explicit descriptor/range")
				}
			}
			u := map[string]any{"txid": strings.Repeat("4", 64), "vout": 0, "scriptPubKey": addresses[0].scriptHex, "amount": json.Number("1.25"), "coinbase": false, "height": 99}
			if mode == "outside" {
				u["scriptPubKey"] = "0014" + strings.Repeat("00", 20)
			}
			if mode == "negative" {
				u["amount"] = json.Number("-1.25")
			}
			unspents := []any{u}
			if mode == "name-script" {
				u["scriptPubKey"] = "51" + addresses[0].scriptHex
			}
			if mode == "missing-coinbase" {
				delete(u, "coinbase")
			}
			if mode == "coinbase" {
				u["coinbase"] = true
			}
			if mode == "fractional-index" {
				u["vout"] = json.Number("0.5")
			}
			if mode == "future-output" {
				u["height"] = 101
			}
			if mode == "duplicate" {
				unspents = append(unspents, u)
			}
			total := json.Number("1.25")
			if mode == "wrong-total" {
				total = json.Number("1.26")
			}
			if mode == "zero" {
				unspents = []any{}
				total = json.Number("0.0")
			}
			value = map[string]any{"success": mode != "incomplete", "bestblock": fixtureTip, "height": 100, "unspents": unspents, "total_amount": total}
			if mode == "null-unspents" {
				value.(map[string]any)["unspents"] = nil
			}
			if mode == "missing-total" {
				delete(value.(map[string]any), "total_amount")
			}
			if mode == "scan-tip" {
				value.(map[string]any)["height"] = 101
			}
		default:
			t.Errorf("forbidden fixture method %s", q.Method)
			w.WriteHeader(500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": q.ID, "result": value, "error": rpcError})
	}))
	c, f := NewClient(testConfig(t, s.URL))
	if f != nil {
		t.Fatal(f.Code)
	}
	return c, &methods, func() { c.Close(); s.Close() }
}

// Health distinguishes a successful unsynced observation from wrong network or
// unsupported version. Name reads preserve raw non-UTF8 value bytes and refuse
// absent/expired/unsynced names rather than treating them as current identity.
func TestHealthAndName(t *testing.T) {
	for _, tc := range []struct{ mode, code string }{{"", ""}, {"expired", "NAME_EXPIRED"}, {"absent", "NAME_NOT_FOUND"}, {"ibd", "NODE_UNSYNCED"}, {"genesis", "WRONG_NETWORK"}, {"network", "WRONG_NETWORK"}, {"version", "UNSUPPORTED_CAPABILITY"}, {"tip", "SNAPSHOT_CHANGED"}, {"null-sync", "PROVIDER_PROTOCOL"}, {"large-name", "PROVIDER_PROTOCOL"}, {"bad-value", "PROVIDER_PROTOCOL"}, {"wrong-name", "PROVIDER_PROTOCOL"}} {
		t.Run(tc.mode, func(t *testing.T) {
			c, _, done := nodeFixture(t, tc.mode, func() {})
			defer done()
			if tc.mode == "ibd" {
				h, f := c.Health(context.Background())
				if f != nil || !h.InitialBlockDownload {
					t.Fatal("unsynced health must remain observable")
				}
			}
			n, f := c.Name(context.Background(), "d/example")
			if tc.code != "" {
				if f == nil || f.Code != tc.code || n != nil {
					t.Fatalf("wrong name refusal %#v", f)
				}
				return
			}
			if f != nil || n.ValueHex != "ff007b7d" || n.ObservedTip.Hash != fixtureTip {
				t.Fatal("wrong name positive")
			}
		})
	}
}

// A new name update mined after preflight is a retryable snapshot change. A
// stable valid name succeeds, while a future height under a stable tip remains
// a provider failure, including expired names. A consistent expired name keeps
// its refusal; a moving snapshot takes precedence. No refusal returns a name or
// replays name_show.
func TestNameSnapshotClassification(t *testing.T) {
	for _, tc := range []struct {
		mode, code string
		exit       int
		retryable  bool
	}{
		{"", "", 0, false},
		{"tip", "SNAPSHOT_CHANGED", 4, true},
		{"name-tip-advanced", "SNAPSHOT_CHANGED", 4, true},
		{"name-height-future", "PROVIDER_PROTOCOL", 5, false},
		{"expired", "NAME_EXPIRED", 3, false},
		{"expired-future", "PROVIDER_PROTOCOL", 5, false},
		{"expired-moving", "SNAPSHOT_CHANGED", 4, true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			c, methods, done := nodeFixture(t, tc.mode, func() {})
			defer done()
			n, f := c.Name(context.Background(), "d/example")
			if tc.code == "" {
				if f != nil || n == nil || n.ObservedTip.Hash != fixtureTip || n.ObservedTip.Height != 100 || n.Height != 99 {
					t.Fatal("stable name control failed")
				}
			} else if f == nil || f.Code != tc.code || f.Exit != tc.exit || f.Retryable != tc.retryable || n != nil {
				t.Fatalf("wrong snapshot refusal: %#v", f)
			}
			nameReads := 0
			for _, method := range *methods {
				switch method {
				case "getnetworkinfo", "getblockchaininfo", "getblockhash", "getbestblockhash":
				case "name_show":
					nameReads++
				default:
					t.Fatalf("unexpected name-read method %s", method)
				}
			}
			if nameReads != 1 {
				t.Fatal("name read was replayed")
			}
		})
	}
}

// Faithful active/expired fixtures agree with the backend expiry predicate at
// positive, zero and negative boundaries. An explicitly inconsistent response
// remains a provider refusal; these are fake-node checks, not captured evidence.
func TestNameExpiryFixtures(t *testing.T) {
	for _, tc := range []struct {
		mode       string
		expiresIn  int64
		expired    bool
		code       string
		consistent bool
	}{
		{"", 100, false, "", true},
		{"expired-zero", 0, true, "NAME_EXPIRED", true},
		{"expired", -1, true, "NAME_EXPIRED", true},
		{"inconsistent-expiry", 0, false, "PROVIDER_PROTOCOL", false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			c, _, done := nodeFixture(t, tc.mode, func() {})
			defer done()
			raw, f := c.call(context.Background(), "name_show", []any{"d/example", map[string]any{"nameEncoding": "utf8", "valueEncoding": "hex", "allowExpired": true}})
			var provider struct {
				Expired   bool  `json:"expired"`
				ExpiresIn int64 `json:"expires_in"`
			}
			if f != nil || json.Unmarshal(raw, &provider) != nil || provider.Expired != tc.expired || provider.ExpiresIn != tc.expiresIn || (provider.Expired == (provider.ExpiresIn <= 0)) != tc.consistent {
				t.Fatal("expiry fixture does not model its stated boundary")
			}
			n, f := c.Name(context.Background(), "d/example")
			if tc.code == "" {
				if f != nil || n == nil || n.Expired || n.ExpiresIn <= 0 {
					t.Fatal("active expiry control refused")
				}
			} else if f == nil || f.Code != tc.code || n != nil {
				t.Fatalf("wrong expiry refusal: %#v", f)
			}
		})
	}
}

// Complete nonzero and zero current-UTXO observations work without any wallet.
// Every failure family emits no partial result and sends no retry/import/abort.
// Pruned=true exercises no historical-block dependency; it is a fixture only.
func TestUTXOScanContract(t *testing.T) {
	for _, tc := range []struct{ mode, code string }{{"", ""}, {"zero", ""}, {"coinbase", ""}, {"busy", "SCAN_BUSY"}, {"uncertain", "SCAN_UNCERTAIN"}, {"outside", "PROVIDER_PROTOCOL"}, {"duplicate", "PROVIDER_PROTOCOL"}, {"negative", "PROVIDER_PROTOCOL"}, {"wrong-total", "PROVIDER_PROTOCOL"}, {"incomplete", "PROVIDER_PROTOCOL"}, {"tip", "SNAPSHOT_CHANGED"}, {"ibd", "NODE_UNSYNCED"}, {"name-script", "PROVIDER_PROTOCOL"}, {"missing-coinbase", "PROVIDER_PROTOCOL"}, {"fractional-index", "PROVIDER_PROTOCOL"}, {"future-output", "PROVIDER_PROTOCOL"}, {"null-unspents", "PROVIDER_PROTOCOL"}, {"missing-total", "PROVIDER_PROTOCOL"}, {"scan-tip", "SNAPSHOT_CHANGED"}} {
		t.Run(tc.mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c, methods, done := nodeFixture(t, tc.mode, cancel)
			defer done()
			r := validDerivation(t)
			request := ScanRequest{Schema: ScanSchema, Network: r.Network, XPub: r.XPub, Branches: []uint32{0, 1}, Start: 0, Count: 2, AddressType: "p2wpkh"}
			out, f := c.Scan(ctx, request)
			if tc.code != "" {
				if f == nil || f.Code != tc.code || out != nil {
					t.Fatalf("wrong scan refusal %#v", f)
				}
				if tc.mode == "busy" && (f.Exit != 4 || !f.Retryable) {
					t.Fatal("busy is caller-retryable")
				}
				if tc.mode == "uncertain" && f.Retryable {
					t.Fatal("uncertain scan is not automatically retryable")
				}
			} else {
				want := int64(125000000)
				if tc.mode == "zero" {
					want = 0
				}
				if f != nil || out.MatchedUTXOAtoms != want || out.ObservedTip.Hash != fixtureTip || out.Coverage.History || out.Coverage.Mempool || !out.Coverage.CompleteForRange || out.Coverage.NameOutputs != "excluded" || out.Coverage.Spendability != "unassessed" {
					t.Fatal("wrong scan positive/coverage")
				}
			}
			scans := 0
			if tc.mode == "coinbase" && out.CoinbaseUTXOCount != 1 {
				t.Fatal("coinbase not retained")
			}
			for _, m := range *methods {
				if m == "scantxoutset" {
					scans++
				}
				if m == "importdescriptors" || m == "abort" || m == "getnewaddress" || m == "getblock" {
					t.Fatal("forbidden extra effect")
				}
			}
			wantScans := 1
			if tc.mode == "ibd" {
				wantScans = 0
			}
			if scans != wantScans {
				t.Fatalf("scan calls %d", scans)
			}
		})
	}
}

// Integer amount conversion accepts exact decimals/exponents within the money
// bound; excess precision, negative/non-number and oversized exponents refuse.
func TestExactAmounts(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int64
	}{{"0", 0}, {"1.25", 125000000}, {"0.00000001", 1}, {"1e-8", 1}, {"21000000", 2100000000000000}} {
		n, ok := amountAtoms(json.RawMessage(tc.raw))
		if !ok || n != tc.want {
			t.Fatalf("amount conversion %s", tc.raw)
		}
	}
	for _, raw := range []string{"-1", "0.000000001", "21000001", "1e999999999", "\"1.25\"", "null"} {
		if _, ok := amountAtoms(json.RawMessage(raw)); ok {
			t.Fatal("invalid amount admitted")
		}
	}
}

// Cancelled and malformed requests fail before scan submission; a nearby valid
// request is covered above. No abort or retry can be sent.
func TestScanBeforeSubmission(t *testing.T) {
	c, methods, done := nodeFixture(t, "", func() {})
	defer done()
	r := validDerivation(t)
	valid := ScanRequest{Schema: ScanSchema, Network: r.Network, XPub: r.XPub, Branches: []uint32{0, 1}, Count: 2, AddressType: "p2wpkh"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, f := c.Scan(ctx, valid); out != nil || f == nil || f.Code != "RPC_UNAVAILABLE" {
		t.Fatal("pre-submit cancellation mislabeled")
	}
	for _, change := range []func(*ScanRequest){func(r *ScanRequest) { r.Branches = []uint32{1, 0} }, func(r *ScanRequest) { r.Count = 1001 }, func(r *ScanRequest) { r.Start = 1 << 31 }, func(r *ScanRequest) { r.AddressType = "p2pkh" }, func(r *ScanRequest) { r.XPub = "invalid" }} {
		r := valid
		change(&r)
		if out, f := c.Scan(context.Background(), r); out != nil || f == nil || f.Code != "BAD_INPUT" {
			t.Fatal("invalid scan input admitted")
		}
	}
	if len(*methods) != 0 {
		t.Fatal("pre-submit failure performed RPC")
	}
}
