package facade

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Public keys and values copied byte-for-byte from mainnet name_show output
// (tip 851209). They are independent of the chain-lab builders.
const (
	ivanSocial = "a6b79d4e39e783da7cc0f0c19f462c1a1c099699cdbe204c0f1db97c6ef7b438"
	ivanGrant  = "18fe8d331d945e77dd10bb695afaa0e5475f818880c8c03768b4db02a55dc891"
	cedarKey   = "ff59fe00359f3cb69d1013714d7e62aa029202080ea107c09afb91070c7b00bf"

	mainnetLandlord = `{"nostr":{"names":{"_":"` + ivanSocial + `"}},"swarma":{"landlord":{"grant":"` + ivanGrant + `"}}}`
	mainnetAgent    = `{"nostr":{"names":{"_":"` + cedarKey + `"}},"swarma":{"agent":{"nostr":"` + cedarKey + `","landlord":"id/ivanopcode"}}}`
	mainnetSwarma   = `{"nostr":{"names":{"_":"` + ivanSocial + `"}}}`

	plainLandlord = `{"swarma":{"landlord":{"grant":"` + ivanGrant + `"}}}`
	plainAgent    = `{"swarma":{"agent":{"nostr":"` + cedarKey + `","landlord":"id/ivanopcode"}}}`
	relayLandlord = `{"nostr":{"names":{"_":"` + ivanSocial + `"},"relays":{"` + ivanSocial + `":["wss://relay.example","wss://relay2.example"]}},"swarma":{"landlord":{"grant":"` + ivanGrant + `"}}}`
)

type idRecord struct {
	value     string // hex as the provider sends it
	height    int64
	expiresIn int64
	rpcCode   int // non-zero: name_show answers with this RPC error
}

type idScenario struct {
	records    map[string]idRecord
	moveTipAt  int // move the tip during the n-th name_show (1-based); 0 never
	movedTip   Tip
	tipHeight  int64
	extraValue map[string]any // raw provider value overrides by name
}

func hexOf(s string) string { return hex.EncodeToString([]byte(s)) }

func activeRecord(value string) idRecord {
	return idRecord{value: hexOf(value), height: 90, expiresIn: 35000}
}

// The fake node answers only the read fence and records each method and each
// requested name. Its tip moves only while the selected name_show executes.
func identityFixture(t *testing.T, sc idScenario) (*Client, func() ([]string, []string)) {
	t.Helper()
	var mu sync.Mutex
	var methods, names []string
	height := sc.tipHeight
	if height == 0 {
		height = 100
	}
	tip := Tip{Hash: fixtureTip, Height: height}
	shows := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var q struct {
			ID     int               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			t.Error("invalid fixture request")
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		methods = append(methods, q.Method)
		var value, rpcError any
		switch q.Method {
		case "getnetworkinfo":
			value = map[string]any{"version": 280000, "connections": 10}
		case "getblockchaininfo":
			value = map[string]any{"chain": "main", "bestblockhash": tip.Hash, "blocks": tip.Height, "headers": tip.Height, "initialblockdownload": false, "verificationprogress": 1, "pruned": true}
		case "getblockhash":
			value = MainGenesis
		case "getbestblockhash":
			value = tip.Hash
		case "name_show":
			shows++
			var name string
			var options map[string]any
			if len(q.Params) != 2 || json.Unmarshal(q.Params[0], &name) != nil || json.Unmarshal(q.Params[1], &options) != nil || !reflect.DeepEqual(options, map[string]any{"nameEncoding": "utf8", "valueEncoding": "hex", "allowExpired": true}) {
				t.Error("unexpected explicit name request")
			}
			names = append(names, name)
			if shows == sc.moveTipAt {
				tip = sc.movedTip
			}
			rec, ok := sc.records[name]
			if !ok {
				rpcError = map[string]any{"code": -4, "message": "name never existed: " + name}
				break
			}
			if rec.rpcCode != 0 {
				rpcError = map[string]any{"code": rec.rpcCode, "message": "fixture refusal"}
				break
			}
			value = map[string]any{"name": name, "value": rec.value, "expired": rec.expiresIn <= 0, "expires_in": rec.expiresIn, "txid": strings.Repeat("3", 64), "vout": 0, "height": rec.height}
			if v, ok := sc.extraValue[name]; ok {
				value = v
			}
		default:
			t.Errorf("forbidden identity fixture method %s", q.Method)
			http.Error(w, "forbidden method", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"id": q.ID, "result": value, "error": rpcError}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(s.Close)
	c, f := NewClient(testConfig(t, s.URL))
	if f != nil {
		t.Fatal(f.Code)
	}
	t.Cleanup(c.Close)
	return c, func() ([]string, []string) {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), methods...), append([]string(nil), names...)
	}
}

func mainnetRecords() map[string]idRecord {
	return map[string]idRecord{
		"id/ivanopcode":       activeRecord(mainnetLandlord),
		"id/ivanopcode-cedar": activeRecord(mainnetAgent),
		"id/swarma":           activeRecord(mainnetSwarma),
	}
}

var preflight = []string{"getnetworkinfo", "getblockchaininfo", "getblockhash"}

func calls(extra ...string) []string { return append(append([]string(nil), preflight...), extra...) }

// Claim: the exact mainnet byte shapes classify as LIP-0004 says, with the keys
// read from the chain, and every near-miss spelling is role "none".
// Limit: classification only; landlord resolution is tested through the node.
func TestClassifyV3(t *testing.T) {
	// Grow an otherwise valid relay list until it crosses 520 bytes; the last
	// fitting value is the boundary positive control.
	relayValue := func(n int) (string, []string) {
		var urls []string
		for i := range n {
			urls = append(urls, "wss://r"+strconv.Itoa(i)+".example")
		}
		b, _ := json.Marshal(urls)
		return `{"nostr":{"names":{"_":"` + ivanSocial + `"},"relays":{"` + ivanSocial + `":` + string(b) + `}},"swarma":{"landlord":{"grant":"` + ivanGrant + `"}}}`, urls
	}
	n := 1
	for v, _ := relayValue(n + 1); len(v) <= 520; v, _ = relayValue(n + 1) {
		n++
	}
	fit, fitURLs := relayValue(n)
	long, _ := relayValue(n + 1)
	cases := []struct {
		name, value string
		want        v3Value
	}{
		{"mainnet-landlord", mainnetLandlord, v3Value{role: "landlord", grantKey: ivanGrant, social: &Social{Key: ivanSocial, Relays: []string{}}}},
		{"plain-landlord", plainLandlord, v3Value{role: "landlord", grantKey: ivanGrant}},
		{"relay-landlord", relayLandlord, v3Value{role: "landlord", grantKey: ivanGrant, social: &Social{Key: ivanSocial, Relays: []string{"wss://relay.example", "wss://relay2.example"}}}},
		{"mainnet-agent", mainnetAgent, v3Value{role: "agent", nostrKey: cedarKey, landlord: "id/ivanopcode", social: &Social{Key: cedarKey, Relays: []string{}}}},
		{"plain-agent", plainAgent, v3Value{role: "agent", nostrKey: cedarKey, landlord: "id/ivanopcode"}},
		{"id-swarma-shape", mainnetSwarma, v3Value{role: "none"}},
		{"whitespace", `{"swarma": {"landlord":{"grant":"` + ivanGrant + `"}}}`, v3Value{role: "none"}},
		{"reordered", `{"swarma":{"landlord":{"grant":"` + ivanGrant + `"}},"nostr":{"names":{"_":"` + ivanSocial + `"}}}`, v3Value{role: "none"}},
		{"extra-member", `{"swarma":{"landlord":{"grant":"` + ivanGrant + `","x":1}}}`, v3Value{role: "none"}},
		{"uppercase-key", `{"swarma":{"landlord":{"grant":"` + strings.ToUpper(ivanGrant) + `"}}}`, v3Value{role: "none"}},
		{"off-curve-key", `{"swarma":{"landlord":{"grant":"` + strings.Repeat("f", 64) + `"}}}`, v3Value{role: "none"}},
		{"both-roles", `{"swarma":{"landlord":{"grant":"` + ivanGrant + `"},"agent":{"nostr":"` + cedarKey + `","landlord":"id/ivanopcode"}}}`, v3Value{role: "none"}},
		{"agent-root-mismatch", `{"nostr":{"names":{"_":"` + ivanSocial + `"}},"swarma":{"agent":{"nostr":"` + cedarKey + `","landlord":"id/ivanopcode"}}}`, v3Value{role: "none"}},
		{"agent-non-id-landlord", `{"swarma":{"agent":{"nostr":"` + cedarKey + `","landlord":"d/ivanopcode"}}}`, v3Value{role: "none"}},
		{"agent-uppercase-landlord", `{"swarma":{"agent":{"nostr":"` + cedarKey + `","landlord":"id/Ivan"}}}`, v3Value{role: "none"}},
		{"relay-http", `{"nostr":{"names":{"_":"` + ivanSocial + `"},"relays":{"` + ivanSocial + `":["http://relay.example"]}},"swarma":{"landlord":{"grant":"` + ivanGrant + `"}}}`, v3Value{role: "none"}},
		{"fits-520", fit, v3Value{role: "landlord", grantKey: ivanGrant, social: &Social{Key: ivanSocial, Relays: fitURLs}}},
		{"over-520", long, v3Value{role: "none"}},
		{"invalid-utf8", "\xff\x00{}", v3Value{role: "none"}},
		{"empty", "", v3Value{role: "none"}},
		{"json-null", "null", v3Value{role: "none"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyV3([]byte(tc.value)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("classification = %#v, want %#v", got, tc.want)
			}
		})
	}
	if len(fit) > 520 || len(long) <= 520 {
		t.Fatal("520-byte boundary controls are mis-sized")
	}
}

func showResult(t *testing.T, c *Client, name string) (*IdentityResult, map[string]any) {
	t.Helper()
	r, f := c.Identity(context.Background(), name)
	if f != nil {
		t.Fatalf("identity refused: %s", f.Code)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return r, m
}

func keysOf(m map[string]any) []string { return slices.Sorted(maps.Keys(m)) }

// Claim: id/ivanopcode's mainnet value is shown as a landlord with both keys,
// exact value bytes and the observed tip, using one name read in one snapshot.
func TestIdentityShowLandlord(t *testing.T) {
	c, observed := identityFixture(t, idScenario{records: mainnetRecords()})
	r, m := showResult(t, c, "id/ivanopcode")
	if r.Role != "landlord" || r.GrantKey != ivanGrant || r.Social == nil || r.Social.Key != ivanSocial || r.Reason != "" || r.ValueHex != hexOf(mainnetLandlord) || r.Height != 90 || r.ExpiresIn != 35000 || r.ObservedTip != (Tip{fixtureTip, 100}) {
		t.Fatalf("landlord projection differs: %#v", r)
	}
	if got := keysOf(m); !reflect.DeepEqual(got, []string{"expires_in", "grant_key", "height", "name", "observed_tip", "role", "social", "txid", "value_hex", "vout"}) {
		t.Fatalf("landlord members = %v", got)
	}
	methods, names := observed()
	if !reflect.DeepEqual(methods, calls("name_show", "getbestblockhash")) || !reflect.DeepEqual(names, []string{"id/ivanopcode"}) {
		t.Fatalf("landlord reads = %v %v", methods, names)
	}
}

// Claim: an agent is shown with its key and pointer, and its landlord is resolved
// by a second name read inside the same tip snapshot.
func TestIdentityShowAgent(t *testing.T) {
	c, observed := identityFixture(t, idScenario{records: mainnetRecords()})
	r, m := showResult(t, c, "id/ivanopcode-cedar")
	want := &ResolvedLandlord{Name: "id/ivanopcode", GrantKey: ivanGrant, Social: &Social{Key: ivanSocial, Relays: []string{}}, ValueHex: hexOf(mainnetLandlord), TxID: strings.Repeat("3", 64), Height: 90, ExpiresIn: 35000}
	if r.Role != "agent" || r.NostrKey != cedarKey || r.Landlord != "id/ivanopcode" || r.Reason != "" || r.Social == nil || r.Social.Key != cedarKey || r.GrantKey != "" || !reflect.DeepEqual(r.LandlordResolved, want) || r.ValueHex != hexOf(mainnetAgent) {
		t.Fatalf("agent projection differs: %#v", r)
	}
	if got := keysOf(m); !reflect.DeepEqual(got, []string{"expires_in", "height", "landlord", "landlord_resolved", "name", "nostr_key", "observed_tip", "role", "social", "txid", "value_hex", "vout"}) {
		t.Fatalf("agent members = %v", got)
	}
	methods, names := observed()
	if !reflect.DeepEqual(methods, calls("name_show", "name_show", "getbestblockhash")) || !reflect.DeepEqual(names, []string{"id/ivanopcode-cedar", "id/ivanopcode"}) {
		t.Fatalf("agent reads = %v %v", methods, names)
	}
}

// Claim: the id/swarma value shape is a successful observation with role
// "none", reason VALUE_NOT_V3, no key members and no further name read.
func TestIdentityShowValueNotV3(t *testing.T) {
	c, observed := identityFixture(t, idScenario{records: mainnetRecords()})
	r, m := showResult(t, c, "id/swarma")
	if r.Role != "none" || r.Reason != ReasonValueNotV3 || r.ValueHex != hexOf(mainnetSwarma) {
		t.Fatalf("non-v3 projection differs: %#v", r)
	}
	if got := keysOf(m); !reflect.DeepEqual(got, []string{"expires_in", "height", "name", "observed_tip", "reason", "role", "txid", "value_hex", "vout"}) {
		t.Fatalf("non-v3 members = %v", got)
	}
	if methods, _ := observed(); !reflect.DeepEqual(methods, calls("name_show", "getbestblockhash")) {
		t.Fatalf("non-v3 reads = %v", methods)
	}
}

// Claim: an agent whose pointer does not reach an active v3 landlord keeps its
// own fields but gets reason LANDLORD_NOT_V3 and no landlord_resolved. The
// valid-landlord row is the nearby positive control.
func TestIdentityShowLandlordNotV3(t *testing.T) {
	agentTo := func(landlord string) string {
		return `{"swarma":{"agent":{"nostr":"` + cedarKey + `","landlord":"` + landlord + `"}}}`
	}
	expired := activeRecord(plainLandlord)
	expired.expiresIn = 0
	cases := []struct {
		name, pointer string
		target        idRecord
		ok            bool
	}{
		{"valid-landlord", "id/ivanopcode", activeRecord(plainLandlord), true},
		{"swarma-shape", "id/target", activeRecord(mainnetSwarma), false},
		{"another-agent", "id/target", activeRecord(plainAgent), false},
		{"expired-landlord", "id/target", expired, false},
		{"missing-landlord", "id/absent", idRecord{}, false},
		{"self-pointer", "id/agent", idRecord{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			records := map[string]idRecord{"id/agent": activeRecord(agentTo(tc.pointer))}
			if tc.target.value != "" {
				records[tc.pointer] = tc.target
			}
			c, observed := identityFixture(t, idScenario{records: records})
			r, _ := showResult(t, c, "id/agent")
			if r.Role != "agent" || r.Landlord != tc.pointer || r.NostrKey != cedarKey {
				t.Fatalf("agent fields lost: %#v", r)
			}
			if tc.ok {
				if r.Reason != "" || r.LandlordResolved == nil || r.LandlordResolved.GrantKey != ivanGrant {
					t.Fatalf("valid landlord control refused: %#v", r)
				}
			} else if r.Reason != ReasonLandlordNotV3 || r.LandlordResolved != nil {
				t.Fatalf("non-landlord pointer admitted: reason %q resolved %#v", r.Reason, r.LandlordResolved)
			}
			if _, names := observed(); !reflect.DeepEqual(names, []string{"id/agent", tc.pointer}) {
				t.Fatalf("landlord reads = %v", names)
			}
		})
	}
}

// Claim: a tip hash change during either name read refuses with retryable
// SNAPSHOT_CHANGED and no result, including a same-height reorganisation. The
// unmoved row is the positive control.
func TestIdentityShowSnapshotChanged(t *testing.T) {
	other := strings.Repeat("2", 64)
	cases := []struct {
		name, target string
		moveAt       int
		moved        Tip
		code         string
	}{
		{"agent-unmoved", "id/ivanopcode-cedar", 0, Tip{}, ""},
		{"landlord-target-advanced", "id/ivanopcode", 1, Tip{other, 101}, "SNAPSHOT_CHANGED"},
		{"agent-target-reorg-same-height", "id/ivanopcode-cedar", 1, Tip{other, 100}, "SNAPSHOT_CHANGED"},
		{"agent-landlord-read-advanced", "id/ivanopcode-cedar", 2, Tip{other, 101}, "SNAPSHOT_CHANGED"},
		{"non-v3-advanced", "id/swarma", 1, Tip{other, 101}, "SNAPSHOT_CHANGED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, observed := identityFixture(t, idScenario{records: mainnetRecords(), moveTipAt: tc.moveAt, movedTip: tc.moved})
			r, f := c.Identity(context.Background(), tc.target)
			if tc.code == "" {
				if f != nil || r == nil {
					t.Fatal("unmoved snapshot control refused")
				}
				return
			}
			if f == nil || f.Code != tc.code || !f.Retryable || f.Exit != 4 || r != nil {
				t.Fatalf("moved snapshot admitted: %#v %#v", f, r)
			}
			if methods, _ := observed(); methods[len(methods)-1] != "getbestblockhash" {
				t.Fatalf("snapshot not closed by a tip read: %v", methods)
			}
		})
	}
}

// Claim: malformed or oversize provider value bytes, for the target or for the
// landlord, refuse with PROVIDER_PROTOCOL and never reach v3 parsing. The
// exact 520-byte value is the boundary positive control.
func TestIdentityShowMalformedValue(t *testing.T) {
	at520 := strings.Repeat("ab", 520)
	cases := []struct {
		name, target string
		records      map[string]idRecord
		code         string
	}{
		{"boundary-520", "id/agent", map[string]idRecord{"id/agent": {value: at520, height: 90, expiresIn: 5}}, ""},
		{"oversize-521", "id/agent", map[string]idRecord{"id/agent": {value: at520 + "ab", height: 90, expiresIn: 5}}, "PROVIDER_PROTOCOL"},
		{"odd-hex", "id/agent", map[string]idRecord{"id/agent": {value: hexOf(plainLandlord) + "a", height: 90, expiresIn: 5}}, "PROVIDER_PROTOCOL"},
		{"non-hex", "id/agent", map[string]idRecord{"id/agent": {value: "zz" + hexOf(plainLandlord), height: 90, expiresIn: 5}}, "PROVIDER_PROTOCOL"},
		{"landlord-oversize", "id/ivanopcode-cedar", map[string]idRecord{"id/ivanopcode-cedar": activeRecord(mainnetAgent), "id/ivanopcode": {value: at520 + "ab", height: 90, expiresIn: 5}}, "PROVIDER_PROTOCOL"},
		{"landlord-future-height", "id/ivanopcode-cedar", map[string]idRecord{"id/ivanopcode-cedar": activeRecord(mainnetAgent), "id/ivanopcode": {value: hexOf(plainLandlord), height: 101, expiresIn: 5}}, "PROVIDER_PROTOCOL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := identityFixture(t, idScenario{records: tc.records})
			r, f := c.Identity(context.Background(), tc.target)
			if tc.code == "" {
				if f != nil || r == nil || r.Role != "none" || r.Reason != ReasonValueNotV3 || len(r.ValueHex) != 1040 {
					t.Fatalf("520-byte boundary control refused: %#v", f)
				}
				return
			}
			if f == nil || f.Code != tc.code || r != nil {
				t.Fatalf("malformed provider value admitted: %#v %#v", f, r)
			}
		})
	}
}

// Claim: missing and expired targets keep the name-read refusals, and a
// landlord read refused for any reason other than absence is not hidden as
// LANDLORD_NOT_V3.
func TestIdentityShowRefusals(t *testing.T) {
	expired := activeRecord(plainLandlord)
	expired.expiresIn = -1
	cases := []struct {
		name, target string
		records      map[string]idRecord
		code         string
		exit         int
	}{
		{"missing-target", "id/absent", mainnetRecords(), "NAME_NOT_FOUND", 3},
		{"expired-target", "id/old", map[string]idRecord{"id/old": expired}, "NAME_EXPIRED", 3},
		{"landlord-read-refused", "id/ivanopcode-cedar", map[string]idRecord{"id/ivanopcode-cedar": activeRecord(mainnetAgent), "id/ivanopcode": {rpcCode: -1}}, "RPC_REFUSED", 3},
		{"empty-name", "", mainnetRecords(), "BAD_INPUT", 2},
		{"long-name", "id/" + strings.Repeat("a", 253), mainnetRecords(), "BAD_INPUT", 2},
		{"invalid-utf8-name", "id/\xff", mainnetRecords(), "BAD_INPUT", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, observed := identityFixture(t, idScenario{records: tc.records})
			r, f := c.Identity(context.Background(), tc.target)
			if f == nil || f.Code != tc.code || f.Exit != tc.exit || r != nil {
				t.Fatalf("refusal = %#v %#v, want %s", f, r, tc.code)
			}
			if tc.code == "BAD_INPUT" {
				if methods, _ := observed(); len(methods) != 0 {
					t.Fatalf("bad input reached the node: %v", methods)
				}
			}
		})
	}
}

// Claim: the complete CLI path admits identity show with the strict envelope
// and exit codes, refuses a malformed, extended or oversize request before the
// config is opened, and never echoes the request name in a refusal.
func TestCLIIdentityShow(t *testing.T) {
	c, _ := identityFixture(t, idScenario{records: mainnetRecords(), moveTipAt: 4, movedTip: Tip{strings.Repeat("2", 64), 101}})
	config := writeInput(t, c.config)
	request := func(name string) string {
		return writeInput(t, struct {
			Name string `json:"name"`
		}{name})
	}
	e, code, raw := runCLI(t, "identity", "show", "--config", config, "--request", request("id/ivanopcode"), "--json")
	if code != 0 || e.Command != "identity show" || e.Network != "main" || !strings.Contains(string(raw), `"role":"landlord"`) || !strings.Contains(string(raw), `"grant_key":"`+ivanGrant+`"`) {
		t.Fatalf("landlord CLI result differs: %s", raw)
	}
	e, code, raw = runCLI(t, "identity", "show", "--config", config, "--request", request("id/swarma"), "--json")
	if code != 0 || !strings.Contains(string(raw), `"role":"none","reason":"VALUE_NOT_V3"`) {
		t.Fatalf("non-v3 CLI result differs: %s", raw)
	}
	// The fixture's fourth name_show is the agent's landlord read in this run.
	e, code, raw = runCLI(t, "identity", "show", "--config", config, "--request", request("id/ivanopcode-cedar"), "--json")
	if code != 4 || e.Error.Code != "SNAPSHOT_CHANGED" || !e.Error.Retryable || strings.Contains(string(raw), "cedar") {
		t.Fatalf("snapshot CLI refusal differs: %s", raw)
	}
	e, code, raw = runCLI(t, "identity", "show", "--config", config, "--request", request("id/absent-fixture"), "--json")
	if code != 3 || e.Error.Code != "NAME_NOT_FOUND" || strings.Contains(string(raw), "absent-fixture") {
		t.Fatalf("missing-name CLI refusal differs: %s", raw)
	}
	dir := t.TempDir()
	oversize := filepath.Join(dir, "oversize.json")
	if err := os.WriteFile(oversize, []byte(`{"name":"`+strings.Repeat("a", 65536)+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	extended := filepath.Join(dir, "extended.json")
	if err := os.WriteFile(extended, []byte(`{"name":"id/ivanopcode","role":"landlord"}`), 0600); err != nil {
		t.Fatal(err)
	}
	duplicate := filepath.Join(dir, "duplicate.json")
	if err := os.WriteFile(duplicate, []byte(`{"name":"id/a","name":"id/b"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"identity", "show", "--config", "absent", "--request", oversize, "--json"},
		{"identity", "show", "--config", "absent", "--request", extended, "--json"},
		{"identity", "show", "--config", "absent", "--request", duplicate, "--json"},
		{"identity", "show", "--config", config, "--request", request("id/ivanopcode")},
		{"identity", "show", "--request", request("id/ivanopcode"), "--json"},
		{"identity", "show", "--config", config, "--request", request("id/ivanopcode"), "--mode", "utxo-scan", "--json"},
	} {
		e, code, _ := runCLI(t, args...)
		if code != 2 || e.Error.Code != "BAD_INPUT" || e.Network != "" {
			t.Fatalf("invalid identity invocation admitted: %v -> %#v", args[2:], e.Error)
		}
	}
}
