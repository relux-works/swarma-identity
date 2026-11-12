package facade

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type nameReadScenario struct {
	expiresIn  int64
	expired    bool
	nameHeight int64
	nextTip    Tip
}

// The fake changes its current tip only when name_show is executed. Sampling
// before that read sees the old hash, unlike a static differing-hash response.
func temporalNameFixture(t *testing.T, scenario nameReadScenario) (*Client, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var methods []string
	tip := Tip{Hash: fixtureTip, Height: 100}
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
		var value any
		switch q.Method {
		case "getnetworkinfo":
			value = map[string]any{"version": 280000, "connections": 10}
		case "getblockchaininfo":
			value = map[string]any{"chain": "main", "bestblockhash": tip.Hash, "blocks": tip.Height, "headers": tip.Height, "initialblockdownload": false, "verificationprogress": 1, "pruned": true}
		case "getblockhash":
			value = MainGenesis
		case "name_show":
			var name string
			var options map[string]any
			if len(q.Params) != 2 || json.Unmarshal(q.Params[0], &name) != nil || name != "d/example" || json.Unmarshal(q.Params[1], &options) != nil || !reflect.DeepEqual(options, map[string]any{"nameEncoding": "utf8", "valueEncoding": "hex", "allowExpired": true}) {
				t.Error("unexpected explicit name request")
			}
			if scenario.nextTip.Hash != "" {
				tip = scenario.nextTip
			}
			value = map[string]any{"name": "d/example", "value": "ff007b7d", "expired": scenario.expired, "expires_in": scenario.expiresIn, "txid": strings.Repeat("3", 64), "vout": 0, "height": scenario.nameHeight}
		case "getbestblockhash":
			value = tip.Hash
		default:
			t.Errorf("forbidden name fixture method %s", q.Method)
			http.Error(w, "forbidden method", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"id": q.ID, "result": value, "error": nil}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(s.Close)
	c, f := NewClient(testConfig(t, s.URL))
	if f != nil {
		t.Fatal(f.Code)
	}
	return c, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), methods...)
	}
}

func assertNameCallOrder(t *testing.T, methods []string, postcheck bool) {
	t.Helper()
	want := []string{"getnetworkinfo", "getblockchaininfo", "getblockhash", "name_show"}
	if postcheck {
		want = append(want, "getbestblockhash")
	}
	if !reflect.DeepEqual(methods, want) {
		t.Errorf("name RPC order = %v, want %v", methods, want)
	}
}
