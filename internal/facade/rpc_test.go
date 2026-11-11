package facade

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func testConfig(t *testing.T, endpoint string) Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "auth")
	if err := os.WriteFile(p, []byte("fixture-user:fixture-password"), 0600); err != nil {
		t.Fatal(err)
	}
	return Config{Schema: ConfigSchema, Network: "main", Node: NodeConfig{ID: "fixture", RPCURL: endpoint, AuthFile: p, GenesisHash: MainGenesis, RPCProfile: "namecoin-core-read/1"}}
}

// A positive read is authenticated and correlated. Forbidden methods/actions are
// rejected locally, with no second HTTP request and no raw backend error echoed.
func TestRPCMethodFence(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		calls++
		user, password, ok := r.BasicAuth()
		if !ok || user != "fixture-user" || password != "fixture-password" {
			t.Error("missing explicit authentication")
		}
		var q map[string]any
		json.NewDecoder(r.Body).Decode(&q)
		json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"version": 280000}, "error": nil, "id": q["id"]})
	}))
	defer s.Close()
	c, f := NewClient(testConfig(t, s.URL))
	if f != nil {
		t.Fatal(f.Code)
	}
	if _, f := c.call(context.Background(), "getnetworkinfo", nil); f != nil {
		t.Fatal(f.Code)
	}
	for _, tc := range []struct {
		method string
		params []any
	}{{"sendtoaddress", []any{}}, {"importdescriptors", []any{}}, {"scantxoutset", []any{"abort"}}, {"scantxoutset", []any{"status"}}} {
		if _, f := c.call(context.Background(), tc.method, tc.params); f == nil || f.Code != "UNSUPPORTED_CAPABILITY" {
			t.Fatal("forbidden request admitted")
		}
	}
	if calls != 1 {
		t.Fatalf("HTTP calls=%d", calls)
	}
}

// A refused connection sends no request headers and is unavailable, unlike
// the post-submission cancellation exercised by the scan fixture.
func TestScanConnectionFailureBeforeSubmission(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("closed endpoint received a request") }))
	endpoint := s.URL
	s.Close()
	c, f := NewClient(testConfig(t, endpoint))
	if f != nil {
		t.Fatal(f.Code)
	}
	defer c.Close()
	if _, f := c.call(context.Background(), "scantxoutset", []any{"start", []any{}}); f == nil || f.Code != "RPC_UNAVAILABLE" || !f.Retryable {
		t.Fatal("pre-write refusal mislabeled as submitted scan")
	}
}

// Redirects and mismatched/duplicate envelopes cannot turn into successful reads;
// the sentinel credential text never enters the fixed failure message.
func TestRPCUntrustedResponses(t *testing.T) {
	for _, mode := range []string{"wrong-id", "duplicate", "redirect", "raw-error", "missing-error-code", "null-error-message", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			redirected := 0
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected++ }))
			defer target.Close()
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				var q struct {
					ID int `json:"id"`
				}
				json.NewDecoder(r.Body).Decode(&q)
				switch mode {
				case "wrong-id":
					json.NewEncoder(w).Encode(map[string]any{"id": q.ID + 1, "result": 1, "error": nil})
				case "duplicate":
					w.Write([]byte(`{"id":1,"id":1,"result":1,"error":null}`))
				case "redirect":
					http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
				case "raw-error":
					json.NewEncoder(w).Encode(map[string]any{"id": q.ID, "result": nil, "error": map[string]any{"code": -1, "message": "fixture-password"}})
				case "missing-error-code":
					json.NewEncoder(w).Encode(map[string]any{"id": q.ID, "result": nil, "error": map[string]any{"message": "fixture-password"}})
				case "null-error-message":
					json.NewEncoder(w).Encode(map[string]any{"id": q.ID, "result": nil, "error": map[string]any{"code": -1, "message": nil}})
				case "oversize":
					w.Write([]byte(`{"id":1,"result":"` + strings.Repeat("x", maxResponse) + `","error":null}`))
				}
			}))
			defer s.Close()
			c, f := NewClient(testConfig(t, s.URL))
			if f != nil {
				t.Fatal(f.Code)
			}
			_, f = c.call(context.Background(), "getnetworkinfo", nil)
			if f == nil || strings.Contains(f.Message, "fixture-password") || redirected != 0 {
				t.Fatal("untrusted response accepted or disclosed")
			}
			if mode != "raw-error" && f.Code != "PROVIDER_PROTOCOL" {
				t.Fatal("wrong protocol refusal")
			}
		})
	}
}

// The admitted cookie is a private regular file; adjacent unsafe file types and
// network destinations refuse without altering those files.
func TestCredentialAndEndpointFence(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1:1234")
	if c, f := NewClient(cfg); f != nil || c == nil {
		t.Fatal("positive refused")
	}
	for _, endpoint := range []string{"http://192.0.2.1:1234", "http://user:password@127.0.0.1", "http://127.0.0.1/?secret=x"} {
		c := cfg
		c.Node.RPCURL = endpoint
		if _, f := NewClient(c); f == nil {
			t.Fatal("unsafe endpoint admitted")
		}
	}
	if err := os.Chmod(cfg.Node.AuthFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, f := NewClient(cfg); f == nil {
		t.Fatal("public auth file admitted")
	}
	os.Chmod(cfg.Node.AuthFile, 0600)
	link := cfg.Node.AuthFile + ".link"
	if err := os.Symlink(cfg.Node.AuthFile, link); err != nil {
		t.Fatal(err)
	}
	c := cfg
	c.Node.AuthFile = link
	if _, f := NewClient(c); f == nil {
		t.Fatal("symlink admitted")
	}
	if err := os.Link(cfg.Node.AuthFile, link+".hard"); err != nil {
		t.Fatal(err)
	}
	if _, f := NewClient(cfg); f == nil {
		t.Fatal("hard-linked auth admitted")
	}
	// Opening a non-regular FIFO must refuse immediately, without waiting for
	// a writer before the file-type check can run.
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	c.Node.AuthFile = fifo
	if _, f := NewClient(c); f == nil || f.Code != "BAD_INPUT" {
		t.Fatal("FIFO admitted")
	}
}
