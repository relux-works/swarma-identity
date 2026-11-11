package facade

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const ConfigSchema = "swarma-identity/config/1"
const MainGenesis = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"
const maxResponse = 4 << 20

type Config struct {
	Schema      string             `json:"schema"`
	Network     string             `json:"network"`
	Node        NodeConfig         `json:"node"`
	WatchWallet *WatchWalletConfig `json:"watch_wallet,omitempty"`
}

type NodeConfig struct {
	ID          string `json:"id"`
	RPCURL      string `json:"rpc_url"`
	AuthFile    string `json:"auth_file"`
	GenesisHash string `json:"genesis_hash"`
	RPCProfile  string `json:"rpc_profile"`
}

type WatchWalletConfig struct {
	Name     string `json:"name"`
	Coverage string `json:"coverage"`
}

type Client struct {
	config   Config
	url      string
	user     string
	password string
	http     *http.Client
	sequence int
	calls    int
}

func NewClient(c Config) (*Client, *Failure) {
	if c.Schema != ConfigSchema || c.Node.ID == "" || len(c.Node.ID) > 128 || c.Node.RPCProfile != "namecoin-core-read/1" {
		return nil, fail("BAD_INPUT")
	}
	if _, ok := networkParams(c.Network); !ok {
		return nil, fail("BAD_INPUT")
	}
	if c.WatchWallet != nil && (c.WatchWallet.Name == "" || len(c.WatchWallet.Name) > 128 || c.WatchWallet.Coverage != "wallet-visible") {
		return nil, fail("BAD_INPUT")
	}
	if len(c.Node.GenesisHash) != 64 || strings.Trim(c.Node.GenesisHash, "0123456789abcdef") != "" {
		return nil, fail("BAD_INPUT")
	}
	if c.Network == "main" && c.Node.GenesisHash != MainGenesis {
		return nil, fail("WRONG_NETWORK")
	}
	u, err := url.Parse(c.Node.RPCURL)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fail("BAD_INPUT")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fail("BAD_INPUT")
	}
	if u.Port() != "" {
		port, e := strconv.Atoi(u.Port())
		if e != nil || port < 1 || port > 65535 {
			return nil, fail("BAD_INPUT")
		}
	}
	f, err := os.OpenFile(c.Node.AuthFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fail("BAD_INPUT")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, fail("BAD_INPUT")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return nil, fail("BAD_INPUT")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return nil, fail("BAD_INPUT")
	}
	cookie := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	user, password, ok := strings.Cut(cookie, ":")
	if !ok || user == "" || password == "" || strings.ContainsAny(cookie, "\r\n\x00") {
		return nil, fail("BAD_INPUT")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	// Each request carries its own deadline: ordinary reads get five seconds,
	// while an explicitly admitted scan may take up to 285 seconds.
	transport := &http.Transport{Proxy: nil, MaxIdleConns: 1, MaxIdleConnsPerHost: 1,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			h, p, e := net.SplitHostPort(address)
			if e != nil {
				return nil, e
			}
			if h == "localhost" {
				h = "127.0.0.1"
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(h, p))
		}}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{config: c, url: u.String(), user: user, password: password, http: client}, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) call(ctx context.Context, method string, params []any) (json.RawMessage, *Failure) {
	allowed := false
	switch method {
	case "getnetworkinfo", "getblockchaininfo", "getblockhash", "getbestblockhash", "name_show":
		allowed = true
	case "scantxoutset":
		if len(params) == 2 {
			action, ok := params[0].(string)
			allowed = ok && action == "start"
		}
	}
	if !allowed {
		return nil, fail("UNSUPPORTED_CAPABILITY")
	}
	if method != "scantxoutset" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if ctx.Err() != nil || c.calls >= 128 {
		return nil, fail("RPC_UNAVAILABLE")
	}
	c.calls++
	c.sequence++
	id := c.sequence
	if params == nil {
		params = []any{}
	}
	request := struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  []any  `json:"params"`
	}{"1.0", id, method, params}
	b, err := json.Marshal(request)
	if err != nil {
		return nil, fail("INTERNAL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(b))
	if err != nil {
		return nil, fail("BAD_INPUT")
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.user, c.password)
	var submitted atomic.Bool
	if method == "scantxoutset" {
		// Once headers have been written, conservatively treat a lost response
		// as uncertain. A connection refusal before any write is distinguishable.
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{WroteHeaders: func() { submitted.Store(true) }}))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if method == "scantxoutset" && submitted.Load() {
			return nil, fail("SCAN_UNCERTAIN")
		}
		return nil, fail("RPC_UNAVAILABLE")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fail("RPC_REFUSED")
	}
	if value := resp.Header.Get("Content-Type"); value != "" {
		mt, _, e := mime.ParseMediaType(value)
		if e != nil || mt != "application/json" {
			return nil, fail("PROVIDER_PROTOCOL")
		}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		if method == "scantxoutset" {
			return nil, fail("SCAN_UNCERTAIN")
		}
		return nil, fail("RPC_UNAVAILABLE")
	}
	if len(raw) > maxResponse || validateJSON(raw) != nil {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	var responseID int
	if json.Unmarshal(obj["id"], &responseID) != nil || responseID != id {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	errorRaw, present := obj["error"]
	if !present {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	if !bytes.Equal(bytes.TrimSpace(errorRaw), []byte("null")) {
		if result, present := obj["result"]; !present || !bytes.Equal(bytes.TrimSpace(result), []byte("null")) {
			return nil, fail("PROVIDER_PROTOCOL")
		}
		errorObject, valid := object(errorRaw)
		var rpcError struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if !valid || !member(errorObject, "code", &rpcError.Code) || !member(errorObject, "message", &rpcError.Message) {
			return nil, fail("PROVIDER_PROTOCOL")
		}
		if method == "scantxoutset" && rpcError.Code == -8 && strings.HasPrefix(rpcError.Message, "Scan already in progress") {
			return nil, fail("SCAN_BUSY")
		}
		if method == "name_show" && rpcError.Code == -4 {
			return nil, fail("NAME_NOT_FOUND")
		}
		if rpcError.Code == -32601 {
			return nil, fail("UNSUPPORTED_CAPABILITY")
		}
		return nil, fail("RPC_REFUSED")
	}
	result, exists := obj["result"]
	if !exists || bytes.Equal(bytes.TrimSpace(result), []byte("null")) || resp.StatusCode != http.StatusOK {
		return nil, fail("PROVIDER_PROTOCOL")
	}
	return result, nil
}
