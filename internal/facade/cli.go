package facade

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"strings"
	"syscall"
)

const ResultSchema = "swarma-identity/result/1"

type Envelope struct {
	Schema  string   `json:"schema"`
	OK      bool     `json:"ok"`
	Command string   `json:"command"`
	Network string   `json:"network"`
	Result  any      `json:"result"`
	Error   *Failure `json:"error"`
}

func inputFile(path string, dst any) *Failure {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fail("BAD_INPUT")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 65536 {
		return fail("BAD_INPUT")
	}
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || DecodeStrict(b, dst) != nil {
		return fail("BAD_INPUT")
	}
	return nil
}

// Run writes exactly one closed JSON envelope. Flag, file and provider errors
// never echo user input, paths, cookies or raw provider messages.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	e := Envelope{Schema: ResultSchema}
	f := fail("BAD_INPUT")
	if len(args) >= 2 {
		switch args[0] + " " + args[1] {
		case "node health", "name show", "address derive", "balance watch":
			e.Command = args[0] + " " + args[1]
			e.Network, e.Result, f = execute(ctx, e.Command, args[2:])
		}
	}
	e.Error = f
	e.OK = f == nil
	if f != nil {
		e.Result = nil
	}
	if json.NewEncoder(stdout).Encode(e) != nil {
		io.WriteString(stderr, "Could not write the result.\n")
		return 1
	}
	if f != nil {
		return f.Exit
	}
	return 0
}

func execute(ctx context.Context, command string, args []string) (string, any, *Failure) {
	flags := flag.NewFlagSet("swarma-identity", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	jsonOutput := flags.Bool("json", false, "")
	var configPath, requestPath, mode string
	if command != "address derive" {
		flags.StringVar(&configPath, "config", "", "")
	}
	if command != "node health" {
		flags.StringVar(&requestPath, "request", "", "")
	}
	if command == "balance watch" {
		flags.StringVar(&mode, "mode", "utxo-scan", "")
	}
	// The command interface accepts long options once, not positional arguments
	// or last-value-wins ambiguity. Values themselves are not interpreted here.
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			return "", nil, fail("BAD_INPUT")
		}
		name, _, inline := strings.Cut(a[2:], "=")
		if flags.Lookup(name) == nil || seen[name] {
			return "", nil, fail("BAD_INPUT")
		}
		seen[name] = true
		if name != "json" && !inline {
			i++
			if i >= len(args) {
				return "", nil, fail("BAD_INPUT")
			}
		}
	}
	if flags.Parse(args) != nil || flags.NArg() != 0 || !*jsonOutput {
		return "", nil, fail("BAD_INPUT")
	}
	if command == "address derive" {
		var r DeriveRequest
		if f := inputFile(requestPath, &r); f != nil {
			return "", nil, f
		}
		rows, f := Derive(r)
		if f != nil {
			return selectedNetwork(r.Network), nil, f
		}
		return r.Network, struct {
			AddressType string    `json:"address_type"`
			Addresses   []Address `json:"addresses"`
		}{r.AddressType, rows}, nil
	}
	// Reject malformed public requests before opening the selected auth file.
	var nameRequest struct {
		Name string `json:"name"`
	}
	var scanRequest ScanRequest
	if command == "name show" {
		if f := inputFile(requestPath, &nameRequest); f != nil {
			return "", nil, f
		}
	}
	if command == "balance watch" {
		if mode != "utxo-scan" {
			return "", nil, fail("UNSUPPORTED_CAPABILITY")
		}
		if f := inputFile(requestPath, &scanRequest); f != nil {
			return "", nil, f
		}
		// Validate the public request using the same bounded derivation path.
		if scanRequest.Schema != ScanSchema || scanRequest.AddressType != "p2wpkh" || len(scanRequest.Branches) != 2 || scanRequest.Branches[0] != 0 || scanRequest.Branches[1] != 1 {
			return selectedNetwork(scanRequest.Network), nil, fail("BAD_INPUT")
		}
		if _, f := deriveRange(DeriveRequest{Schema: DeriveSchema, Network: scanRequest.Network, XPub: scanRequest.XPub, RelativePath: []uint32{0}, Start: scanRequest.Start, Count: scanRequest.Count, AddressType: scanRequest.AddressType}, 1000); f != nil {
			return selectedNetwork(scanRequest.Network), nil, f
		}
	}
	var config Config
	if f := inputFile(configPath, &config); f != nil {
		return "", nil, f
	}
	network := selectedNetwork(config.Network)
	if command == "balance watch" && scanRequest.Network != config.Network {
		return network, nil, fail("BAD_INPUT")
	}
	c, f := NewClient(config)
	if f != nil {
		return network, nil, f
	}
	defer c.Close()
	switch command {
	case "node health":
		result, f := c.Health(ctx)
		return network, result, f
	case "name show":
		result, f := c.Name(ctx, nameRequest.Name)
		return network, result, f
	case "balance watch":
		result, f := c.Scan(ctx, scanRequest)
		return network, result, f
	}
	return network, nil, fail("BAD_INPUT")
}

func selectedNetwork(n string) string {
	if _, ok := networkParams(n); ok {
		return n
	}
	return ""
}
