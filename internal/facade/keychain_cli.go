package facade

import (
	"context"
	"io"
	"strings"
)

// keychainOptions parses the long options of the G1-K commands with the same
// rules as every other command: each known option once, no positionals,
// --json required.
func keychainOptions(args []string, names ...string) (map[string]string, *Failure) {
	allowed := map[string]bool{"json": true}
	for _, n := range names {
		allowed[n] = true
	}
	got := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			return nil, fail("BAD_INPUT")
		}
		name, value, inline := strings.Cut(a[2:], "=")
		if _, dup := got[name]; !allowed[name] || dup {
			return nil, fail("BAD_INPUT")
		}
		if name == "json" {
			if inline {
				return nil, fail("BAD_INPUT")
			}
			got[name] = ""
			continue
		}
		if !inline {
			i++
			if i >= len(args) {
				return nil, fail("BAD_INPUT")
			}
			value = args[i]
		}
		got[name] = value
	}
	if _, ok := got["json"]; !ok {
		return nil, fail("BAD_INPUT")
	}
	return got, nil
}

// RunKeychain is the swarma-keychain entry point: the G1-K commands only,
// with the injected signer and the controlling terminal.
func RunKeychain(ctx context.Context, args []string, stdout, stderr io.Writer, signer GrantKeySigner) int {
	if len(args) >= 2 {
		switch args[0] + " " + args[1] {
		case "keychain keygen", "keychain sign", "value build":
			return run(ctx, args, stdout, stderr, keychainDeps{signer: signer, terminal: openTTY})
		}
	}
	return run(ctx, nil, stdout, stderr, keychainDeps{})
}

func executeKeychain(_ context.Context, command string, args []string, deps keychainDeps) (string, any, *Failure) {
	switch command {
	case "keychain keygen":
		o, f := keychainOptions(args, "label", "network")
		if f != nil {
			return "", nil, f
		}
		network, ok := o["network"]
		if !ok {
			network = "main"
		}
		result, f := KeychainKeygen(deps, o["label"], network)
		return selectedNetwork(network), result, f
	case "keychain sign":
		o, f := keychainOptions(args, "label", "request")
		if f != nil {
			return "", nil, f
		}
		return keychainSignCommand(deps, o["label"], o["request"])
	case "value build":
		o, f := keychainOptions(args, "grant-xonly", "social-descriptor")
		if f != nil {
			return "", nil, f
		}
		var d ValueNostrDescriptor
		if f := inputFile(o["social-descriptor"], &d); f != nil {
			return "", nil, f
		}
		result, f := BuildLandlordValue(o["grant-xonly"], d)
		return "", result, f
	}
	return "", nil, fail("BAD_INPUT")
}
