package facade

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// Inspect the original JSON before decoding into Go scalar fields. In
// particular, null must never become an apparently valid empty string/false/0.
// Values tied to the input still have separate complete independent oracles.
func nostrWireProblem(raw []byte, command string) string {
	var wire any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&wire) != nil {
		return "JSON syntax"
	}
	e, ok := nostrWireObject(wire, "schema", "ok", "command", "network", "result", "error")
	if !ok {
		return "envelope keys/type"
	}
	if e["schema"] != "swarma-identity/result/1" || e["command"] != command || e["network"] != "" {
		return "envelope string type/value"
	}
	success, ok := e["ok"].(bool)
	if !ok {
		return "envelope bool type"
	}
	if !success {
		failure, ok := nostrWireObject(e["error"], "code", "message", "retryable")
		if !ok || e["result"] != nil {
			return "failure keys/type"
		}
		for _, name := range []string{"code", "message"} {
			if s, ok := failure[name].(string); !ok || s == "" {
				return "failure string type"
			}
		}
		if retry, ok := failure["retryable"].(bool); !ok || retry {
			return "failure bool type/value"
		}
		return ""
	}
	if e["error"] != nil {
		return "success error must be null"
	}
	var fields map[string]any
	if command == "nostr profile-prepare" {
		r, ok := nostrWireObject(e["result"], "schema", "canonical_utf8", "event")
		if !ok || r["schema"] != "swarma-identity/nostr-profile-prepared/1" {
			return "prepared result keys/schema"
		}
		if _, ok := r["canonical_utf8"].(string); !ok {
			return "canonical string type"
		}
		fields, ok = nostrWireObject(r["event"], "id", "pubkey", "created_at", "kind", "tags", "content")
		if !ok {
			return "prepared event keys/type"
		}
		if _, ok := fields["content"].(string); !ok {
			return "content string type"
		}
		tags, ok := fields["tags"].([]any)
		if !ok {
			return "tags array type"
		}
		for _, tag := range tags {
			items, ok := tag.([]any)
			if !ok || len(items) == 0 {
				return "tag array type"
			}
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return "tag item string type"
				}
			}
		}
	} else if command == "nostr profile-verify" {
		var ok bool
		fields, ok = nostrWireObject(e["result"], "schema", "valid", "id", "pubkey", "created_at", "kind")
		if !ok || fields["schema"] != "swarma-identity/nostr-profile-verified/1" {
			return "verified result keys/schema"
		}
		if valid, ok := fields["valid"].(bool); !ok || !valid {
			return "verified bool type/value"
		}
	} else {
		return "unsupported test command"
	}
	for _, name := range []string{"id", "pubkey"} {
		if _, ok := fields[name].(string); !ok {
			return "event string type"
		}
	}
	for _, name := range []string{"created_at", "kind"} {
		n, ok := fields[name].(json.Number)
		if !ok || strings.HasPrefix(n.String(), "+") {
			return "event integer type"
		}
		if _, err := strconv.ParseUint(n.String(), 10, 64); err != nil {
			return "event integer syntax"
		}
	}
	return ""
}

func nostrWireObject(value any, names ...string) (map[string]any, bool) {
	m, ok := value.(map[string]any)
	if !ok || len(m) != len(names) {
		return nil, false
	}
	for _, name := range names {
		if _, ok := m[name]; !ok {
			return nil, false
		}
	}
	return m, true
}

// Both real successes have an empty JSON string network. A null mutation has
// the same typed Go zero value, but must fail the original-wire admission.
func TestNostrNullNetworkSuccess(t *testing.T) {
	for _, command := range []string{"profile-prepare", "profile-verify"} {
		t.Run(command, func(t *testing.T) {
			event := publicNostrFixture(t)
			var request any = nostrPrepareInput(event)
			if command == "profile-verify" {
				request = map[string]any{"schema": "swarma-identity/nostr-profile-verify/1", "event": event}
			}
			_, code, raw := runCLI(t, "nostr", command, "--request", writeInput(t, request), "--json")
			if code != 0 || nostrWireProblem(raw, "nostr "+command) != "" {
				t.Fatal("normal wire positive refused")
			}
			var wire map[string]any
			if json.Unmarshal(raw, &wire) != nil {
				t.Fatal("wire control setup")
			}
			wire["network"] = nil
			bad, _ := json.Marshal(wire)
			var lossy Envelope
			if json.Unmarshal(bad, &lossy) != nil || lossy.Network != "" || !lossy.OK {
				t.Fatal("null-to-zero-value witness was not activated")
			}
			if nostrWireProblem(bad, "nostr "+command) != "envelope string type/value" {
				t.Fatal("wire null network was not refused before typed decoding")
			}
		})
	}
}

// Every closed envelope/result/event/failure member is exercised with a null,
// missing member and wrong JSON type beside the real complete output. Null is
// admitted only for success.error and failure.result, as the contract requires.
func TestNostrWireMemberTypes(t *testing.T) {
	for _, command := range []string{"profile-prepare", "profile-verify"} {
		for _, refusal := range []bool{false, true} {
			name := command + map[bool]string{false: "/success", true: "/refusal"}[refusal]
			t.Run(name, func(t *testing.T) {
				event := publicNostrFixture(t)
				var request any = nostrPrepareInput(event)
				if command == "profile-verify" {
					request = map[string]any{"schema": "swarma-identity/nostr-profile-verify/1", "event": event}
				}
				if refusal {
					request = map[string]any{"schema": "invalid"}
				}
				_, code, raw := runCLI(t, "nostr", command, "--request", writeInput(t, request), "--json")
				if (code != 0) != refusal || nostrWireProblem(raw, "nostr "+command) != "" {
					t.Fatal("real wire positive control refused")
				}
				var original map[string]any
				if json.Unmarshal(raw, &original) != nil {
					t.Fatal("wire shape setup")
				}
				var visit func(map[string]any, []string)
				visit = func(object map[string]any, path []string) {
					for member, value := range object {
						parts := append(append([]string{}, path...), member)
						for _, mode := range []string{"null", "missing", "wrong-type"} {
							if mode == "null" && value == nil {
								continue
							}
							t.Run(strings.Join(parts, ".")+"/"+mode, func(t *testing.T) {
								var changed map[string]any
								if json.Unmarshal(raw, &changed) != nil {
									t.Fatal("wire mutation setup")
								}
								dst := changed
								for _, part := range parts[:len(parts)-1] {
									dst = dst[part].(map[string]any)
								}
								switch mode {
								case "missing":
									delete(dst, member)
								case "null":
									dst[member] = nil
								case "wrong-type":
									if _, ok := value.(string); ok {
										dst[member] = 0
									} else {
										dst[member] = "wrong-type"
									}
								}
								bad, _ := json.Marshal(changed)
								if nostrWireProblem(bad, "nostr "+command) == "" {
									t.Fatal("wrong wire member admitted")
								}
							})
						}
						if nested, ok := value.(map[string]any); ok {
							visit(nested, parts)
						}
					}
				}
				visit(original, nil)
			})
		}
	}
}
