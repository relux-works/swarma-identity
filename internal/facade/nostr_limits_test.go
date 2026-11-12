package facade

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func checkNostrPrepare(t *testing.T, r map[string]any, want string) Envelope {
	t.Helper()
	e, code, raw := runCLI(t, "nostr", "profile-prepare", "--request", writeInput(t, r), "--json")
	if want != "" {
		exit := 2
		if want == "UNSUPPORTED_CAPABILITY" {
			exit = 3
		}
		assertNostrRefusal(t, e, code, want, exit, raw)
	} else if code != 0 || !e.OK || e.Error != nil || e.Network != "" {
		t.Fatalf("bounded positive control refused: %d %#v", code, e.Error)
	} else {
		assertNostrPrepared(t, e, r)
	}
	return e
}

// No signature is manufactured: a changed, admissible public event must get
// past admission and fail its old signature; malformed bytes must fail earlier.
func checkNostrBoundary(t *testing.T, r map[string]any, want string) Envelope {
	t.Helper()
	var prepared Envelope
	t.Run("prepare", func(t *testing.T) { prepared = checkNostrPrepare(t, r, want) })
	t.Run("verify", func(t *testing.T) {
		event := publicNostrFixture(t)
		originalID := event["id"]
		for _, key := range []string{"pubkey", "created_at", "kind", "tags", "content"} {
			event[key] = r[key]
		}
		event["id"] = simpleNostrReference(t, event)
		expect := want
		if expect == "" && event["id"] != originalID {
			expect = "INVALID_SIGNATURE"
		}
		e, code, raw := runCLI(t, "nostr", "profile-verify", "--request", writeInput(t, map[string]any{"schema": NostrVerifySchema, "event": event}), "--json")
		if expect == "" {
			if code != 0 || !e.OK {
				t.Fatal("unchanged signed boundary control refused")
			}
			assertNostrVerified(t, e, event)
			return
		}
		exit := 3
		if expect == "BAD_INPUT" {
			exit = 2
		}
		assertNostrRefusal(t, e, code, expect, exit, raw)
	})
	return prepared
}

// Each ceiling is exercised at its exact admitted limit and just outside it.
// UTF-8 and escaping expansion are measured in bytes, independently of counts.
func TestNostrLimits(t *testing.T) {
	// Empty tags and a one-string empty tag are admitted minima; zero items
	// in a tag and metadata shorter than an object are refused in both paths.
	for _, tc := range []struct {
		name          string
		tags          [][]string
		content, want string
	}{
		{"empty-tags", [][]string{}, "{}", ""},
		{"one-empty-string", [][]string{{""}}, "{}", ""},
		{"empty-tag", [][]string{{}}, "{}", "BAD_INPUT"},
		{"one-byte-content", [][]string{}, " ", "BAD_INPUT"},
		{"empty-content", [][]string{}, "", "BAD_INPUT"},
	} {
		t.Run("minimum/"+tc.name, func(t *testing.T) {
			r := nostrPrepareInput(publicNostrFixture(t))
			r["tags"] = tc.tags
			r["content"] = tc.content
			checkNostrBoundary(t, r, tc.want)
		})
	}
	for _, tc := range []struct {
		name string
		set  func(map[string]any, bool)
	}{
		{"content-bytes", func(r map[string]any, over bool) {
			n := 16384
			if over {
				n++
			}
			r["content"] = `{"x":"` + strings.Repeat("a", n-8) + `"}`
		}},
		{"content-multibyte", func(r map[string]any, over bool) {
			s := strings.Repeat("é", (16384-8)/2)
			if over {
				s += "a"
			}
			r["content"] = `{"x":"` + s + `"}`
		}},
		{"tag-count", func(r map[string]any, over bool) {
			n := 128
			if over {
				n++
			}
			tags := make([][]string, n)
			for i := range tags {
				tags[i] = []string{""}
			}
			r["tags"] = tags
		}},
		{"tag-item-count", func(r map[string]any, over bool) {
			n := 16
			if over {
				n++
			}
			r["tags"] = [][]string{make([]string, n)}
		}},
		{"tag-utf8-bytes", func(r map[string]any, over bool) {
			s := strings.Repeat("é", 512)
			if over {
				s += "a"
			}
			r["tags"] = [][]string{{s}}
		}},
		{"aggregate-tag-bytes", func(r map[string]any, over bool) {
			tags := make([][]string, 9)
			for i := 0; i < 8; i++ {
				tags[i] = []string{strings.Repeat("a", 1024)}
			}
			tags[8] = []string{""}
			if over {
				tags[8][0] = "a"
			}
			r["tags"] = tags
		}},
		{"aggregate-multibyte", func(r map[string]any, over bool) {
			tags := make([][]string, 9)
			for i := 0; i < 8; i++ {
				tags[i] = []string{strings.Repeat("é", 512)}
			}
			tags[8] = []string{""}
			if over {
				tags[8][0] = "a"
			}
			r["tags"] = tags
		}},
		{"metadata-depth", func(r map[string]any, over bool) {
			n := 32
			if over {
				n++
			}
			r["content"] = strings.Repeat(`{"x":`, n) + "0" + strings.Repeat("}", n)
		}},
	} {
		for _, over := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/over=%t", tc.name, over), func(t *testing.T) {
				r := nostrPrepareInput(publicNostrFixture(t))
				tc.set(r, over)
				want := ""
				if over {
					want = "BAD_INPUT"
				}
				checkNostrBoundary(t, r, want)
			})
		}
	}
	for _, n := range []int{65536, 65537} {
		t.Run(fmt.Sprintf("request-bytes/%d", n), func(t *testing.T) {
			for _, command := range []string{"profile-prepare", "profile-verify"} {
				t.Run(command, func(t *testing.T) {
					event := publicNostrFixture(t)
					var request any = nostrPrepareInput(event)
					if command == "profile-verify" {
						request = map[string]any{"schema": NostrVerifySchema, "event": event}
					}
					raw, _ := json.Marshal(request)
					raw = append(raw, []byte(strings.Repeat(" ", n-len(raw)))...)
					e, code, b := runCLI(t, "nostr", command, "--request", writeNostrRaw(t, raw), "--json")
					if n == 65537 {
						assertNostrRefusal(t, e, code, "BAD_INPUT", 2, b)
					} else if code != 0 || !e.OK {
						t.Fatal("exact raw-file limit refused")
					} else if command == "profile-prepare" {
						assertNostrPrepared(t, e, event)
					} else {
						assertNostrVerified(t, e, event)
					}
				})
			}
		})
	}
	// Construct the length with an independent ASCII-only serializer. All
	// individual field limits still pass; only the complete canonical cap moves.
	for _, n := range []int{32768, 32769} {
		t.Run(fmt.Sprintf("canonical-bytes/%d", n), func(t *testing.T) {
			r := nostrPrepareInput(publicNostrFixture(t))
			tags := make([][]string, 8)
			for i := range tags {
				tags[i] = []string{strings.Repeat("\n", 1024)}
			}
			r["tags"] = tags
			r["content"] = `{"x":""}`
			base, _ := json.Marshal([]any{0, r["pubkey"], r["created_at"], r["kind"], r["tags"], r["content"]})
			pad := n - len(base)
			if pad < 0 || pad+8 > 16384 {
				t.Fatal("invalid independent boundary construction")
			}
			r["content"] = `{"x":"` + strings.Repeat("a", pad) + `"}`
			ref, _ := json.Marshal([]any{0, r["pubkey"], r["created_at"], r["kind"], r["tags"], r["content"]})
			if len(ref) != n {
				t.Fatal("reference length")
			}
			want := ""
			if n > 32768 {
				want = "BAD_INPUT"
			}
			e := checkNostrBoundary(t, r, want)
			if want == "" {
				var canonical string
				if json.Unmarshal(nostrResult(t, e)["canonical_utf8"], &canonical) != nil || canonical != string(ref) {
					t.Fatal("exact canonical limit changed bytes")
				}
			}
		})
	}
}

// Only the five listed C0 values are supported tag characters; quote and
// backslash complete the seven escapes. DEL, astral Unicode and empty strings
// remain valid. This is the local interface subset, not general relay policy.
func TestNostrTagControls(t *testing.T) {
	for c := 0; c < 32; c++ {
		t.Run(fmt.Sprintf("U+%04X", c), func(t *testing.T) {
			r := nostrPrepareInput(publicNostrFixture(t))
			r["tags"] = [][]string{{string(rune(c))}}
			want := "BAD_INPUT"
			if c == 8 || c == 9 || c == 10 || c == 12 || c == 13 {
				want = ""
			}
			checkNostrBoundary(t, r, want)
		})
	}
	r := nostrPrepareInput(publicNostrFixture(t))
	r["tags"] = [][]string{{"", "\x7f", "😀", `"\`}}
	checkNostrBoundary(t, r, "")
}

// Canonical number syntax is separate from numeric range. Unsupported kinds
// are refused only after malformed fields, with equivalent rules in verify.
func TestNostrNumbersAndVerifyShape(t *testing.T) {
	for _, lexeme := range []string{"-0", "-1", "1e0", "1.0", "true", "9007199254740992"} {
		t.Run("timestamp/"+lexeme, func(t *testing.T) {
			r := nostrPrepareInput(publicNostrFixture(t))
			r["created_at"] = json.RawMessage(lexeme)
			checkNostrBoundary(t, r, "BAD_INPUT")
		})
	}
	for _, ts := range []uint64{0, 9007199254740991} {
		r := nostrPrepareInput(publicNostrFixture(t))
		r["created_at"] = ts
		checkNostrBoundary(t, r, "")
	}
	for _, lexeme := range []string{"-0", "-1", "1e0", "0.0", "true", "65536"} {
		r := nostrPrepareInput(publicNostrFixture(t))
		r["kind"] = json.RawMessage(lexeme)
		checkNostrBoundary(t, r, "BAD_INPUT")
	}
	for _, kind := range []int{1, 65535} {
		r := nostrPrepareInput(publicNostrFixture(t))
		r["kind"] = kind
		checkNostrPrepare(t, r, "UNSUPPORTED_CAPABILITY")
		event := publicNostrFixture(t)
		event["kind"] = kind
		e, code, raw := runCLI(t, "nostr", "profile-verify", "--request", writeInput(t, map[string]any{"schema": NostrVerifySchema, "event": event}), "--json")
		assertNostrRefusal(t, e, code, "UNSUPPORTED_CAPABILITY", 3, raw)
		event["sig"] = "nostr-input-marker"
		e, code, raw = runCLI(t, "nostr", "profile-verify", "--request", writeInput(t, map[string]any{"schema": NostrVerifySchema, "event": event}), "--json")
		assertNostrRefusal(t, e, code, "BAD_INPUT", 2, raw)
	}
	for _, field := range []string{"id", "pubkey", "created_at", "kind", "tags", "content", "sig"} {
		event := publicNostrFixture(t)
		delete(event, field)
		e, code, raw := runCLI(t, "nostr", "profile-verify", "--request", writeInput(t, map[string]any{"schema": NostrVerifySchema, "event": event}), "--json")
		assertNostrRefusal(t, e, code, "BAD_INPUT", 2, raw)
	}
	for _, sig := range []string{"", strings.Repeat("f", 127), strings.Repeat("g", 128), strings.Repeat("A", 128)} {
		event := publicNostrFixture(t)
		event["sig"] = sig
		e, code, raw := runCLI(t, "nostr", "profile-verify", "--request", writeInput(t, map[string]any{"schema": NostrVerifySchema, "event": event}), "--json")
		assertNostrRefusal(t, e, code, "BAD_INPUT", 2, raw)
	}
	event := publicNostrFixture(t)
	event["unknown"] = true
	e, code, raw := runCLI(t, "nostr", "profile-verify", "--request", writeInput(t, map[string]any{"schema": NostrVerifySchema, "event": event}), "--json")
	assertNostrRefusal(t, e, code, "BAD_INPUT", 2, raw)
	base, _ := json.Marshal(publicNostrFixture(t))
	for _, member := range []string{`"id":"` + strings.Repeat("0", 64) + `",`, `"\u0069d":"` + strings.Repeat("0", 64) + `",`} {
		body := `{"schema":"` + NostrVerifySchema + `","event":{` + member + string(base[1:]) + `}`
		e, code, raw := runCLI(t, "nostr", "profile-verify", "--request", writeNostrRaw(t, []byte(body)), "--json")
		assertNostrRefusal(t, e, code, "BAD_INPUT", 2, raw)
	}
	TestNostrProfileSignedPublicFixture(t)
}

// Offline dispatch rejects online/signing/output flags and ignores ambient
// configuration/time. Valid explicit inputs work beside every refused flag.
func TestNostrOfflineCLI(t *testing.T) {
	for _, key := range []string{"NAMECOIN_RPC_URL", "NAMECOIN_CONFIG", "SWARMA_IDENTITY_CONFIG", "SWARMA_KEYVAULT_SOCKET", "NOSTR_RELAY", "HTTP_PROXY", "HTTPS_PROXY"} {
		t.Setenv(key, "nostr-input-marker://invalid")
	}
	for _, command := range []string{"profile-prepare", "profile-verify"} {
		var r any = nostrPrepareInput(publicNostrFixture(t))
		if command == "profile-verify" {
			r = map[string]any{"schema": NostrVerifySchema, "event": publicNostrFixture(t)}
		}
		path := writeInput(t, r)
		for _, flags := range [][]string{{"--config", "nostr-input-marker"}, {"--mode", "online"}, {"--relay", "nostr-input-marker"}, {"--output", "nostr-input-marker"}, {"--sign"}, {"--request", path}, {"--json"}, {"positional"}, {"-json"}, {"--json=false"}} {
			args := append([]string{"nostr", command, "--request", path, "--json"}, flags...)
			e, code, raw := runCLI(t, args...)
			assertNostrRefusal(t, e, code, "BAD_INPUT", 2, raw)
		}
		for _, args := range [][]string{{"nostr", command, "--json"}, {"nostr", command, "--request", path}} {
			e, code, raw := runCLI(t, args...)
			assertNostrRefusal(t, e, code, "BAD_INPUT", 2, raw)
		}
	}
	TestNostrProfileSignedPublicFixture(t)
}
