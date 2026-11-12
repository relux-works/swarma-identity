package facade

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeNostrRaw(t *testing.T, raw []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertNostrRefusal(t *testing.T, e Envelope, code int, want string, exit int, raw []byte) {
	t.Helper()
	if code != exit || e.OK || e.Error == nil || e.Error.Code != want || e.Error.Retryable || e.Result != nil || e.Network != "" {
		t.Fatalf("Nostr refusal = code%d %#v, want %s/exit%d/nonretryable/no result", code, e.Error, want, exit)
	}
	if strings.Contains(string(raw), "nostr-input-marker") {
		t.Fatal("refusal echoed input")
	}
	wantMessage := fail(want).Message
	if want == "EVENT_ID_MISMATCH" {
		wantMessage = "The supplied event id does not match its canonical fields."
	} else if want == "INVALID_SIGNATURE" {
		wantMessage = "The supplied event signature is not valid for its public key and event id."
	}
	if e.Error.Message != wantMessage {
		t.Fatal("refusal did not use the fixed diagnostic")
	}
}

// This independent reference uses the standard JSON encoder only for ASCII
// tamper fixtures without HTML/separator characters. Unicode/escaping expected
// bytes come separately from the frozen external golden corpus.
func asciiNostrReference(t *testing.T, e map[string]any) string {
	t.Helper()
	b, err := json.Marshal([]any{0, e["pubkey"], e["created_at"], e["kind"], e["tags"], e["content"]})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Each signed field is bound twice: stale ids fail the independent hash check;
// recomputed altered ids with the old signature fail public verification. The
// already-signed unaltered event is the nearby complete CLI positive control.
func TestNostrProfileTampering(t *testing.T) {
	for _, field := range []string{"content", "created_at", "tags", "pubkey"} {
		for _, recompute := range []bool{false, true} {
			t.Run(field+map[bool]string{false: "/stale-id", true: "/new-id"}[recompute], func(t *testing.T) {
				event := publicNostrFixture(t)
				switch field {
				case "content":
					event[field] = `{"name":"nostr-input-marker"}`
				case "created_at":
					event[field] = event[field].(float64) + 1
				case "tags":
					event[field] = [][]string{{"x", "nostr-input-marker"}}
				case "pubkey":
					// Public key from official BIP-340 vector 0, never its secret.
					other := "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
					if event[field] == other {
						t.Fatal("key binding control must change the public key")
					}
					event[field] = other
				}
				want := "EVENT_ID_MISMATCH"
				if recompute {
					event["id"] = asciiNostrReference(t, event)
					want = "INVALID_SIGNATURE"
				}
				r := map[string]any{"schema": NostrVerifySchema, "event": event}
				e, code, raw := runCLI(t, "nostr", "profile-verify", "--request", writeInput(t, r), "--json")
				assertNostrRefusal(t, e, code, want, 3, raw)
			})
		}
	}
	for _, tc := range []struct{ name, id, sig, code string }{
		{"bad-id", strings.Repeat("0", 64), "", "EVENT_ID_MISMATCH"},
		{"bad-signature", "", strings.Repeat("0", 128), "INVALID_SIGNATURE"},
		{"hash-before-signature", strings.Repeat("0", 64), strings.Repeat("0", 128), "EVENT_ID_MISMATCH"},
		{"signature-out-of-range", "", strings.Repeat("f", 128), "INVALID_SIGNATURE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := publicNostrFixture(t)
			if tc.id != "" {
				event["id"] = tc.id
			}
			if tc.sig != "" {
				event["sig"] = tc.sig
			}
			e, code, raw := runCLI(t, "nostr", "profile-verify", "--request", writeInput(t, map[string]any{"schema": NostrVerifySchema, "event": event}), "--json")
			assertNostrRefusal(t, e, code, tc.code, 3, raw)
		})
	}
	TestNostrProfileSignedPublicFixture(t)
}

// Official public-vector outcomes ground verification independently of local
// signing or an implementation agreeing with itself. The Nostr digest is32B;
// variable-message-length official rows are explicitly outside this interface.
func TestNostrBIP340PublicVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/nostr/bip340-verification.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Index     string `json:"index"`
		Pubkey    string `json:"public_key"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
		Expected  string `json:"verification_result"`
	}
	if json.Unmarshal(b, &rows) != nil {
		t.Fatal("public verification corpus")
	}
	positive, negative := 0, 0
	for _, row := range rows {
		if len(row.Message) != 64 {
			continue
		}
		t.Run(row.Index, func(t *testing.T) {
			pk, e1 := hex.DecodeString(row.Pubkey)
			msg, e2 := hex.DecodeString(row.Message)
			sig, e3 := hex.DecodeString(row.Signature)
			if e1 != nil || e2 != nil || e3 != nil {
				t.Fatal("public vector encoding")
			}
			want := row.Expected == "TRUE"
			if want {
				positive++
			} else {
				negative++
			}
			if verifyNostrSignature(pk, msg, sig) != want {
				t.Fatal("verifier disagrees with official public vector outcome")
			}
		})
	}
	if positive != 5 || negative != 10 {
		t.Fatalf("fixed32-byte controls = %d positive/%d negative", positive, negative)
	}
}

// Closed envelopes/events and typed arrays reject ambiguity without weakening
// arbitrary metadata content. Valid escaped field names and metadata-null are
// paired controls; duplicate decoded names and structural null remain refused.
func TestNostrStrictInputs(t *testing.T) {
	valid := nostrPrepareInput(publicNostrFixture(t))
	for _, field := range []string{"schema", "pubkey", "created_at", "kind", "tags", "content"} {
		for _, missing := range []bool{false, true} {
			t.Run(field+map[bool]string{false: "/null", true: "/missing"}[missing], func(t *testing.T) {
				r := nostrPrepareInput(publicNostrFixture(t))
				if missing {
					delete(r, field)
				} else {
					r[field] = nil
				}
				e, code, raw := runCLI(t, "nostr", "profile-prepare", "--request", writeInput(t, r), "--json")
				assertNostrRefusal(t, e, code, "BAD_INPUT", 2, raw)
			})
		}
	}
	for _, tc := range []struct {
		name, field string
		value       any
	}{
		{"unknown", "extra", "nostr-input-marker"},
		{"schema", "schema", "other/1"},
		{"uppercase-key", "pubkey", strings.ToUpper(valid["pubkey"].(string))},
		{"invalid-point", "pubkey", strings.Repeat("f", 64)},
		{"short-key", "pubkey", "00"},
		{"null-tag", "tags", []any{nil}},
		{"null-tag-item", "tags", []any{[]any{"x", nil}}},
		{"mixed-tag", "tags", []any{[]any{"x", 1}}},
		{"nested-tag", "tags", []any{[]any{"x", []any{"y"}}}},
		{"empty-tag", "tags", [][]string{{}}},
		{"metadata-array", "content", `[]`},
		{"metadata-null", "content", `null`},
		{"metadata-string", "content", `"x"`},
		{"metadata-duplicate", "content", `{"a":1,"a":2}`},
		{"metadata-escaped-duplicate", "content", `{"a":1,"\u0061":2}`},
		{"metadata-nested-duplicate", "content", `{"x":[{"a":1,"a":2}]}`},
		{"metadata-lone-surrogate", "content", `{"a":"\ud800"}`},
		{"metadata-trailing-document", "content", `{} {}`},
		{"fraction-time", "created_at", 1.5},
		{"string-time", "created_at", "1"},
		{"negative-time", "created_at", -1},
		{"unsafe-time", "created_at", uint64(9007199254740992)},
		{"invalid-kind", "kind", 65536},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := nostrPrepareInput(publicNostrFixture(t))
			r[tc.field] = tc.value
			e, code, raw := runCLI(t, "nostr", "profile-prepare", "--request", writeInput(t, r), "--json")
			assertNostrRefusal(t, e, code, "BAD_INPUT", 2, raw)
		})
	}
	for _, field := range []string{"id", "pubkey", "created_at", "kind", "tags", "content", "sig"} {
		t.Run("verify-null/"+field, func(t *testing.T) {
			event := publicNostrFixture(t)
			event[field] = nil
			e, code, raw := runCLI(t, "nostr", "profile-verify", "--request", writeInput(t, map[string]any{"schema": NostrVerifySchema, "event": event}), "--json")
			assertNostrRefusal(t, e, code, "BAD_INPUT", 2, raw)
		})
	}
	b, _ := json.Marshal(valid)
	for name, raw := range map[string][]byte{
		"duplicate-root":         []byte(strings.TrimSuffix(string(b), "}") + `,"schema":"other"}`),
		"escaped-duplicate-root": []byte(strings.TrimSuffix(string(b), "}") + `,"\u0073chema":"other"}`),
		"null-event":             []byte(`{"schema":"swarma-identity/nostr-profile-verify/1","event":null}`),
		"invalid-utf8":           append(append([]byte{}, b[:len(b)-1]...), 0xff, '}'),
	} {
		t.Run(name, func(t *testing.T) {
			command := "profile-prepare"
			if name == "null-event" {
				command = "profile-verify"
			}
			e, code, output := runCLI(t, "nostr", command, "--request", writeNostrRaw(t, raw), "--json")
			assertNostrRefusal(t, e, code, "BAD_INPUT", 2, output)
		})
	}
	for _, content := range []string{`{"nullable":null}`, ` {"x":[null,true,1e400,{"y":"z"}]} `} {
		r := nostrPrepareInput(publicNostrFixture(t))
		r["content"] = content
		e, code, _ := runCLI(t, "nostr", "profile-prepare", "--request", writeInput(t, r), "--json")
		if code != 0 || e.Error != nil {
			t.Fatal("arbitrary metadata-member/null/number control refused")
		}
	}
	alias := strings.Replace(string(b), `"pubkey":`, `"p\u0075bkey":`, 1)
	e, code, _ := runCLI(t, "nostr", "profile-prepare", "--request", writeNostrRaw(t, []byte(alias)), "--json")
	if code != 0 || e.Error != nil {
		t.Fatal("unambiguous escaped field name control refused")
	}
}
