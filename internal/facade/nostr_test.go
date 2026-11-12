package facade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"testing"
)

func publicNostrFixture(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile("testdata/nostr/kind0-event.json")
	if err != nil {
		t.Fatal(err)
	}
	var e map[string]any
	if json.Unmarshal(b, &e) != nil {
		t.Fatal("public event fixture")
	}
	return e
}

func nostrPrepareInput(fields map[string]any) map[string]any {
	r := map[string]any{"schema": "swarma-identity/nostr-profile-prepare/1"}
	for _, k := range []string{"pubkey", "created_at", "kind", "tags", "content"} {
		r[k] = fields[k]
	}
	return r
}

func nostrResult(t *testing.T, e Envelope) map[string]json.RawMessage {
	t.Helper()
	b, err := json.Marshal(e.Result)
	var result map[string]json.RawMessage
	if err != nil || json.Unmarshal(b, &result) != nil || result == nil {
		t.Fatal("missing Nostr result")
	}
	return result
}

func assertNostrKeys[V any](t *testing.T, object map[string]V, want ...string) {
	t.Helper()
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Fatalf("Nostr key set = %v, want %v", keys, want)
	}
}

func assertNostrFields(t *testing.T, object, want map[string]any) {
	t.Helper()
	if !reflect.DeepEqual(object, want) {
		t.Fatal("Nostr returned fields differ from independent expected values")
	}
}

// Ordinary boundary/encoding fixtures use standard JSON's common escaping
// subset. Special HTML/separator bytes retain their separate frozen goldens.
func assertNostrPrepared(t *testing.T, e Envelope, fields map[string]any) {
	t.Helper()
	canonical, err := json.Marshal([]any{0, fields["pubkey"], fields["created_at"], fields["kind"], fields["tags"], fields["content"]})
	if err != nil {
		t.Fatal(err)
	}
	id := sha256.Sum256(canonical)
	event := map[string]any{"id": hex.EncodeToString(id[:])}
	for _, key := range []string{"pubkey", "created_at", "kind", "tags", "content"} {
		event[key] = fields[key]
	}
	want := map[string]any{"schema": "swarma-identity/nostr-profile-prepared/1", "canonical_utf8": string(canonical), "event": event}
	assertNostrSuccess(t, e, "nostr profile-prepare", want)
}

func assertNostrVerified(t *testing.T, e Envelope, event map[string]any) {
	t.Helper()
	assertNostrSuccess(t, e, "nostr profile-verify", map[string]any{"schema": "swarma-identity/nostr-profile-verified/1", "valid": true, "id": event["id"], "pubkey": event["pubkey"], "created_at": event["created_at"], "kind": event["kind"]})
}

func assertNostrSuccess(t *testing.T, e Envelope, command string, want map[string]any) {
	t.Helper()
	if e.Schema != "swarma-identity/result/1" || !e.OK || e.Error != nil || e.Network != "" || e.Command != command {
		t.Fatal("Nostr success envelope differs from contract")
	}
	// Normalize test-owned numeric/slice representations through the transport,
	// never through product canonicalization or product result construction.
	var actual, expected map[string]any
	b, err := json.Marshal(e.Result)
	w, werr := json.Marshal(want)
	if err != nil || werr != nil || json.Unmarshal(b, &actual) != nil || json.Unmarshal(w, &expected) != nil {
		t.Fatal("Nostr expected/result transport")
	}
	assertNostrFields(t, actual, expected)
}

type nostrRefusingWriter struct{ calls int }

func (w *nostrRefusingWriter) Write([]byte) (int, error) {
	w.calls++
	return 0, errors.New("controlled stdout refusal")
}

// For these valid inputs a writer that accepts no bytes causes exactly the
// literal stderr fallback and exit1. Writable controls still return full data;
// this does not claim atomicity for writers that accept a partial prefix.
func TestNostrOutputWriterFailure(t *testing.T) {
	for _, command := range []string{"profile-prepare", "profile-verify"} {
		t.Run(command, func(t *testing.T) {
			event := publicNostrFixture(t)
			var request any = nostrPrepareInput(event)
			if command == "profile-verify" {
				request = map[string]any{"schema": "swarma-identity/nostr-profile-verify/1", "event": event}
			}
			args := []string{"nostr", command, "--request", writeInput(t, request), "--json"}
			e, code, _ := runCLI(t, args...)
			if code != 0 {
				t.Fatal("writable positive refused")
			}
			if command == "profile-prepare" {
				assertNostrPrepared(t, e, event)
			} else {
				assertNostrVerified(t, e, event)
			}
			writer := &nostrRefusingWriter{}
			var diagnostics bytes.Buffer
			code = Run(context.Background(), args, writer, &diagnostics)
			if code != 1 || writer.calls != 1 || diagnostics.String() != "Could not write the result.\n" {
				t.Fatalf("writer refusal: exit%d writes%d stderr%q", code, writer.calls, diagnostics.String())
			}
		})
	}
}

// Frozen NIP-01 bytes and independent hashes cover encoder defaults, Unicode,
// lexical metadata preservation, exact integers and ordered duplicate tags.
// All preparation is public and deterministic; no signature is manufactured.
func TestNostrProfileGolden(t *testing.T) {
	b, err := os.ReadFile("testdata/nostr/canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name         string         `json:"name"`
		Fields       map[string]any `json:"fields"`
		CanonicalHex string         `json:"canonical_hex"`
		ID           string         `json:"id"`
	}
	if json.Unmarshal(b, &rows) != nil || len(rows) == 0 {
		t.Fatal("canonical fixtures")
	}
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			request := writeInput(t, nostrPrepareInput(row.Fields))
			e, code, _ := runCLI(t, "nostr", "profile-prepare", "--request", request, "--json")
			if code != 0 || !e.OK || e.Error != nil || e.Network != "" || e.Command != "nostr profile-prepare" {
				t.Fatalf("offline prepare refused: code%d %#v", code, e.Error)
			}
			r := nostrResult(t, e)
			assertNostrKeys(t, r, "schema", "canonical_utf8", "event")
			var canonical, schema string
			var event map[string]any
			if len(r) != 3 || json.Unmarshal(r["canonical_utf8"], &canonical) != nil || json.Unmarshal(r["schema"], &schema) != nil || schema != "swarma-identity/nostr-profile-prepared/1" || json.Unmarshal(r["event"], &event) != nil || len(event) != 6 {
				t.Fatal("wrong prepared result schema")
			}
			if hex.EncodeToString([]byte(canonical)) != row.CanonicalHex || event["id"] != row.ID || event["content"] != row.Fields["content"] {
				t.Fatal("canonical bytes/id/content differ from independent golden")
			}
			assertNostrKeys(t, event, "id", "pubkey", "created_at", "kind", "tags", "content")
			assertNostrFields(t, event, map[string]any{"id": row.ID, "pubkey": row.Fields["pubkey"], "created_at": row.Fields["created_at"], "kind": row.Fields["kind"], "tags": row.Fields["tags"], "content": row.Fields["content"]})
			if _, exists := event["sig"]; exists {
				t.Fatal("unsigned preparation invented a signature")
			}
			e2, code2, _ := runCLI(t, "nostr", "profile-prepare", "--request", request, "--json")
			b1, _ := json.Marshal(e.Result)
			b2, _ := json.Marshal(e2.Result)
			if code2 != 0 || !bytes.Equal(b1, b2) {
				t.Fatal("fixed public preparation is not deterministic")
			}
		})
	}
}

// A pinned already-signed neutral kind-0 event succeeds through both complete
// CLI paths. This is public fixture verification, never a signing round trip.
func TestNostrProfileSignedPublicFixture(t *testing.T) {
	event := publicNostrFixture(t)
	e, code, _ := runCLI(t, "nostr", "profile-prepare", "--request", writeInput(t, nostrPrepareInput(event)), "--json")
	if code != 0 || e.Error != nil {
		t.Fatalf("public prepare control refused: %d %#v", code, e.Error)
	}
	var prepared map[string]any
	if json.Unmarshal(nostrResult(t, e)["event"], &prepared) != nil || prepared["id"] != event["id"] {
		t.Fatal("public fixture id mismatch")
	}
	assertNostrKeys(t, prepared, "id", "pubkey", "created_at", "kind", "tags", "content")
	wantPrepared := map[string]any{}
	for _, key := range []string{"id", "pubkey", "created_at", "kind", "tags", "content"} {
		wantPrepared[key] = event[key]
	}
	assertNostrFields(t, prepared, wantPrepared)
	request := map[string]any{"schema": "swarma-identity/nostr-profile-verify/1", "event": event}
	e, code, _ = runCLI(t, "nostr", "profile-verify", "--request", writeInput(t, request), "--json")
	if code != 0 || !e.OK || e.Error != nil || e.Network != "" || e.Command != "nostr profile-verify" {
		t.Fatalf("public verify control refused: %d %#v", code, e.Error)
	}
	r := nostrResult(t, e)
	assertNostrKeys(t, r, "schema", "valid", "id", "pubkey", "created_at", "kind")
	var valid bool
	var id, schema string
	if len(r) != 6 || json.Unmarshal(r["valid"], &valid) != nil || !valid || json.Unmarshal(r["id"], &id) != nil || id != event["id"] || json.Unmarshal(r["schema"], &schema) != nil || schema != "swarma-identity/nostr-profile-verified/1" {
		t.Fatal("wrong verified result")
	}
	var summary map[string]any
	b, _ := json.Marshal(e.Result)
	if json.Unmarshal(b, &summary) != nil {
		t.Fatal("verified summary")
	}
	assertNostrFields(t, summary, map[string]any{"schema": "swarma-identity/nostr-profile-verified/1", "valid": true, "id": event["id"], "pubkey": event["pubkey"], "created_at": event["created_at"], "kind": event["kind"]})
}

// Transport field order/whitespace/escaped aliases do not change the decoded
// public event, while the separate lexical goldens preserve content spelling.
func TestNostrTransportEquivalence(t *testing.T) {
	fields := nostrPrepareInput(publicNostrFixture(t))
	base, _ := json.Marshal(fields)
	var outputs [][]byte
	for _, alias := range []bool{false, true} {
		var request []byte
		if !alias {
			request = base
		} else {
			var b bytes.Buffer
			b.WriteString(" \n{")
			for i, field := range []string{"tags", "created_at", "schema", "content", "kind", "pubkey"} {
				if i > 0 {
					b.WriteString(",\n")
				}
				key := `"` + field + `"`
				if field == "pubkey" {
					key = `"p\u0075bkey"`
				}
				value, _ := json.Marshal(fields[field])
				b.WriteString(key + " : ")
				b.Write(value)
			}
			b.WriteString("}\t ")
			request = b.Bytes()
		}
		e, code, _ := runCLI(t, "nostr", "profile-prepare", "--request", writeNostrRaw(t, request), "--json")
		if code != 0 || !e.OK {
			t.Fatal("equivalent transport refused")
		}
		b, _ := json.Marshal(e.Result)
		outputs = append(outputs, b)
	}
	if !bytes.Equal(outputs[0], outputs[1]) {
		t.Fatal("transport spelling changed canonical result")
	}
}
