package facade

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
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
			var canonical, schema string
			var event map[string]any
			if len(r) != 3 || json.Unmarshal(r["canonical_utf8"], &canonical) != nil || json.Unmarshal(r["schema"], &schema) != nil || schema != "swarma-identity/nostr-profile-prepared/1" || json.Unmarshal(r["event"], &event) != nil || len(event) != 6 {
				t.Fatal("wrong prepared result schema")
			}
			if hex.EncodeToString([]byte(canonical)) != row.CanonicalHex || event["id"] != row.ID || event["content"] != row.Fields["content"] {
				t.Fatal("canonical bytes/id/content differ from independent golden")
			}
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
	request := map[string]any{"schema": "swarma-identity/nostr-profile-verify/1", "event": event}
	e, code, _ = runCLI(t, "nostr", "profile-verify", "--request", writeInput(t, request), "--json")
	if code != 0 || !e.OK || e.Error != nil || e.Network != "" || e.Command != "nostr profile-verify" {
		t.Fatalf("public verify control refused: %d %#v", code, e.Error)
	}
	r := nostrResult(t, e)
	var valid bool
	var id, schema string
	if len(r) != 6 || json.Unmarshal(r["valid"], &valid) != nil || !valid || json.Unmarshal(r["id"], &id) != nil || id != event["id"] || json.Unmarshal(r["schema"], &schema) != nil || schema != "swarma-identity/nostr-profile-verified/1" {
		t.Fatal("wrong verified result")
	}
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
