package grantv4

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type wireEntry struct {
	stage string
	value object
}

func loadWire(t *testing.T) (object, []wireEntry, map[string]object) {
	t.Helper()
	raw, err := os.ReadFile("testdata/wire-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if hash(raw) != "0d14f471e4a0a39c99455fab663bdce5c05f2c97fe2383ecbe95717721d53ae0" {
		t.Fatal("wire corpus pin changed")
	}
	var data object
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&data) != nil {
		t.Fatal("wire corpus decoding")
	}
	var entries []wireEntry
	byID := map[string]object{}
	var walk func(any, string)
	walk = func(v any, path string) {
		switch x := v.(type) {
		case object:
			if id := str(x, "id"); id != "" {
				entries = append(entries, wireEntry{path, x})
				byID[id] = x
				return
			}
			for _, name := range keys(x) {
				walk(x[name], path+"/"+name)
			}
		case []any:
			for _, child := range x {
				walk(child, path)
			}
		}
	}
	for _, name := range []string{"canonical", "integers", "primitives", "assents", "identifiers", "consent_events", "issuance"} {
		walk(data[name], name)
	}
	if len(entries) != 207 {
		t.Fatalf("wire vector count: %d, want 207", len(entries))
	}
	return data, entries, byID
}

// wireGrant models the specification's stated context, never a verified grant.
// Its raw identifier/signature inputs may be the historical memberless stand-in.
func wireGrant(c object, primitive object) *Grant {
	r := object{"key": str(c, "request_public_key")}
	if str(c, "mode") == "name" {
		r = object{"name": str(c, "recipient_name")}
	}
	signer := str(c, "issuer_public_key")
	if signer == "" {
		signer = str(c, "party_public_key")
	}
	g := &Grant{payload: object{"genesis": str(c, "genesis"), "contract": str(c, "contract"), "recipient": r}, signer: signer}
	if primitive != nil {
		g.raw, _ = hex.DecodeString(str(primitive, "octets_hex"))
		g.signed, _ = hex.DecodeString(str(primitive, "signed_octets_hex"))
		g.signature = str(primitive, "signature")
	}
	return g
}

func wireOutpoint(v object) *Outpoint {
	if v == nil {
		return nil
	}
	return &Outpoint{TxID: str(v, "txid"), Vout: uint32(num(v, "vout"))}
}

func wireExpected(entry wireEntry) string {
	v := entry.value
	want := str(v, "expect")
	if want == "" {
		want = "ok"
	}
	// Node evidence is deliberately not accepted as caller-supplied facts.
	switch str(v, "id") {
	case "consent-v-02", "consent-c-20", "consent-c-21", "consent-c-22", "consent-c-23", "consent-c-24", "consent-c-25", "consent-c-26", "consent-c-27", "consent-c-28", "consent-c-29", "consent-c-30", "consent-c-31",
		"issuance-v-02", "issuance-i-09", "composed-v-02", "composed-i-03":
		return "UNSUPPORTED_CAPABILITY"
	}
	return want
}

func runWire(t *testing.T, entry wireEntry, byID map[string]object) (err error) {
	t.Helper()
	defer guard(&err)
	v := entry.value
	get := func(name string) []byte { return octets(t, str(v, name)) }
	equal := func(got, want, claim string) {
		t.Helper()
		if got != want {
			t.Fatalf("%s differs from vector", claim)
		}
	}
	base := obj(byID["consent-c-01"], "context")
	switch {
	case strings.HasPrefix(entry.stage, "canonical/"):
		raw := get("hex")
		parseDocument(raw, 65536)
		if str(v, "sha256") != "" {
			equal(hash(raw), str(v, "sha256"), "canonical hash")
			equal(string(raw), str(v, "text"), "canonical octets")
		}
	case strings.HasPrefix(entry.stage, "integers/"):
		checkSchema(v["value"], leaf("amount"))
	case strings.HasPrefix(entry.stage, "primitives/"):
		switch {
		case strings.HasSuffix(entry.stage, "/types"):
			equal(hex.EncodeToString([]byte(str(v, "type"))), str(v, "tag_hex"), "tag octets")
			equal(hash([]byte(str(v, "type"))), str(v, "tag_sha256"), "tag hash")
			equal(string(get("octets_hex")), str(v, "octets"), "primitive octets")
			equal(typed(str(v, "type"), get("octets_hex")), str(v, "typed_digest"), "typed digest")
			equal(hash(get("octets_hex")), str(v, "sha256"), "payload identifier")
		case strings.HasSuffix(entry.stage, "/cross"):
			equal(typed(str(v, "under"), get("octets_hex")), str(v, "typed_digest"), "cross-type digest")
		case strings.HasSuffix(entry.stage, "/descriptive"):
			equal(typed(str(v, "type"), get("without_hex")), str(v, "without_typed_digest"), "plain digest")
			equal(hash(get("without_hex")), str(v, "without_sha256"), "plain identifier")
			equal(typed(str(v, "type"), get("with_member_hex")), str(v, "with_member_typed_digest"), "descriptive digest")
			equal(hash(get("with_member_hex")), str(v, "with_member_sha256"), "descriptive identifier")
		case strings.HasSuffix(entry.stage, "/grant_stand_in"):
			equal(typed(str(v, "type"), get("octets_hex")), str(v, "typed_digest"), "stand-in digest")
			equal(hash(get("octets_hex")), str(v, "identifier"), "stand-in identifier")
			equal(hash(get("signed_octets_hex")), str(v, "content_address"), "stand-in address")
			if !Verify(str(v, "public_key"), str(v, "typed_digest"), str(v, "signature")) {
				t.Fatal("stand-in signature")
			}
		default:
			t.Fatal("unhandled primitive stage")
		}
	case entry.stage == "assents/bindings":
		_, _, err = checkAssent(get("signed_form_hex"), wireGrant(obj(v, "context"), nil))
	case strings.HasPrefix(entry.stage, "assents/"):
		var p object
		p, _, err = readAssent(get("signed_form_hex"), nil)
		if err == nil && strings.HasSuffix(entry.stage, "/valid") {
			raw, digest, e := AssentPayload(wireGrant(object{"genesis": str(p, "genesis"), "contract": str(p, "contract"), "party_public_key": str(p, "party")}, nil))
			if e != nil {
				t.Fatal(e)
			}
			equal(hex.EncodeToString(raw), str(v, "payload_hex"), "assent payload")
			equal(string(raw), str(v, "payload"), "assent text")
			equal(digest, str(v, "typed_digest"), "assent digest")
			equal(hash(raw), str(v, "assent_id"), "assent identifier")
			equal(hash(get("signed_form_hex")), str(v, "content_address"), "assent address")
		}
	case entry.stage == "identifiers":
		source := byID[str(v, "object")]
		var ref *string
		if s := str(v, "reference"); s != "" {
			ref = &s
		}
		var p object
		p, _, err = readAssent(octets(t, str(source, "signed_form_hex")), ref)
		if err == nil && str(v, "identifier") != "" {
			equal(hash(encode(p)), str(v, "identifier"), "identifier")
			equal(typed(AssentType, encode(p)), str(v, "typed_digest"), "identifier digest")
			equal(hash(octets(t, str(source, "signed_form_hex"))), str(v, "content_address"), "identifier address")
		}
	case strings.HasPrefix(entry.stage, "consent_events/"):
		context := obj(v, "context")
		if context == nil {
			context = base
			if str(v, "id") == "consent-v-02" {
				context = obj(byID["consent-c-20"], "context")
			}
		}
		var event Event
		event, err = checkConsent(get("event_hex"), wireGrant(context, nil), int64(num(context, "now")))
		if err == nil && str(v, "event_id") != "" {
			equal(event.ID, str(v, "event_id"), "event id")
			equal(string(eventJSON([]any{0, event.Pubkey, event.CreatedAt, event.Kind, event.Tags, event.Content})), str(v, "id_preimage"), "event id preimage")
		}
	case entry.stage == "issuance/stored" || entry.stage == "issuance/compound":
		err = readPreparation(get("preparation_hex"))
	case strings.HasPrefix(entry.stage, "issuance/"):
		var g *Grant
		var assent, consent []byte
		var output *Outpoint
		now := int64(1794600000)
		if strings.HasPrefix(entry.stage, "issuance/composed/") {
			context := obj(v, "context")
			parts := obj(v, "parts")
			g = wireGrant(context, byID[str(context, "grant")])
			assent = octets(t, str(parts, "issuer_assent_hex"))
			consent = octets(t, str(parts, "consent_event_hex"))
			output = wireOutpoint(obj(parts, "name_output"))
			now = int64(num(context, "now"))
		} else {
			inputs := obj(v, "inputs")
			context := base
			if str(inputs, "mode") == "name" {
				context = obj(byID["consent-c-20"], "context")
			}
			g = wireGrant(context, byID[str(inputs, "grant")])
			assent = octets(t, str(byID[str(inputs, "issuer_assent")], "signed_form_hex"))
			consent = octets(t, str(byID[str(inputs, "recipient_consent")], "event_hex"))
			output = wireOutpoint(obj(inputs, "name_output"))
		}
		var raw []byte
		var commitment, frame string
		raw, commitment, frame, err = prepareChecked(g, assent, consent, output, now)
		if err == nil {
			if str(v, "preparation_hex") != "" {
				equal(hex.EncodeToString(raw), str(v, "preparation_hex"), "preparation octets")
				equal(string(raw), str(v, "preparation"), "preparation text")
				equal(commitment, str(v, "commitment"), "preparation commitment")
				equal(frame, str(v, "script_hex"), "preparation frame")
			}
			err = CheckFrame(str(v, "script_hex"), frame)
		}
	default:
		t.Fatal("unhandled wire stage")
	}
	return err
}

// TestWireVectors proves every in-scope pinned wire outcome and arithmetic oracle, with a valid same-stage control beside each refusal and explicit unsupported evidence cases.
func TestWireVectors(t *testing.T) {
	_, entries, byID := loadWire(t)
	controls := map[string]string{"canonical": "canon-v-01", "integers": "int-v-01", "primitives": "prim-type-01", "assents": "assent-v-01", "identifiers": "id-02", "consent_events": "consent-c-01", "issuance": "issuance-v-01"}
	index := map[string]wireEntry{}
	for _, entry := range entries {
		index[str(entry.value, "id")] = entry
	}
	counts := map[string]int{}
	var results []map[string]string
	for _, entry := range entries {
		id := str(entry.value, "id")
		stage := strings.Split(entry.stage, "/")[0]
		counts[stage]++
		t.Run(id, func(t *testing.T) {
			control := index[controls[stage]]
			if err := runWire(t, control, byID); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			got := "ok"
			if err := runWire(t, entry, byID); err != nil {
				got = err.Error()
			}
			want := wireExpected(entry)
			if got != want {
				t.Fatalf("want %s; got %s", want, got)
			}
			results = append(results, map[string]string{"id": id, "stage": entry.stage, "actual": got})
		})
	}
	for stage, want := range map[string]int{"canonical": 53, "integers": 19, "primitives": 11, "assents": 42, "identifiers": 4, "consent_events": 35, "issuance": 43} {
		if counts[stage] != want {
			t.Fatalf("%s count: %d, want %d", stage, counts[stage], want)
		}
	}
	if path := os.Getenv("GRANTV4_WIRE_OUTPUT"); path != "" && !t.Failed() {
		raw, err := json.Marshal(results)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
