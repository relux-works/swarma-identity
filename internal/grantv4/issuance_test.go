package grantv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// signedEvent uses fresh test keys and an independently formatted NIP-01 preimage.
func signedEvent(t *testing.T, g *Grant, createdAt int64, name string) (Event, []byte) {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal("test key generation")
	}
	pub := hex.EncodeToString(schnorr.SerializePubKey(key.PubKey()))
	g.payload["recipient"] = object{"key": pub}
	e := Event{Pubkey: pub, CreatedAt: createdAt, Kind: 8181, Tags: [][]string{{"t", "swarma-contract-consent/1"}, {"genesis", g.Genesis()}, {"contract", g.Contract()}, {"issuer", g.Signer()}}}
	suffix := ""
	if name != "" {
		g.payload["recipient"] = object{"name": name}
		e.Tags = append(e.Tags, []string{"name", name})
		suffix = fmt.Sprintf(`,["name",%q]`, name)
	}
	preimage := fmt.Sprintf(`[0,%q,%d,8181,[["t","swarma-contract-consent/1"],["genesis",%q],["contract",%q],["issuer",%q]%s],""]`, pub, createdAt, g.Genesis(), g.Contract(), g.Signer(), suffix)
	digest := sha256.Sum256([]byte(preimage))
	e.ID = hex.EncodeToString(digest[:])
	sig, err := schnorr.Sign(key, digest[:])
	if err != nil {
		t.Fatal("test event signing")
	}
	e.Sig = hex.EncodeToString(sig.Serialize())
	// The independent fixture encoder uses the required fixed-order event struct.
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(e) != nil {
		t.Fatal("test event encoding")
	}
	return e, bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}

// TestConsentTimeBounds proves both inclusive Unix-second edges pass and zero, negative, and neighbouring upper overflows refuse as CONSENT_SHAPE before time checks.
func TestConsentTimeBounds(t *testing.T) {
	_, c := loadCorpus(t)
	for _, pair := range []struct{ good, bad int64 }{{1, 0}, {2, -1}, {253402300799, 253402300800}, {253402300798, 253402300801}} {
		t.Run(fmt.Sprintf("%d", pair.bad), func(t *testing.T) {
			g := validGrants(t, c)["grant-v-01"]
			_, raw := signedEvent(t, g, pair.good, "")
			if _, err := checkConsent(raw, g, 253402300801); err != nil {
				t.Fatalf("positive event: %v", err)
			}
			if e, err := ConsentTemplate(g, pair.good); err != nil || e.CreatedAt != pair.good {
				t.Fatalf("positive template: %v", err)
			}
			_, raw = signedEvent(t, g, pair.bad, "")
			if _, err := checkConsent(raw, g, 253402300801); err == nil || err.Error() != "CONSENT_SHAPE" {
				t.Fatalf("event time bound: want CONSENT_SHAPE; got %v", err)
			}
			if e, err := ConsentTemplate(g, pair.bad); err == nil || err.Error() != "CONSENT_SHAPE" || !reflect.DeepEqual(e, Event{}) {
				t.Fatalf("template time bound: want CONSENT_SHAPE; got %v", err)
			}
		})
	}
}

// TestConsentLiteralHTML proves literal ASCII names reach the explicit evidence refusal and escaped HTML spellings refuse shape, beside valid by-key events.
func TestConsentLiteralHTML(t *testing.T) {
	_, c := loadCorpus(t)
	for _, char := range []string{"&", "<", ">"} {
		t.Run(char, func(t *testing.T) {
			g := validGrants(t, c)["grant-v-01"]
			_, raw := signedEvent(t, g, 1700000000, "")
			if _, err := checkConsent(raw, g, 1700000000); err != nil {
				t.Fatalf("positive key event: %v", err)
			}
			e, raw := signedEvent(t, g, 1700000000, "id/a"+char+"b")
			if eventID(e) != e.ID {
				t.Fatal("literal event id differs from independent preimage")
			}
			if _, err := checkConsent(raw, g, 1700000000); err == nil || err.Error() != "UNSUPPORTED_CAPABILITY" {
				t.Fatalf("literal name: want UNSUPPORTED_CAPABILITY; got %v", err)
			}
			escaped := bytes.Replace(raw, []byte(char), []byte(fmt.Sprintf(`\u%04x`, char[0])), 1)
			if _, err := checkConsent(escaped, g, 1700000000); err == nil || err.Error() != "CONSENT_SHAPE" {
				t.Fatalf("escaped name: want CONSENT_SHAPE; got %v", err)
			}
		})
	}
}

// TestConsentTagCharacters proves quoted/backslashed ASCII reaches the evidence gate while escaped controls and non-ASCII names refuse CONSENT_SHAPE beside valid by-key events.
func TestConsentTagCharacters(t *testing.T) {
	_, c := loadCorpus(t)
	for _, name := range []string{"id/a\nb", "id/a\u2028b", "id/a\u007fb"} {
		g := validGrants(t, c)["grant-v-01"]
		_, raw := signedEvent(t, g, 1700000000, "")
		if _, err := checkConsent(raw, g, 1700000000); err != nil {
			t.Fatalf("positive key event: %v", err)
		}
		_, raw = signedEvent(t, g, 1700000000, `id/a"\b`)
		if _, err := checkConsent(raw, g, 1700000000); err == nil || err.Error() != "UNSUPPORTED_CAPABILITY" {
			t.Fatalf("ASCII name: want UNSUPPORTED_CAPABILITY; got %v", err)
		}
		_, raw = signedEvent(t, g, 1700000000, name)
		if _, err := checkConsent(raw, g, 1700000000); err == nil || err.Error() != "CONSENT_SHAPE" {
			t.Fatalf("non-printable name: want CONSENT_SHAPE; got %v", err)
		}
	}
}

// TestAttachSignatureForm proves malformed external signatures have one exact form refusal, independent of JSON escaping or size, beside verified attachments.
func TestAttachSignatureForm(t *testing.T) {
	_, c := loadCorpus(t)
	g := validGrants(t, c)["grant-v-01"]
	for _, bad := range []string{"", strings.Repeat("<", 128), strings.Repeat("0", 127), strings.Repeat("A", 128), strings.Repeat("\n", 128), strings.Repeat("\"", 128), strings.Repeat("0", 65536)} {
		d, err := Draft(g.Payload(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Attach(d, g.Signature(), nil); err != nil {
			t.Fatalf("positive attachment: %v", err)
		}
		if got, err := Attach(d, bad, nil); err == nil || err.Error() != "WIRE_SIGNATURE_FORM" || got != nil {
			t.Fatalf("signature form: want WIRE_SIGNATURE_FORM; got %v", err)
		}
	}
}

// TestReadRequiresSignedParent proves child verification cannot use an unsigned Draft as its authenticated delegation source, while drafting remains available.
func TestReadRequiresSignedParent(t *testing.T) {
	_, c := loadCorpus(t)
	grants := validGrants(t, c)
	child, parent := grants["grant-v-05"], grants["grant-v-03"]
	if _, err := Read(child.Signed(), parent, nil); err != nil {
		t.Fatalf("positive parent: %v", err)
	}
	draft, err := Draft(parent.Payload(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Draft(child.Payload(), draft); err != nil {
		t.Fatalf("unsigned child drafting: %v", err)
	}
	if got, err := Read(child.Signed(), draft, nil); err == nil || err.Error() != "WIRE_ID" || got != nil {
		t.Fatalf("unsigned parent: want WIRE_ID; got %v", err)
	}
}
