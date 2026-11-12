package facade

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const NostrPrepareSchema = "swarma-identity/nostr-profile-prepare/1"
const NostrVerifySchema = "swarma-identity/nostr-profile-verify/1"

type NostrPrepareRequest struct {
	Schema    string     `json:"schema"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt uint64     `json:"created_at"`
	Kind      uint16     `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
}

type NostrUnsignedEvent struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt uint64     `json:"created_at"`
	Kind      uint16     `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
}

type NostrSignedEvent struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt uint64     `json:"created_at"`
	Kind      uint16     `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

type NostrVerifyRequest struct {
	Schema string           `json:"schema"`
	Event  NostrSignedEvent `json:"event"`
}

type NostrPreparedProfile struct {
	Schema        string             `json:"schema"`
	CanonicalUTF8 string             `json:"canonical_utf8"`
	Event         NostrUnsignedEvent `json:"event"`
}

type NostrVerifiedProfile struct {
	Schema    string `json:"schema"`
	Valid     bool   `json:"valid"`
	ID        string `json:"id"`
	Pubkey    string `json:"pubkey"`
	CreatedAt uint64 `json:"created_at"`
	Kind      uint16 `json:"kind"`
}

func lowerHex(s string, bytes int) bool {
	return len(s) == bytes*2 && strings.Trim(s, "0123456789abcdef") == ""
}

// Encoding the signed message is separate from JSON transport encoding. The
// admitted strings use only NIP-01's seven escapes, with all other UTF-8 intact.
func writeNostrString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n':
			b.WriteString(`\n`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			b.WriteByte(s[i])
		}
	}
	b.WriteByte('"')
}

func nostrCanonical(pubkey string, createdAt uint64, kind uint16, tags [][]string, content string) (string, *Failure) {
	if !lowerHex(pubkey, 32) || createdAt > 9007199254740991 || tags == nil || len(tags) > 128 || len(content) < 2 || len(content) > 16384 || validateJSON([]byte(content)) != nil {
		return "", fail("BAD_INPUT")
	}
	if _, ok := object([]byte(content)); !ok {
		return "", fail("BAD_INPUT")
	}
	key, _ := hex.DecodeString(pubkey)
	if _, err := schnorr.ParsePubKey(key); err != nil {
		return "", fail("BAD_INPUT")
	}
	total := 0
	for _, tag := range tags {
		if len(tag) < 1 || len(tag) > 16 {
			return "", fail("BAD_INPUT")
		}
		for _, s := range tag {
			if len(s) > 1024 || !utf8.ValidString(s) {
				return "", fail("BAD_INPUT")
			}
			total += len(s)
			for _, r := range s {
				if r < 0x20 && r != '\b' && r != '\t' && r != '\n' && r != '\f' && r != '\r' {
					return "", fail("BAD_INPUT")
				}
			}
		}
	}
	if total > 8192 {
		return "", fail("BAD_INPUT")
	}
	var b strings.Builder
	b.WriteString("[0,")
	writeNostrString(&b, pubkey)
	b.WriteByte(',')
	b.WriteString(strconv.FormatUint(createdAt, 10))
	b.WriteByte(',')
	b.WriteString(strconv.FormatUint(uint64(kind), 10))
	b.WriteString(",[")
	for i, tag := range tags {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('[')
		for j, s := range tag {
			if j > 0 {
				b.WriteByte(',')
			}
			writeNostrString(&b, s)
		}
		b.WriteByte(']')
	}
	b.WriteString("],")
	writeNostrString(&b, content)
	b.WriteByte(']')
	if b.Len() > 32768 {
		return "", fail("BAD_INPUT")
	}
	if kind != 0 {
		return "", fail("UNSUPPORTED_CAPABILITY")
	}
	return b.String(), nil
}

func PrepareNostrProfile(r NostrPrepareRequest) (*NostrPreparedProfile, *Failure) {
	if r.Schema != NostrPrepareSchema {
		return nil, fail("BAD_INPUT")
	}
	canonical, f := nostrCanonical(r.Pubkey, r.CreatedAt, r.Kind, r.Tags, r.Content)
	if f != nil {
		return nil, f
	}
	id := sha256.Sum256([]byte(canonical))
	e := NostrUnsignedEvent{hex.EncodeToString(id[:]), r.Pubkey, r.CreatedAt, r.Kind, r.Tags, r.Content}
	return &NostrPreparedProfile{"swarma-identity/nostr-profile-prepared/1", canonical, e}, nil
}

func verifyNostrSignature(pubkey, digest, signature []byte) bool {
	if len(digest) != 32 {
		return false
	}
	key, err := schnorr.ParsePubKey(pubkey)
	if err != nil {
		return false
	}
	sig, err := schnorr.ParseSignature(signature)
	return err == nil && sig.Verify(digest, key)
}

func VerifyNostrProfile(r NostrVerifyRequest) (*NostrVerifiedProfile, *Failure) {
	e := r.Event
	if r.Schema != NostrVerifySchema || !lowerHex(e.ID, 32) || !lowerHex(e.Sig, 64) {
		return nil, fail("BAD_INPUT")
	}
	canonical, f := nostrCanonical(e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content)
	if f != nil {
		return nil, f
	}
	id := sha256.Sum256([]byte(canonical))
	supplied, _ := hex.DecodeString(e.ID)
	if subtle.ConstantTimeCompare(supplied, id[:]) != 1 {
		return nil, fail("EVENT_ID_MISMATCH")
	}
	key, _ := hex.DecodeString(e.Pubkey)
	sig, _ := hex.DecodeString(e.Sig)
	if !verifyNostrSignature(key, id[:], sig) {
		return nil, fail("INVALID_SIGNATURE")
	}
	return &NostrVerifiedProfile{"swarma-identity/nostr-profile-verified/1", true, e.ID, e.Pubkey, e.CreatedAt, e.Kind}, nil
}
