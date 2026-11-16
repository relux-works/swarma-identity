package facade

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"syscall"

	"github.com/relux-works/swarma-identity/internal/grantv4"
)

const GrantV4RequestSchema = "swarma-identity/grant-v4/1"

// GrantV4Request is public file exchange only. It contains complete canonical
// documents, never a private key or a digest to be signed. Commands explicitly
// select v4; no v3 command or decoder changes its interpretation.
type GrantV4Request struct {
	members    map[string]json.RawMessage `json:"-"`
	Schema     string                     `json:"schema"`
	PayloadHex string                     `json:"payload_hex,omitempty"`
	ParentHex  string                     `json:"parent_hex,omitempty"`
	Signature  string                     `json:"signature,omitempty"`
	Calendar   *GrantV4Calendar           `json:"calendar,omitempty"`
	CreatedAt  int64                      `json:"created_at,omitempty"`
	SignedHex  string                     `json:"signed_hex,omitempty"`
	AssentHex  string                     `json:"assent_hex,omitempty"`
	ConsentHex string                     `json:"consent_hex,omitempty"`
	NameOutput *grantv4.Outpoint          `json:"name_output,omitempty"`
	Now        int64                      `json:"now,omitempty"`
	FrameHex   string                     `json:"frame_hex,omitempty"`
}
type GrantV4Calendar struct {
	CurrentHeight      uint64 `json:"current_height"`
	StartAfterSeconds  uint64 `json:"start_after_seconds"`
	EndAfterSeconds    uint64 `json:"end_after_seconds"`
	TargetBlockSeconds uint64 `json:"target_block_seconds"`
}
type GrantV4Draft struct {
	PayloadHex       string `json:"payload_hex"`
	GrantID          string `json:"grant_id"`
	TypedDigest      string `json:"typed_digest"`
	Signer           string `json:"signer"`
	SealScript       string `json:"seal_script"`
	SignedHex        string `json:"signed_hex,omitempty"`
	ContentAddress   string `json:"content_address,omitempty"`
	AdmissionChecked bool   `json:"admission_checked"`
}

func resultV4(g *grantv4.Grant) *GrantV4Draft {
	r := &GrantV4Draft{PayloadHex: hex.EncodeToString(g.Payload()), GrantID: g.ID(), TypedDigest: g.Digest(), Signer: g.Signer(), SealScript: g.SealScript()}
	if len(g.Signed()) > 0 {
		r.SignedHex = hex.EncodeToString(g.Signed())
		r.ContentAddress = g.ContentAddress()
	}
	return r
}
func decodeV4(s string, optional bool) ([]byte, *Failure) {
	if s == "" && optional {
		return nil, nil
	}
	b, e := hex.DecodeString(s)
	if e != nil || len(b) == 0 || len(b) > 2*grantv4.MaxBytes || hex.EncodeToString(b) != s {
		return nil, fail("BAD_INPUT")
	}
	return b, nil
}
func draftV4(r GrantV4Request) (*grantv4.Grant, *grantv4.Grant, *Failure) {
	raw, f := decodeV4(r.PayloadHex, false)
	if f != nil {
		return nil, nil, f
	}
	parentRaw, f := decodeV4(r.ParentHex, true)
	if f != nil {
		return nil, nil, f
	}
	var parent *grantv4.Grant
	if parentRaw != nil {
		var e error
		parent, e = grantv4.Read(parentRaw, nil, nil)
		if e != nil {
			return nil, nil, rentalRefusal(e)
		}
	}
	// Document and member refusals precede the optional local conversion.
	if _, e := grantv4.Draft(raw, parent); e != nil {
		return nil, nil, rentalRefusal(e)
	}
	if r.Calendar != nil {
		c := r.Calendar
		before, after, e := grantv4.Heights(c.CurrentHeight, c.StartAfterSeconds, c.EndAfterSeconds, c.TargetBlockSeconds)
		if e != nil {
			return nil, nil, rentalRefusal(e)
		}
		raw, e = grantv4.WithHeights(raw, parent, before, after)
		if e != nil {
			return nil, nil, rentalRefusal(e)
		}
	}
	g, e := grantv4.Draft(raw, parent)
	if e != nil {
		return nil, nil, rentalRefusal(e)
	}
	return g, parent, nil
}

// inputV4 has its own exchange-file bound: hex of two maximum-size documents
// does not fit the old 64 KiB v3 request bound. Every inner document retains
// its own smaller protocol bound. Files remain regular, nonblocking and closed.
func inputV4(path string, dst any) *Failure {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if e != nil {
		return fail("BAD_INPUT")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > 524288 {
		return fail("BAD_INPUT")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 524289))
	if e != nil || len(raw) > 524288 || validateJSON(raw) != nil {
		return fail("BAD_INPUT")
	}
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Pointer || v.IsNil() || closedObject(raw, v.Elem().Type()) != nil || json.Unmarshal(raw, dst) != nil {
		return fail("BAD_INPUT")
	}
	if r, ok := dst.(*GrantV4Request); ok {
		if json.Unmarshal(raw, &r.members) != nil {
			return fail("BAD_INPUT")
		}
	}
	return nil
}
func executeGrantV4(command string, args []string) (string, any, *Failure) {
	o, f := keychainOptions(args, "request")
	if f != nil {
		return "", nil, f
	}
	var r GrantV4Request
	if f = inputV4(o["request"], &r); f != nil {
		return "", nil, f
	}
	if r.Schema != GrantV4RequestSchema {
		return "", nil, fail("BAD_INPUT")
	}
	// Stage membership is about presence, even for empty strings or zero.
	allowed := " schema parent_hex "
	switch command {
	case "grant draft-v4":
		allowed += "payload_hex calendar "
	case "grant sign-v4":
		allowed += "payload_hex calendar signature "
	case "grant consent-v4":
		allowed += "payload_hex calendar created_at "
		if len(r.members["created_at"]) == 0 || string(r.members["created_at"]) == "null" {
			return "", nil, fail("BAD_INPUT")
		}
	case "grant anchor-v4":
		allowed += "signed_hex assent_hex consent_hex name_output now frame_hex "
		if len(r.members["now"]) == 0 || string(r.members["now"]) == "null" {
			return "", nil, fail("BAD_INPUT")
		}
	default:
		return "", nil, fail("BAD_INPUT")
	}
	for name := range r.members {
		if !strings.Contains(allowed, " "+name+" ") {
			return "", nil, fail("BAD_INPUT")
		}
	}
	switch command {
	case "grant draft-v4", "grant sign-v4", "grant consent-v4":
		if r.SignedHex != "" || r.AssentHex != "" || r.ConsentHex != "" || r.NameOutput != nil || r.Now != 0 || r.FrameHex != "" || (command != "grant sign-v4" && r.Signature != "") || (command != "grant consent-v4" && r.CreatedAt != 0) {
			return "", nil, fail("BAD_INPUT")
		}
		g, parent, f := draftV4(r)
		if f != nil {
			return "", nil, f
		}
		switch command {
		case "grant draft-v4":
			return "", resultV4(g), nil
		case "grant sign-v4":
			signed, e := grantv4.Attach(g, r.Signature, parent)
			if e != nil {
				return "", nil, rentalRefusal(e)
			}
			return "", resultV4(signed), nil
		case "grant consent-v4":
			event, e := grantv4.ConsentTemplate(g, r.CreatedAt)
			if e != nil {
				return "", nil, rentalRefusal(e)
			}
			assent, digest, e := grantv4.AssentPayload(g)
			if e != nil {
				return "", nil, rentalRefusal(e)
			}
			return "", struct {
				Event        grantv4.Event `json:"event_template"`
				AssentHex    string        `json:"assent_payload_hex"`
				AssentDigest string        `json:"assent_digest"`
			}{event, hex.EncodeToString(assent), digest}, nil
		}
	case "grant anchor-v4":
		if r.PayloadHex != "" || r.Signature != "" || r.Calendar != nil || r.CreatedAt != 0 {
			return "", nil, fail("BAD_INPUT")
		}
		parts := make([][]byte, 4)
		for i, s := range []string{r.SignedHex, r.AssentHex, r.ConsentHex, r.ParentHex} {
			parts[i], f = decodeV4(s, i == 3)
			if f != nil {
				return "", nil, f
			}
		}
		raw, commitment, frame, e := grantv4.Preparation(parts[0], parts[1], parts[2], parts[3], r.NameOutput, r.Now)
		if e != nil {
			return "", nil, rentalRefusal(e)
		}
		if r.FrameHex != "" {
			if e = grantv4.CheckFrame(r.FrameHex, frame); e != nil {
				return "", nil, rentalRefusal(e)
			}
		}
		return "", struct {
			PreparationHex   string `json:"preparation_hex"`
			Commitment       string `json:"commitment"`
			FrameHex         string `json:"frame_hex"`
			DryRun           bool   `json:"dry_run"`
			AdmissionChecked bool   `json:"admission_checked"`
		}{hex.EncodeToString(raw), commitment, frame, true, false}, nil
	}
	return "", nil, fail("BAD_INPUT")
}

// signedAssentV4 rebuilds and verifies the device result before releasing it.
func signedAssentV4(g *grantv4.Grant, signature string) []byte {
	raw, _, e := grantv4.AssentPayload(g)
	if e != nil {
		return nil
	}
	q, _ := json.Marshal(signature)
	out := append([]byte(`{"payload":`), raw...)
	out = append(out, []byte(`,"signature":`)...)
	out = append(out, q...)
	return append(out, '}')
}
