package facade

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/relux-works/swarma-identity/internal/keychain/keychainfake"
)

// TestV4DisplayBounds proves the exact 8192-leaf display boundary is usable, and one extra leaf refuses before display, confirmation or private-key use.
func TestV4DisplayBounds(t *testing.T) {
	request := func(count int) KeychainV4Request {
		g, _ := v4Grant(t, "grant-v-01")
		var p map[string]any
		d := json.NewDecoder(bytes.NewReader(g.Payload()))
		d.UseNumber()
		if d.Decode(&p) != nil {
			t.Fatal("payload")
		}
		actions := make([]string, 0, count)
		for a := byte(0x21); a <= 0x7e && len(actions) < count; a++ {
			for b := byte(0x21); b <= 0x7e && len(actions) < count; b++ {
				actions = append(actions, string([]byte{a, b}))
			}
		}
		if len(actions) != count {
			t.Fatal("action count")
		}
		p["actions"] = actions
		raw, ok := compactJSON(p)
		if !ok {
			t.Fatal("canonical payload")
		}
		r := v4KeyRequest(t, "grant-v-01")
		r.PayloadHex = hex.EncodeToString(raw)
		return r
	}
	h := newKCWithStore(t, confirmWord, keychainfake.New(), v4PublicTestScalar)
	e, exit := v4KC(t, h, "sign-v4", request(8164))
	mustOK(t, e, exit)
	if !h.keyRead || !strings.Contains(h.preKey, "committed fields (8192):") {
		t.Fatal("exact positive bound not exercised")
	}
	h = newKCWithStore(t, confirmWord, keychainfake.New(), v4PublicTestScalar)
	e, exit = v4KC(t, h, "sign-v4", request(8165))
	if exit != 3 || e.Error == nil || e.Error.Code != "SCOPE_TEXT_SIZE" || e.Result != nil || h.keyRead || h.term.shown.Len() != 0 {
		t.Fatal("display limit did not refuse before key use")
	}
}

// TestV4StatedValueRefusals proves stated values are bounded and exact-name/duplicate checked, with valid unverified values beside every refusal and no private-key use.
func TestV4StatedValueRefusals(t *testing.T) {
	for _, c := range []struct{ value, code string }{
		{strings.Repeat(" ", 521), "BAD_INPUT"},
		{strings.Replace(landlordValue(v4IssuerKey), `"swarma"`, `"Swarma"`, 1), "STATED_LANDLORD_VALUE_KEY_MISMATCH"},
		{strings.Replace(landlordValue(v4IssuerKey), `"grant":`, `"grant":"`+v4IssuerKey+`","grant":`, 1), "BAD_INPUT"},
	} {
		r := v4KeyRequest(t, "grant-v-01")
		positive := newKCWithStore(t, confirmWord, keychainfake.New(), v4PublicTestScalar)
		e, exit := v4KC(t, positive, "review-v4", r)
		mustOK(t, e, exit)
		if !strings.Contains(positive.term.shown.String(), "NOT VERIFIED BY THIS SIGNER") {
			t.Fatal("stated value overstated")
		}
		h := newKCWithStore(t, confirmWord, keychainfake.New(), v4PublicTestScalar)
		r.LandlordValueHex = hex.EncodeToString([]byte(c.value))
		e, exit = v4KC(t, h, "review-v4", r)
		if e.OK || e.Result != nil || e.Error == nil || e.Error.Code != c.code || (exit != 2 && exit != 3) || h.keyRead || h.term.shown.Len() != 0 {
			t.Fatal("invalid stated value reached display or key")
		}
	}
}
