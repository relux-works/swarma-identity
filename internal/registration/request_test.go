package registration

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type wireVector struct {
	RequestID      string `json:"request_id"`
	SittingID      string `json:"sitting_id"`
	ExpiresAt      uint64 `json:"expires_at"`
	RequestSHA256  string `json:"request_sha256"`
	ReviewFrameHex string `json:"review_frame_hex"`
	Result         string `json:"result_format_only"`
}

func wireFixture(t *testing.T, mode string) (*Planner, []*Plan, map[string]wireVector) {
	t.Helper()
	p, plans, _ := signedFixture(t, mode)
	b, e := os.ReadFile(filepath.Join("testdata", "core28", mode, "wire-vectors.json"))
	if e != nil {
		t.Fatal(e)
	}
	var vectors map[string]wireVector
	if e := json.Unmarshal(b, &vectors); e != nil {
		t.Fatal(e)
	}
	return p, plans, vectors
}

func requestFor(t *testing.T, p *Planner, plan *Plan, tx PreparedTransaction, v wireVector) *SigningRequest {
	t.Helper()
	r, e := p.PrepareRequest(plan, tx.Slot, tx.PSBT, RequestIDs{v.RequestID, v.SittingID, v.ExpiresAt}, p.profile.Policy.CreatedAt+60)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func ackFor(result []byte) []byte {
	return []byte(fmt.Sprintf("{\"schema\":\"keyvault-namecoin-psbt-ack/2\",\"status\":\"SIGNED\",\"result_sha256\":\"%s\"}\n", digest(result)))
}

// All eight frozen request byte hashes and complete review frames match. The
// format-only receipts contain real Core signatures but synthetic journal data;
// successful checks here establish public bindings, never custody authenticity.
func TestWireV2Parity(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		p, plans, vectors := wireFixture(t, mode)
		for _, plan := range plans {
			for _, tx := range plan.Transactions() {
				v := vectors[tx.Slot]
				r := requestFor(t, p, plan, tx, v)
				if digest(r.Bytes()) != v.RequestSHA256 || hex.EncodeToString(r.ReviewFrame()) != v.ReviewFrameHex {
					t.Fatalf("%s/%s wire mismatch", mode, tx.Slot)
				}
				result := []byte(v.Result)
				checked, e := p.CheckResult(r, result, ackFor(result), 0)
				if e != nil {
					t.Fatalf("%s/%s result: %v", mode, tx.Slot, e)
				}
				if checked.ResultSHA256 != digest(result) || checked.Transaction.TxID != tx.TxID || checked.ReportedJournalSequence == 0 {
					t.Fatal("public result mismatch")
				}
				copy := r.Bytes()
				copy[0] ^= 1
				frame := r.ReviewFrame()
				frame[0] ^= 1
				if digest(r.Bytes()) != v.RequestSHA256 || hex.EncodeToString(r.ReviewFrame()) != v.ReviewFrameHex {
					t.Fatal("request aliases caller")
				}
			}
		}
	}
}

// Approval IDs and the 600-second window are checked against a supplied trusted
// clock; deadline and identifier failures return no partial request.
func TestRequestRefusals(t *testing.T) {
	p, plans, vectors := wireFixture(t, "all-four-before-release")
	plan, tx := plans[0], plans[0].Transactions()[0]
	v := vectors["A"]
	now := p.profile.Policy.CreatedAt + 60
	good := RequestIDs{v.RequestID, v.SittingID, now + 600}
	if _, e := p.PrepareRequest(plan, "A", tx.PSBT, good, now); e != nil {
		t.Fatal(e)
	}
	for _, ids := range []RequestIDs{
		{"00", v.SittingID, now + 1}, {v.RequestID, "00", now + 1},
		{strings.ToUpper(v.RequestID), v.SittingID, now + 1},
		{v.RequestID, v.SittingID, now}, {v.RequestID, v.SittingID, now - 1}, {v.RequestID, v.SittingID, now + 601},
	} {
		r, e := p.PrepareRequest(plan, "A", tx.PSBT, ids, now)
		if !errors.Is(e, ErrInput) || r != nil {
			t.Fatalf("request=%v error=%v", r, e)
		}
	}
	for _, slot := range []string{"", "C", "AA", "E"} {
		r, e := p.PrepareRequest(plan, slot, tx.PSBT, good, now)
		if !errors.Is(e, ErrPSBT) || r != nil {
			t.Fatal("accepted wrong phase/slot")
		}
	}
}

func editResult(t *testing.T, b []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if e := json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	edit(m)
	out, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	return out
}

// Each receipt mutation has a freshly matching ack, so rejection must follow
// the receipt/request/PSBT binding rather than merely detecting a stale hash.
func TestResultBindings(t *testing.T) {
	p, plans, vectors := wireFixture(t, "two-stage")
	plan, tx := plans[1], plans[1].Transactions()[0]
	v := vectors["C"]
	r := requestFor(t, p, plan, tx, v)
	good := []byte(v.Result)
	for _, field := range []string{"schema", "status", "request_id", "sitting_id", "slot", "plan_sha256", "reservation_plan_sha256", "review_sha256", "network", "group", "account", "account_pin_sha256", "unsigned_txid", "signed_psbt_sha256", "journal_head_sha256"} {
		t.Run(field, func(t *testing.T) {
			if _, e := p.CheckResult(r, good, ackFor(good), 0); e != nil {
				t.Fatal(e)
			}
			bad := editResult(t, good, func(m map[string]any) { m["receipt"].(map[string]any)[field] = "invalid" })
			if x, e := p.CheckResult(r, bad, ackFor(bad), 0); !errors.Is(e, ErrResult) || x != nil {
				t.Fatalf("result=%v error=%v", x, e)
			}
		})
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"extra-root", func(m map[string]any) { m["extra"] = true }},
		{"result-schema", func(m map[string]any) { m["schema"] = "keyvault-namecoin-psbt-result/1" }},
		{"extra-receipt", func(m map[string]any) { m["receipt"].(map[string]any)["extra"] = true }},
		{"zero-sequence", func(m map[string]any) { m["receipt"].(map[string]any)["journal_sequence"] = 0 }},
		{"missing-signature", func(m map[string]any) {
			s := m["receipt"].(map[string]any)
			s["input_signatures"] = s["input_signatures"].([]any)[:1]
		}},
		{"signature-order", func(m map[string]any) {
			s := m["receipt"].(map[string]any)["input_signatures"].([]any)
			s[0], s[1] = s[1], s[0]
		}},
		{"duplicate-index", func(m map[string]any) {
			s := m["receipt"].(map[string]any)["input_signatures"].([]any)
			s[1].(map[string]any)["index"] = 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := editResult(t, good, tc.edit)
			if x, e := p.CheckResult(r, bad, ackFor(bad), 0); !errors.Is(e, ErrResult) || x != nil {
				t.Fatalf("result=%v error=%v", x, e)
			}
		})
	}
	for _, field := range []string{"index", "pubkey", "algorithm", "encoding", "sighash", "signature", "extra"} {
		bad := editResult(t, good, func(m map[string]any) {
			m["receipt"].(map[string]any)["input_signatures"].([]any)[0].(map[string]any)[field] = "invalid"
		})
		if x, e := p.CheckResult(r, bad, ackFor(bad), 0); !errors.Is(e, ErrResult) || x != nil {
			t.Fatalf("%s: result=%v error=%v", field, x, e)
		}
	}
	for _, pair := range [][2][]byte{{[]byte(`"schema":`), []byte(`"schema":"duplicate","schema":`)}, {[]byte(`"status":`), []byte(`"status":"SIGNED","status":`)}, {[]byte(`"index":`), []byte(`"index":0,"index":`)}} {
		bad := bytes.Replace(good, pair[0], pair[1], 1)
		if x, e := p.CheckResult(r, bad, ackFor(bad), 0); !errors.Is(e, ErrResult) || x != nil {
			t.Fatalf("duplicate: result=%v error=%v", x, e)
		}
	}
}

// Exact stdout binds the entire original result file, including insignificant
// JSON whitespace. Wrong hashes, extra fields/lines, truncation and nonzero
// exits never return a public success. Re-encoding cannot reuse the old ack.
func TestResultAcknowledgement(t *testing.T) {
	p, plans, vectors := wireFixture(t, "two-stage")
	plan, tx := plans[0], plans[0].Transactions()[0]
	v := vectors["A"]
	r := requestFor(t, p, plan, tx, v)
	result := []byte(v.Result)
	ack := ackFor(result)
	for _, bad := range [][]byte{
		bytes.Replace(ack, []byte(digest(result)), []byte(strings.Repeat("00", 32)), 1),
		bytes.Replace(ack, []byte("}\n"), []byte(",\"extra\":true}\n"), 1),
		append(append([]byte{}, ack...), '\n'), ack[:len(ack)-1], ack[:len(ack)-7], nil,
	} {
		if x, e := p.CheckResult(r, result, bad, 0); !errors.Is(e, ErrResult) || x != nil {
			t.Fatalf("result=%v error=%v", x, e)
		}
	}
	for _, exit := range []int{1, 2, 3, -1} {
		if x, e := p.CheckResult(r, result, ack, exit); !errors.Is(e, ErrResult) || x != nil {
			t.Fatal("accepted nonzero signer exit")
		}
	}
	reencoded := editResult(t, result, func(map[string]any) {})
	if bytes.Equal(reencoded, result) {
		t.Fatal("fixture order failed to change")
	}
	if x, e := p.CheckResult(r, reencoded, ack, 0); !errors.Is(e, ErrResult) || x != nil {
		t.Fatal("ack failed to bind original file bytes")
	}
	if _, e := p.CheckResult(r, reencoded, ackFor(reencoded), 0); e != nil {
		t.Fatal(e)
	}
}
