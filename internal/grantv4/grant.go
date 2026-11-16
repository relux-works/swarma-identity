package grantv4

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
)

// Grant holds checked, private copies. Callers cannot change the payload
// between validation, display and signature verification.
type Grant struct {
	payload   object
	raw       []byte
	signed    []byte
	signature string
	signer    string
}

func (g *Grant) Payload() []byte        { return bytes.Clone(g.raw) }
func (g *Grant) Signed() []byte         { return bytes.Clone(g.signed) }
func (g *Grant) ID() string             { return hash(g.raw) }
func (g *Grant) Digest() string         { return typed(Type, g.raw) }
func (g *Grant) ContentAddress() string { return hash(g.signed) }
func (g *Grant) Signature() string      { return g.signature }
func (g *Grant) Signer() string         { return g.signer }
func (g *Grant) Child() bool            { _, ok := g.payload["parent"]; return ok }
func (g *Grant) Genesis() string        { return str(g.payload, "genesis") }
func (g *Grant) Contract() string       { return str(g.payload, "contract") }
func (g *Grant) Recipient() []byte      { return encode(g.payload["recipient"]) }
func (g *Grant) Issuer() []byte {
	if g.Child() {
		return nil
	}
	return encode(g.payload["issuer"])
}
func (g *Grant) SealScript() string {
	b, _ := hex.DecodeString(str(obj(g.payload, "seal"), "key"))
	return "0014" + hex.EncodeToString(btcutil.Hash160(b))
}

func checkedPayload(v any) object {
	m, ok := v.(object)
	if !ok || str(m, "type") != Type {
		reject("WIRE_TYPE")
	}
	checkSchema(m, payloadSchema)
	return m
}
func place(g object, parent *Grant) string {
	if _, child := g["parent"]; child {
		if parent == nil || str(g, "parent") != parent.ID() {
			reject("WIRE_ID")
		}
		if parent.Child() {
			reject("CHAIN_DEPTH")
		}
		d := obj(parent.payload, "delegate")
		if d == nil {
			reject("NOT_DELEGABLE")
		}
		return str(d, "key")
	}
	return str(obj(g, "issuer"), "grant_key")
}

// Read applies all nine steps, including signature and reference precedence.
// A child's parent must be a signed result of Read, not an unsigned Draft.
// Proposal-only script and stop-placement restrictions are deliberately not
// judged; the four undetermined vectors read as well-formed documents.
func Read(raw []byte, parent *Grant, reference *string) (g *Grant, err error) {
	defer func() {
		if err != nil {
			g = nil
		}
	}()
	defer guard(&err)
	doc := parseDocument(raw, MaxBytes).(object)
	if len(doc) != 2 {
		reject("WIRE_MEMBER")
	}
	if _, ok := doc["payload"]; !ok {
		reject("WIRE_MEMBER")
	}
	if _, ok := doc["signature"]; !ok {
		reject("WIRE_MEMBER")
	}
	sig, ok := doc["signature"].(string)
	p := checkedPayload(doc["payload"])
	if !ok || !isHex(sig, 128) {
		reject("WIRE_SIGNATURE_FORM")
	}
	g = &Grant{payload: p, raw: encode(p), signed: bytes.Clone(raw), signature: sig}
	if g.Child() && parent != nil && len(parent.signed) == 0 {
		reject("WIRE_ID")
	}
	g.signer = place(p, parent)
	code := "WIRE_SIGNATURE"
	if g.Child() {
		code = "CHILD_SIGNER"
	}
	if !Verify(g.signer, g.Digest(), sig) {
		reject(code)
	}
	if reference != nil && *reference != g.ID() {
		reject("WIRE_ID")
	}
	rules(p)
	return g, nil
}

// Draft accepts canonical payload members, reserves the full signed
// envelope overhead, and applies every non-signature rule before returning
// anything. It never repairs noncanonical input or accepts a supplied digest.
// Payloads spliced into more envelope members always refuse; the exact code
// depends on the resulting envelope defect, not a payload-only pipeline.
func Draft(payload []byte, parent *Grant) (g *Grant, err error) {
	defer func() {
		if err != nil {
			g = nil
		}
	}()
	defer guard(&err)
	// Read the eventual envelope so nesting and byte bounds are identical to
	// the signed-object pipeline, including the exact 65536-byte boundary.
	envelope := append([]byte(`{"payload":`), payload...)
	envelope = append(envelope, []byte(`,"signature":"`+string(bytes.Repeat([]byte{'0'}, 128))+`"}`)...)
	doc := parseDocument(envelope, MaxBytes).(object)
	if len(doc) != 2 || doc["payload"] == nil || doc["signature"] == nil {
		reject("WIRE_MEMBER")
	}
	p := checkedPayload(doc["payload"])
	signer := place(p, parent)
	rules(p)
	return &Grant{payload: p, raw: encode(p), signer: signer}, nil
}

// Attach verifies a device signature against exactly the drafted bytes.
func Attach(g *Grant, signature string, parent *Grant) (*Grant, error) {
	if !isHex(signature, 128) {
		return nil, Refusal("WIRE_SIGNATURE_FORM")
	}
	raw := append([]byte(`{"payload":`), g.raw...)
	q, _ := json.Marshal(signature)
	raw = append(raw, []byte(`,"signature":`)...)
	raw = append(raw, q...)
	raw = append(raw, '}')
	return Read(raw, parent, nil)
}
func Verify(key, digest, signature string) bool {
	if !isHex(key, 64) || !isHex(digest, 64) || !isHex(signature, 128) {
		return false
	}
	k, _ := hex.DecodeString(key)
	d, _ := hex.DecodeString(digest)
	s, _ := hex.DecodeString(signature)
	pub, e := schnorr.ParsePubKey(k)
	if e != nil {
		return false
	}
	sig, e := schnorr.ParseSignature(s)
	return e == nil && sig.Verify(d, pub)
}
func ascending(a []any, member string) bool {
	last := ""
	for i, v := range a {
		s, _ := v.(string)
		if member != "" {
			s = str(v.(object), member)
		}
		if i > 0 && last >= s {
			return false
		}
		last = s
	}
	return true
}
func limitKey(m object) string {
	n := object{}
	for k, v := range m {
		if k != "amount" {
			n[k] = v
		}
	}
	return string(encode(n))
}
func distinctLimits(a []any) bool {
	seen := map[string]bool{}
	for _, v := range a {
		k := limitKey(v.(object))
		if seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}

type run struct {
	tx          string
	first, last uint64
}

func (a run) meets(b run) bool { return a.tx == b.tx && a.first <= b.last && b.first <= a.last }
func collides(a run, others []run) bool {
	for _, b := range others {
		if a.meets(b) {
			return true
		}
	}
	return false
}
func rules(g object) {
	if num(g, "not_before_height") >= num(g, "not_after_height") || !ascending(arr(g, "actions"), "") || !distinctLimits(arr(g, "limits")) {
		reject("GRANT_SHAPE")
	}
	d := obj(g, "delegate")
	if d == nil {
		return
	}
	bad := func() { reject("GRANT_DELEGATE") }
	if !ascending(arr(d, "actions"), "") || !distinctLimits(arr(d, "pools")) || !ascending(arr(d, "notaries"), "name") {
		bad()
	}
	notaries := map[string]bool{}
	for _, v := range arr(d, "notaries") {
		notaries[str(v.(object), "name")] = true
	}
	var coins, stops []run
	sums := map[string]*big.Int{}
	for _, v := range arr(d, "groups") {
		group := v.(object)
		t := obj(group, "template")
		r := obj(t, "recipient")
		if !distinctLimits(arr(t, "limits")) {
			bad()
		}
		landlords := arr(r, "class")
		names := map[string]bool{}
		for _, v := range landlords {
			n := str(v.(object), "name")
			if names[n] {
				bad()
			}
			names[n] = true
		}
		_, certified := t["certifier"]
		if certified {
			if !notaries[str(t, "certifier")] {
				bad()
			}
		} else {
			if _, ok := r["key"]; ok {
				bad()
			}
			if landlords != nil {
				if len(landlords) != 1 {
					bad()
				}
				l := landlords[0].(object)
				issuer := obj(g, "issuer")
				for _, k := range []string{"name", "owner", "registration"} {
					if !bytes.Equal(encode(l[k]), encode(issuer[k])) {
						bad()
					}
				}
			}
		}
		rows := uint64(0)
		for _, v := range arr(group, "ranges") {
			r := v.(object)
			count := num(r, "count")
			rows += count
			first := num(r, "first")
			last := first + count - 1
			if last > 4294967295 {
				bad()
			}
			coins = append(coins, run{str(r, "txid"), first, last})
			s := obj(r, "stop")
			if (s != nil) != certified {
				bad()
			}
			if s != nil {
				first = num(s, "first")
				last = first + count - 1
				if last > 4294967295 {
					bad()
				}
				stops = append(stops, run{str(s, "txid"), first, last})
			}
		}
		for _, v := range arr(t, "limits") {
			l := v.(object)
			k := limitKey(l)
			amount, _ := new(big.Int).SetString(str(l, "amount"), 10)
			product := new(big.Int).Mul(amount, new(big.Int).SetUint64(rows))
			if sums[k] == nil {
				sums[k] = new(big.Int)
			}
			sums[k].Add(sums[k], product)
		}
	}
	pools := arr(d, "pools")
	if len(pools) != len(sums) {
		bad()
	}
	for _, v := range pools {
		l := v.(object)
		total := sums[limitKey(l)]
		amount, _ := new(big.Int).SetString(str(l, "amount"), 10)
		if total == nil || total.Cmp(amount) > 0 {
			bad()
		}
	}
	s := obj(obj(g, "seal"), "outpoint")
	seal := run{str(s, "txid"), num(s, "vout"), num(s, "vout")}
	for i, a := range coins {
		if a.meets(seal) || collides(a, coins[:i]) {
			bad()
		}
	}
	for i, a := range stops {
		if collides(a, stops[:i]) {
			bad()
		}
	}
}

// Heights converts an explicitly supplied calendar interval (seconds) to a
// conservative height window using a positive target block interval. It
// rounds the start up and the end down; it is an estimate, not a clock rule.
func Heights(current, startSeconds, endSeconds, blockSeconds uint64) (before, after uint64, err error) {
	if current > MaxNumber || blockSeconds == 0 || startSeconds >= endSeconds {
		return 0, 0, Refusal("GRANT_SHAPE")
	}
	start := startSeconds / blockSeconds
	if startSeconds%blockSeconds != 0 {
		start++
	}
	end := endSeconds / blockSeconds
	if start > MaxNumber-current || end > MaxNumber-current || start >= end {
		return 0, 0, Refusal("GRANT_SHAPE")
	}
	return current + start, current + end, nil
}

// WithHeights is a drafting convenience only. The input is still validated
// first, and no clock member is introduced into the payload.
func WithHeights(payload []byte, parent *Grant, before, after uint64) ([]byte, error) {
	g, e := Draft(payload, parent)
	if e != nil {
		return nil, e
	}
	g.payload["not_before_height"] = json.Number(strconv.FormatUint(before, 10))
	g.payload["not_after_height"] = json.Number(strconv.FormatUint(after, 10))
	raw := encode(g.payload)
	if _, e = Draft(raw, parent); e != nil {
		return nil, e
	}
	return raw, nil
}
