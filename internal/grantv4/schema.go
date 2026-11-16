package grantv4

import (
	"strconv"
	"strings"

	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type schema struct {
	members   map[string]*schema
	optional  string
	choose    func(object) *schema
	elem      *schema
	min, max  int
	form      string
	low, high uint64
}

func record(m map[string]*schema, optional string) *schema {
	return &schema{members: m, optional: " " + optional + " "}
}
func list(e *schema, low, high int) *schema      { return &schema{elem: e, min: low, max: high} }
func leaf(form string) *schema                   { return &schema{form: form} }
func integer(low, high uint64) *schema           { return &schema{form: "number", low: low, high: high} }
func alternative(f func(object) *schema) *schema { return &schema{choose: f} }
func (s *schema) selected(v any) *schema {
	if s.choose != nil {
		m, _ := v.(object)
		return s.choose(m)
	}
	return s
}

var (
	text       = leaf("text")
	signingKey = leaf("signing")
	outputKey  = leaf("output")
	hashSchema = leaf("hash")
	height     = integer(0, MaxNumber)
	index      = integer(0, 4294967295)
	outpoint   = record(map[string]*schema{"txid": hashSchema, "vout": index}, "")
	pin        = record(map[string]*schema{"name": text, "owner": outputKey, "registration": outpoint}, "")
	issuer     = record(map[string]*schema{"name": text, "owner": outputKey, "registration": outpoint, "grant_key": signingKey}, "")
	executor   = record(map[string]*schema{"name": text, "key": signingKey}, "")
	limits     = list(record(map[string]*schema{"amount": leaf("amount"), "kind": text, "resource": text, "unit": text, "period": text}, "period"), 0, MaxBytes)
	actions    = list(text, 0, MaxBytes)
	byKey      = record(map[string]*schema{"key": signingKey}, "")
	byName     = record(map[string]*schema{"name": text, "owner": outputKey}, "")
	byClass    = record(map[string]*schema{"class": list(pin, 1, MaxBytes)}, "")
	recipient  = alternative(func(m object) *schema {
		if _, ok := m["key"]; ok {
			return byKey
		}
		return byName
	})
	rowRecipient = alternative(func(m object) *schema {
		if _, ok := m["class"]; ok {
			return byClass
		}
		return recipient.selected(m)
	})
	seal      = record(map[string]*schema{"construction": leaf("short"), "key": outputKey, "kind": leaf("short"), "outpoint": outpoint}, "")
	stop      = record(map[string]*schema{"first": index, "script": leaf("script"), "txid": hashSchema}, "")
	coinRange = record(map[string]*schema{"count": integer(1, 4096), "first": index, "script": leaf("script"), "txid": hashSchema, "stop": stop}, "stop")
	template  = alternative(func(m object) *schema {
		members := map[string]*schema{"executor": executor, "limits": limits, "recipient": rowRecipient}
		if _, ok := m["no_certifier"]; ok {
			members["no_certifier"] = leaf("true")
		} else {
			members["certifier"] = text
		}
		return record(members, "")
	})
	group         = record(map[string]*schema{"ranges": list(coinRange, 1, 16), "template": template}, "")
	delegate      = record(map[string]*schema{"actions": actions, "child_seal_key": outputKey, "groups": list(group, 1, 16), "key": signingKey, "notaries": list(pin, 0, 4), "pools": limits}, "child_seal_key")
	payloadSchema = alternative(func(m object) *schema {
		members := map[string]*schema{"actions": actions, "contract": hashSchema, "executor": executor, "genesis": hashSchema, "limits": limits, "not_after_height": height, "not_before_height": height, "recent_block": hashSchema, "recipient": recipient, "seal": seal, "type": leaf("string")}
		if _, ok := m["parent"]; ok {
			members["parent"] = hashSchema
			members["ordinal"] = height
			return record(members, "")
		}
		members["issuer"] = issuer
		members["delegate"] = delegate
		return record(members, "delegate")
	})
)

// checkSchema makes three complete passes: names at every depth, values in
// canonical order, then curve points. A later object's name defect therefore
// precedes an earlier value defect (W9.3).
func checkSchema(v any, s *schema) {
	for pass := 0; pass < 3; pass++ {
		schemaPass(v, s, pass)
	}
}
func schemaPass(v any, s *schema, pass int) {
	s = s.selected(v)
	if s.members != nil {
		m, ok := v.(object)
		if !ok {
			if pass == 1 {
				reject("WIRE_MEMBER")
			}
			return
		}
		if pass == 0 {
			for k := range s.members {
				if _, ok := m[k]; !ok && !strings.Contains(s.optional, " "+k+" ") {
					reject("WIRE_MEMBER")
				}
			}
			for k := range m {
				if s.members[k] == nil {
					reject("WIRE_MEMBER")
				}
			}
		}
		for _, k := range keys(m) {
			schemaPass(m[k], s.members[k], pass)
		}
		return
	}
	if s.elem != nil {
		a, ok := v.([]any)
		if !ok || len(a) < s.min || len(a) > s.max {
			if pass == 1 {
				reject("WIRE_MEMBER")
			}
			if !ok {
				return
			}
		}
		for _, x := range a {
			schemaPass(x, s.elem, pass)
		}
		return
	}
	if pass == 0 {
		return
	}
	value, isString := v.(string)
	if pass == 2 {
		switch s.form {
		case "signing":
			b, _ := hex.DecodeString(value)
			if _, e := schnorr.ParsePubKey(b); e != nil {
				reject("WIRE_KEY")
			}
		case "output":
			b, _ := hex.DecodeString(value)
			if _, e := btcec.ParsePubKey(b); e != nil {
				reject("WIRE_KEY")
			}
		}
		return
	}
	if s.form == "number" {
		n, ok := v.(interface{ String() string })
		if !ok {
			reject("WIRE_MEMBER")
		}
		value, e := strconv.ParseUint(n.String(), 10, 64)
		if e != nil || value < s.low || value > s.high {
			reject("WIRE_INTEGER")
		}
		return
	}
	if s.form == "true" {
		if v != true {
			reject("WIRE_MEMBER")
		}
		return
	}
	if !isString {
		reject("WIRE_MEMBER")
	}
	switch s.form {
	case "string":
	case "text", "short":
		bound := 255
		if s.form == "short" {
			bound = 32
		}
		if len(value) < 1 || len(value) > bound {
			reject("WIRE_MEMBER")
		}
		for _, c := range value {
			if c < 0x20 || c > 0x7e {
				reject("WIRE_MEMBER")
			}
		}
	case "hash", "signing":
		if !isHex(value, 64) {
			reject("WIRE_MEMBER")
		}
	case "signature":
		if !isHex(value, 128) {
			reject("WIRE_MEMBER")
		}
	case "output":
		if !isHex(value, 66) || (value[:2] != "02" && value[:2] != "03") {
			reject("WIRE_MEMBER")
		}
	case "script":
		if len(value) < 2 || len(value) > 200 || len(value)%2 != 0 || !isHex(value, len(value)) {
			reject("WIRE_MEMBER")
		}
	case "amount":
		if value == "" || (len(value) > 1 && value[0] == '0') {
			reject("WIRE_INTEGER")
		}
		for _, c := range value {
			if c < '0' || c > '9' {
				reject("WIRE_INTEGER")
			}
		}
		if _, e := strconv.ParseUint(value, 10, 64); e != nil {
			reject("WIRE_INTEGER")
		}
	default:
		panic("unknown schema")
	}
}
