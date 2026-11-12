package facade

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

const DeriveSchema = "swarma-identity/derive/1"

type Failure struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	Exit      int    `json:"-"`
}

func fail(code string) *Failure {
	f := &Failure{Code: code, Message: "The input does not satisfy the selected contract.", Exit: 2}
	switch code {
	case "UNSUPPORTED_CAPABILITY", "WRONG_NETWORK", "NODE_UNSYNCED", "NAME_EXPIRED", "WATCH_WALLET_REQUIRED", "ADDRESS_NOT_WATCHED", "BALANCE_COVERAGE_UNSUPPORTED":
		f.Exit = 3
		f.Message = "The selected operation is refused by the read-only contract."
	case "NAME_NOT_FOUND":
		f.Exit = 3
		f.Message = "The requested name was not found."
	case "SCAN_BUSY", "SNAPSHOT_CHANGED":
		f.Exit = 4
		f.Retryable = true
		f.Message = "The node state prevents a result; the caller may try later."
	case "RPC_UNAVAILABLE":
		f.Exit = 4
		f.Retryable = true
		f.Message = "The selected node could not be read within the operation deadline."
	case "SCAN_UNCERTAIN":
		f.Exit = 4
		f.Message = "A submitted scan has no confirmed result and may still be running; no retry or abort was sent."
	case "RPC_REFUSED":
		f.Exit = 3
		f.Message = "The selected read was refused by the node."
	case "PROVIDER_PROTOCOL":
		f.Exit = 5
		f.Message = "The node returned an invalid or inconsistent response."
	case "INTERNAL":
		f.Exit = 1
		f.Message = "The operation failed internally."
	}
	return f
}

var errJSON = errors.New("invalid closed JSON object")

// DecodeStrict validates UTF-8, duplicate decoded names, exact schema keys and
// required member presence and non-null array elements before unmarshalling.
// No input is included in errors.
func DecodeStrict(raw []byte, dst any) error {
	if len(raw) > 65536 || !utf8.Valid(raw) {
		return errJSON
	}
	if err := validateJSON(raw); err != nil {
		return errJSON
	}
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return errJSON
	}
	if err := closedObject(raw, v.Elem().Type()); err != nil {
		return errJSON
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return errJSON
	}
	return nil
}

func validateJSON(raw []byte) error {
	if !utf8.Valid(raw) || !validUnicodeEscapes(raw) {
		return errJSON
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errJSON
		}
		t, err := d.Token()
		if err != nil {
			return errJSON
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return errJSON
					}
					key, ok := k.(string)
					if !ok || seen[key] {
						return errJSON
					}
					seen[key] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return errJSON
				}
			case '[':
				for d.More() {
					if e := walk(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return errJSON
				}
			default:
				return errJSON
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errJSON
	}
	return nil
}

// encoding/json replaces lone UTF-16 surrogates with U+FFFD. Reject those
// spellings before decoding so an exact name/key cannot silently change.
func validUnicodeEscapes(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		u, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if u >= 0xdc00 && u <= 0xdfff {
			return false
		}
		if u < 0xd800 || u > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}

// Null is forbidden in typed public inputs, including inside index arrays.
// The shared JSON syntax validator still permits legitimate RPC null values.
func closedValue(raw []byte, t reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errJSON
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		return closedObject(raw, t)
	case reflect.Slice:
		var elements []json.RawMessage
		if json.Unmarshal(raw, &elements) != nil {
			return errJSON
		}
		for _, element := range elements {
			if err := closedValue(element, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func closedObject(raw []byte, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return errJSON
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return errJSON
	}
	allowed := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := strings.Split(field.Tag.Get("json"), ",")
		name := tag[0]
		if name == "-" || name == "" {
			continue
		}
		allowed[name] = true
		value, exists := m[name]
		optional := false
		for _, p := range tag[1:] {
			if p == "omitempty" {
				optional = true
			}
		}
		if !exists {
			if !optional {
				return errJSON
			}
			continue
		}
		if err := closedValue(value, field.Type); err != nil {
			return err
		}
	}
	for k := range m {
		if !allowed[k] {
			return errJSON
		}
	}
	return nil
}
