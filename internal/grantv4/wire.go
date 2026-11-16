// Package grantv4 implements the octet-only pipeline of LIP-0020 at version
// 0.1.53. Reading a document is not chain admission or permission to sign it.
package grantv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	Type             = "swarma-grant/4"
	MaxBytes         = 65536
	MaxNumber uint64 = 9007199254740991
)

type Refusal string

func (r Refusal) Error() string { return string(r) }
func reject(code string)        { panic(Refusal(code)) }

// guard catches protocol refusals only; programming faults must not become
// successful results or misleading protocol codes.
func guard(err *error) {
	if p := recover(); p != nil {
		if r, ok := p.(Refusal); ok {
			*err = r
		} else {
			panic(p)
		}
	}
}

type object = map[string]any

type documentReader struct {
	b                            []byte
	i                            int
	duplicate, null, number, str bool
}

func (p *documentReader) peek() byte {
	if p.i == len(p.b) {
		return 0
	}
	return p.b[p.i]
}
func (p *documentReader) space() {
	for strings.ContainsRune(" \t\n\r", rune(p.peek())) && p.peek() != 0 {
		p.i++
	}
}
func (p *documentReader) take(c byte) {
	if p.peek() != c {
		reject("WIRE_JSON")
	}
	p.i++
}
func (p *documentReader) value(depth int) any {
	p.space()
	switch p.peek() {
	case '{', '[':
		if depth > 16 {
			reject("WIRE_SIZE")
		}
		open := p.peek()
		p.i++
		p.space()
		if open == '{' {
			m := object{}
			if p.peek() == '}' {
				p.i++
				return m
			}
			for {
				p.space()
				k := p.string()
				p.space()
				p.take(':')
				if _, exists := m[k]; exists {
					p.duplicate = true
				}
				m[k] = p.value(depth + 1)
				p.space()
				if p.peek() == '}' {
					p.i++
					return m
				}
				p.take(',')
			}
		}
		a := []any{}
		if p.peek() == ']' {
			p.i++
			return a
		}
		for {
			a = append(a, p.value(depth+1))
			p.space()
			if p.peek() == ']' {
				p.i++
				return a
			}
			p.take(',')
		}
	case '"':
		return p.string()
	case 't':
		p.word("true")
		return true
	case 'f':
		p.word("false")
		return false
	case 'n':
		p.word("null")
		p.null = true
		return nil
	default:
		start := p.i
		if p.peek() == '-' {
			p.i++
		}
		if p.peek() == '0' {
			p.i++
		} else {
			if p.peek() < '1' || p.peek() > '9' {
				reject("WIRE_JSON")
			}
			p.digits()
		}
		if p.peek() == '.' {
			p.i++
			p.digitsRequired()
		}
		if p.peek() == 'e' || p.peek() == 'E' {
			p.i++
			if p.peek() == '+' || p.peek() == '-' {
				p.i++
			}
			p.digitsRequired()
		}
		token := string(p.b[start:p.i])
		n, e := strconv.ParseUint(token, 10, 64)
		if e != nil || n > MaxNumber || strings.ContainsAny(token, "-.eE+") {
			p.number = true
		}
		return json.Number(token)
	}
}
func (p *documentReader) digits() {
	for p.peek() >= '0' && p.peek() <= '9' {
		p.i++
	}
}
func (p *documentReader) digitsRequired() {
	start := p.i
	p.digits()
	if start == p.i {
		reject("WIRE_JSON")
	}
}
func (p *documentReader) word(w string) {
	if !bytes.HasPrefix(p.b[p.i:], []byte(w)) {
		reject("WIRE_JSON")
	}
	p.i += len(w)
}
func (p *documentReader) hex4() uint64 {
	if len(p.b)-p.i < 4 {
		reject("WIRE_JSON")
	}
	for _, c := range p.b[p.i : p.i+4] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", rune(c)) {
			reject("WIRE_JSON")
		}
	}
	n, e := strconv.ParseUint(string(p.b[p.i:p.i+4]), 16, 16)
	if e != nil {
		reject("WIRE_JSON")
	}
	p.i += 4
	return n
}
func (p *documentReader) string() string {
	p.take('"')
	var out strings.Builder
	for {
		c := p.peek()
		if c < 0x20 {
			reject("WIRE_JSON")
		}
		p.i++
		if c == '"' {
			return out.String()
		}
		if c == '\\' {
			c = p.peek()
			p.i++
			switch c {
			case '"', '\\', '/':
				out.WriteByte(c)
			case 'b', 'f', 'n', 'r', 't':
				p.str = true
				out.WriteByte(map[byte]byte{'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}[c])
			case 'u':
				n := p.hex4()
				if n < 0x20 {
					p.str = true
				}
				if n >= 0xd800 && n <= 0xdbff && bytes.HasPrefix(p.b[p.i:], []byte(`\u`)) {
					save := p.i
					p.i += 2
					low := p.hex4()
					if low >= 0xdc00 && low <= 0xdfff {
						n = uint64(utf16.DecodeRune(rune(n), rune(low)))
					} else {
						p.i = save
					}
				}
				if n >= 0xd800 && n <= 0xdfff {
					p.str = true
					// Retain distinct unpaired code units until the duplicate
					// pass has finished. encoding/json replaces all with U+FFFD,
					// which would invent earlier WIRE_DUPLICATE refusals.
					out.Write([]byte{byte(0xe0 | n>>12), byte(0x80 | (n>>6)&63), byte(0x80 | n&63)})
				} else {
					out.WriteRune(rune(n))
				}
			default:
				reject("WIRE_JSON")
			}
		} else if c >= 0x80 {
			_, n := utf8.DecodeRune(p.b[p.i-1:])
			if n == 1 {
				reject("WIRE_JSON")
			}
			out.Write(p.b[p.i-1 : p.i-1+n])
			p.i += n - 1
		} else {
			out.WriteByte(c)
		}
	}
}

// parseDocument applies W9.2 globally, not in the order defects happen to
// occur in the JSON. Syntax and nesting are decided on the first pass.
func parseDocument(raw []byte, limit int) any {
	if len(raw) > limit {
		reject("WIRE_SIZE")
	}
	p := documentReader{b: raw}
	p.space()
	if p.peek() != '{' {
		reject("WIRE_JSON")
	}
	v := p.value(1)
	p.space()
	if p.i != len(raw) {
		reject("WIRE_JSON")
	}
	if p.duplicate {
		reject("WIRE_DUPLICATE")
	}
	if p.null {
		reject("WIRE_VALUE")
	}
	if p.number {
		reject("WIRE_NUMBER")
	}
	if p.str {
		reject("WIRE_STRING")
	}
	if !bytes.Equal(encode(v), raw) {
		reject("WIRE_NOT_CANONICAL")
	}
	return v
}
func keys(m object) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := utf16.Encode([]rune(out[i])), utf16.Encode([]rune(out[j]))
		for n := 0; n < min(len(a), len(b)); n++ {
			if a[n] != b[n] {
				return a[n] < b[n]
			}
		}
		return len(a) < len(b)
	})
	return out
}

// encode serializes only already checked restricted JSON values. Unlike
// encoding/json it leaves U+2028, HTML characters and non-BMP text literal.
func encode(v any) []byte {
	var b bytes.Buffer
	var put func(any)
	quote := func(s string) {
		b.WriteByte('"')
		for _, c := range s {
			if c == '"' || c == '\\' {
				b.WriteByte('\\')
			}
			b.WriteRune(c)
		}
		b.WriteByte('"')
	}
	put = func(v any) {
		switch x := v.(type) {
		case object:
			b.WriteByte('{')
			for i, k := range keys(x) {
				if i > 0 {
					b.WriteByte(',')
				}
				quote(k)
				b.WriteByte(':')
				put(x[k])
			}
			b.WriteByte('}')
		case []any:
			b.WriteByte('[')
			for i, e := range x {
				if i > 0 {
					b.WriteByte(',')
				}
				put(e)
			}
			b.WriteByte(']')
		case string:
			quote(x)
		case json.Number:
			b.WriteString(string(x))
		case bool:
			b.WriteString(strconv.FormatBool(x))
		default:
			panic("unchecked JSON value")
		}
	}
	put(v)
	return b.Bytes()
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func typed(tag string, raw []byte) string {
	t := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(t[:])
	h.Write(t[:])
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func str(m object, k string) string { s, _ := m[k].(string); return s }
func obj(m object, k string) object { o, _ := m[k].(object); return o }
func arr(m object, k string) []any  { a, _ := m[k].([]any); return a }
func num(m object, k string) uint64 {
	n, _ := strconv.ParseUint(string(m[k].(json.Number)), 10, 64)
	return n
}
