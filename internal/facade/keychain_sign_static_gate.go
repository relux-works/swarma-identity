package facade

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-identity/internal/keypolicy"
)

// keychain sign for one `swarma-s7 static-gate/1` statement G. The request
// names its own schema and nothing is inferred from its content. Custody, the
// terminal and the typed confirmation are those of sign/1; this file adds the
// statement path only:
//
//   - the preimage is rebuilt here as ASCII(tag) || 0x0a || CCJ-1(G), and the
//     requested digest must be its SHA-256;
//   - G must be canonical CCJ-1: it is parsed, encoded again and compared
//     byte for byte;
//   - the key is bound to the purpose by its label, in both directions (see
//     refuseStaticGateKeyForGrant), and G must name that label and that key;
//   - every value of G is shown by its path, read from the parsed bytes with
//     no table of known sections, beside a scope text worded from G alone.
//
// All of it runs before the display and before any secret is read.
const (
	KeychainSignStaticGateSchema = "swarma-keychain/sign-static-gate/1"
	PurposeStaticGate            = "static_gate"
	// StaticGateKeyLabel is the one Keychain label that signs static_gate,
	// and it signs nothing else.
	StaticGateKeyLabel = "swarma-static-gate-g1"

	staticGateTag         = "swarma-s7 static-gate/1" // the preimage tag and G's kind
	staticGateMaxPreimage = 8192
	staticGateMaxWindow   = 72 * time.Hour
	staticGateTimeLayout  = "2006-01-02T15:04:05Z"
	ccjMaxDepth           = 8
)

// StaticGateSignRequest is the closed request of the static-gate schema.
// statement_b64 is canonical standard base64 of the exact CCJ-1 bytes of G;
// digest is the SHA-256 the caller expects to be signed.
type StaticGateSignRequest struct {
	Schema       string `json:"schema"`
	Purpose      string `json:"purpose"`
	StatementB64 string `json:"statement_b64"`
	Digest       string `json:"digest"`
}

// StaticGateSignResult is public data only: the key, the statement that was
// signed, the digest and the 64-byte BIP-340 signature in lowercase hex.
type StaticGateSignResult struct {
	Purpose      string           `json:"purpose"`
	Label        string           `json:"label"`
	XOnlyKey     string           `json:"xonly_key"`
	AccessPolicy keypolicy.Policy `json:"access_policy"`
	StatementB64 string           `json:"statement_b64"`
	Digest       string           `json:"digest"`
	Signature    string           `json:"signature"`
}

func staticGateRefuse(code string) *Failure {
	return &Failure{Code: code, Message: "The static-gate key rule or statement check refuses this request; no secret was read or created.", Exit: 3}
}

// refuseStaticGateKeyForGrant is the grant half of the key separation: the
// label reserved for the static-gate key signs no grant request (contract,
// grant or seal spend, under sign/1 or sign/2). The other half is in
// signStaticGate: no other label signs a static-gate statement. A label holds
// one key and keygen never imports one, so no key serves both purposes.
func refuseStaticGateKeyForGrant(label string) *Failure {
	if label == StaticGateKeyLabel {
		return staticGateRefuse("KEY_PURPOSE")
	}
	return nil
}

// refuseStaticGateKeygen keeps the reserved label on biometry-current-set.
func refuseStaticGateKeygen(label string, access keypolicy.Policy) *Failure {
	if label == StaticGateKeyLabel && access != keypolicy.CurrentSet {
		return staticGateRefuse("STATIC_GATE_KEY_ACCESS")
	}
	return nil
}

// ccjMember and ccjObject keep an object's members in the order of the bytes.
// A CCJ-1 value is a ccjObject, a []any, a string, a json.Number holding an
// integer, a bool or nil.
type ccjMember struct {
	name  string
	value any
}

type ccjObject []ccjMember

func (o ccjObject) get(name string) (any, bool) {
	for _, m := range o {
		if m.name == name {
			return m.value, true
		}
	}
	return nil, false
}

func (o ccjObject) text(name string) (string, bool) {
	v, _ := o.get(name)
	s, ok := v.(string)
	return s, ok
}

func (o ccjObject) object(name string) (ccjObject, bool) {
	v, _ := o.get(name)
	sub, ok := v.(ccjObject)
	return sub, ok
}

var ccjIntegerPattern = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)

// ccjParse reads exactly one JSON value under the CCJ-1 limits: valid UTF-8,
// no duplicate name in an object, integers only (shortest spelling, within
// 64 bits) and at most ccjMaxDepth nested containers, the outermost counted
// as 1. It does not by itself establish canonical form; ccjCanonical does.
func ccjParse(raw []byte) (any, bool) {
	if !utf8.Valid(raw) {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(depth int) (any, bool)
	walk = func(depth int) (any, bool) {
		tok, err := d.Token()
		if err != nil {
			return nil, false
		}
		switch v := tok.(type) {
		case json.Delim:
			if depth >= ccjMaxDepth || (v != '{' && v != '[') {
				return nil, false
			}
			obj, arr, seen := ccjObject{}, []any{}, map[string]bool{}
			for d.More() {
				name := ""
				if v == '{' {
					k, err := d.Token()
					key, ok := k.(string)
					if err != nil || !ok || seen[key] {
						return nil, false
					}
					seen[key], name = true, key
				}
				value, ok := walk(depth + 1)
				if !ok {
					return nil, false
				}
				obj, arr = append(obj, ccjMember{name, value}), append(arr, value)
			}
			if _, err := d.Token(); err != nil {
				return nil, false
			}
			if v == '{' {
				return obj, true
			}
			return arr, true
		case string:
			return v, true
		case json.Number:
			if _, err := strconv.ParseInt(v.String(), 10, 64); err != nil || !ccjIntegerPattern.MatchString(v.String()) {
				return nil, false
			}
			return v, true
		case bool:
			return v, true
		case nil:
			return nil, true
		}
		return nil, false
	}
	v, ok := walk(0)
	if !ok {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	return v, true
}

// ccjString writes one string with the escapes this signer takes as CCJ-1's:
// \" and \\, the short forms \b \f \n \r \t, \u00xx (lowercase hex) for every
// other control character below 0x20, and every other character as its UTF-8
// bytes. This is the one place that fixes the escape set.
func ccjString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				fmt.Fprintf(b, `\u%04x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
}

// ccjEncode writes the CCJ-1 encoding of a parsed value: object names sorted
// by Unicode scalar (the byte order of their UTF-8), no whitespace, integers
// in the spelling ccjParse admitted.
func ccjEncode(b *bytes.Buffer, v any) bool {
	switch x := v.(type) {
	case ccjObject:
		sorted := slices.Clone(x)
		slices.SortStableFunc(sorted, func(l, r ccjMember) int { return strings.Compare(l.name, r.name) })
		b.WriteByte('{')
		for i, m := range sorted {
			if i > 0 {
				b.WriteByte(',')
			}
			ccjString(b, m.name)
			b.WriteByte(':')
			if !ccjEncode(b, m.value) {
				return false
			}
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if !ccjEncode(b, e) {
				return false
			}
		}
		b.WriteByte(']')
	case string:
		ccjString(b, x)
	case json.Number:
		b.WriteString(x.String())
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case nil:
		b.WriteString("null")
	default:
		return false
	}
	return true
}

// ccjCanonical admits raw only when it is one CCJ-1 value whose encoding is
// exactly raw. The parsed value therefore describes these bytes and no
// others, and its member order is the order of the bytes.
func ccjCanonical(raw []byte) (any, bool) {
	v, ok := ccjParse(raw)
	if !ok {
		return nil, false
	}
	var again bytes.Buffer
	if !ccjEncode(&again, v) || !bytes.Equal(again.Bytes(), raw) {
		return nil, false
	}
	return v, true
}

var ccjPlainName = regexp.MustCompile(`^[a-z0-9_]+$`)

// ccjPath extends a path by one member name. A name of [a-z0-9_] is joined
// with a dot; any other name is shown quoted in brackets with control and
// non-ASCII characters escaped, so a name cannot imitate a nested path.
func ccjPath(path, name string) string {
	if !ccjPlainName.MatchString(name) {
		return path + "[" + strconv.QuoteToASCII(name) + "]"
	}
	if path == "" {
		return name
	}
	return path + "." + name
}

// ccjLeaves lists every value under v as "path = value", in the order of the
// bytes: object members by name, array elements by index. Strings are quoted
// with control and non-ASCII characters escaped, integers keep their
// spelling, and an empty object or array is a value of its own. It knows no
// member name: whatever the statement holds is listed.
func ccjLeaves(path string, v any, out []string) []string {
	switch x := v.(type) {
	case ccjObject:
		if len(x) == 0 {
			return append(out, path+" = {}")
		}
		for _, m := range x {
			out = ccjLeaves(ccjPath(path, m.name), m.value, out)
		}
	case []any:
		if len(x) == 0 {
			return append(out, path+" = []")
		}
		for i, e := range x {
			out = ccjLeaves(fmt.Sprintf("%s[%d]", path, i), e, out)
		}
	case string:
		out = append(out, path+" = "+strconv.QuoteToASCII(x))
	case json.Number:
		out = append(out, path+" = "+x.String())
	case bool:
		out = append(out, path+" = "+strconv.FormatBool(x))
	case nil:
		out = append(out, path+" = null")
	}
	return out
}

// staticGate is one admitted statement: its exact bytes, the preimage and
// digest rebuilt from them, and the few members the signer itself relies on.
type staticGate struct {
	statement   []byte
	preimage    []byte
	digest      []byte
	leaves      []string // every value of G by path
	sections    []string // the top-level member names, in the order of the bytes
	association []string // the leaves under association
	machineID   string
	notBefore   time.Time
	notAfter    time.Time
	approverKey string
}

// staticGatePreimage is ASCII(tag) || 0x0a || statement, with no final line
// feed and no wrapper.
func staticGatePreimage(statement []byte) []byte {
	return append(append([]byte(staticGateTag), 0x0a), statement...)
}

// staticGateTime admits only RFC 3339 UTC in whole seconds with a final Z.
func staticGateTime(s string) (time.Time, bool) {
	t, err := time.Parse(staticGateTimeLayout, s)
	if err != nil || t.UTC().Format(staticGateTimeLayout) != s {
		return time.Time{}, false
	}
	return t, true
}

// checkStaticGate admits one statement for the label that was asked to sign
// it, in this order: size, canonical CCJ-1, digest binding, the members the
// signer relies on, the approver label, the window. The first failure
// refuses; nothing is shown before all of them pass.
func checkStaticGate(statement []byte, digestHex, label string) (*staticGate, *Failure) {
	g := &staticGate{statement: statement, preimage: staticGatePreimage(statement)}
	if len(g.preimage) > staticGateMaxPreimage {
		return nil, staticGateRefuse("STATIC_GATE_FORM")
	}
	v, ok := ccjCanonical(statement)
	root, isObject := v.(ccjObject)
	if !ok || !isObject {
		return nil, staticGateRefuse("STATIC_GATE_FORM")
	}
	sum := sha256.Sum256(g.preimage)
	if digestHex != hex.EncodeToString(sum[:]) {
		return nil, staticGateRefuse("DIGEST_BINDING")
	}
	g.digest = sum[:]
	version, _ := root.get("v")
	kind, _ := root.text("kind")
	approver, okApprover := root.object("approver")
	host, okHost := root.object("host")
	association, okAssociation := root.object("association")
	if version != json.Number("1") || kind != staticGateTag || !okApprover || !okHost || !okAssociation || len(association) == 0 {
		return nil, staticGateRefuse("STATIC_GATE_FORM")
	}
	alg, _ := approver.text("alg")
	key, _ := approver.text("key")
	approverLabel, okLabel := approver.text("label")
	machineID, _ := host.text("machine_id_sha256")
	notBefore, _ := root.text("not_before")
	notAfter, _ := root.text("not_after")
	from, okFrom := staticGateTime(notBefore)
	until, okUntil := staticGateTime(notAfter)
	if alg != "bip340" || !xOnlyKey(key) || !okLabel || !lowerHex(machineID, 32) || !okFrom || !okUntil {
		return nil, staticGateRefuse("STATIC_GATE_FORM")
	}
	if approverLabel != label {
		return nil, staticGateRefuse("STATIC_GATE_LABEL")
	}
	if !until.After(from) || until.Sub(from) > staticGateMaxWindow {
		return nil, staticGateRefuse("STATIC_GATE_WINDOW")
	}
	g.leaves = ccjLeaves("", root, nil)
	g.association = ccjLeaves("association", association, nil)
	for _, m := range root {
		g.sections = append(g.sections, ccjPath("", m.name))
	}
	g.machineID, g.notBefore, g.notAfter, g.approverKey = machineID, from, until, key
	return g, nil
}

// staticGateScopeText words what the signature covers. Its only input is the
// admitted statement: no member of the request and no free text enters it.
func staticGateScopeText(g *staticGate) []string {
	out := []string{
		fmt.Sprintf("One statement of kind %s, version 1.", staticGateTag),
		fmt.Sprintf("Host: only the machine whose machine-id has the SHA-256 %s.", g.machineID),
		fmt.Sprintf("Window: not before %s, not after %s; length %s, the limit is %s.", g.notBefore.Format(staticGateTimeLayout), g.notAfter.Format(staticGateTimeLayout), g.notAfter.Sub(g.notBefore), staticGateMaxWindow),
		fmt.Sprintf("Caller association, %d value(s), exactly as signed:", len(g.association)),
	}
	for _, l := range g.association {
		out = append(out, "  - "+l)
	}
	return append(out, fmt.Sprintf("Sections, %d top-level members, each shown in full below: %s", len(g.sections), strings.Join(g.sections, ", ")))
}

// renderStaticGate is every field the human approves. The confirmation
// covers exactly this text. No value is shortened.
func renderStaticGate(g *staticGate, label, xonly string, access keypolicy.Policy, inspectable bool) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("\n=== SWARMA STATIC-GATE KEY: SIGNING REQUEST ===\n")
	w("Request schema     : %s\n", KeychainSignStaticGateSchema)
	w("Purpose            : %s; this key signs no grant, no consent and no seal spend, and no other key signs this purpose\n", PurposeStaticGate)
	w("Keychain label     : %s\n", label)
	w("Access policy      : %s (this-device-only)\n", access)
	if !inspectable {
		w("Native ACL flags   : unavailable through public Security APIs; authenticated policy metadata is checked before signing.\n")
	}
	w("Signing key x-only : %s (equals approver.key of the statement)\n", xonly)
	w("SCOPE TEXT         : worded by this signer from the statement bytes only; no wording comes from the request\n")
	for _, line := range staticGateScopeText(g) {
		w("  %s\n", line)
	}
	w("Statement members  : all %d values of the statement by path, in the order of the signed bytes\n", len(g.leaves))
	for _, l := range g.leaves {
		w("    %s\n", l)
	}
	w("Signature 1        : BIP-340, purpose %s\n", PurposeStaticGate)
	w("  digest           : %x\n", g.digest)
	w("  SHA-256 of       : the %d bytes below: tag \"%s\" (%d bytes) || \\x0a || canonical statement (%d bytes), no final line feed\n", len(g.preimage), staticGateTag, len(staticGateTag), len(g.statement))
	w("  exact bytes      :\n")
	for off := 0; off < len(g.preimage); off += 64 {
		w("    %04d  %s\n", off, escapeBytes(g.preimage[off:min(off+64, len(g.preimage))], false))
	}
	w("The 1 signature asks for Touch ID once.\n")
	return b.String()
}

func (deps keychainDeps) signStaticGate(label string, r StaticGateSignRequest) (*StaticGateSignResult, *Failure) {
	if r.Schema != KeychainSignStaticGateSchema || r.Purpose != PurposeStaticGate || !validLabel(label) {
		return nil, fail("BAD_INPUT")
	}
	// Key separation, before the statement is even decoded: only the
	// reserved label signs this purpose.
	if label != StaticGateKeyLabel {
		return nil, staticGateRefuse("KEY_PURPOSE")
	}
	statement, err := base64.StdEncoding.Strict().DecodeString(r.StatementB64)
	if err != nil || len(statement) == 0 || base64.StdEncoding.EncodeToString(statement) != r.StatementB64 {
		return nil, fail("BAD_INPUT")
	}
	g, f := checkStaticGate(statement, r.Digest, label)
	if f != nil {
		return nil, f
	}
	if deps.signer == nil {
		return nil, fail("UNSUPPORTED_CAPABILITY")
	}
	stored, err := deps.signer.Public(label)
	if err != nil {
		return nil, keychainFailure(err)
	}
	pub, err := btcec.ParsePubKey(stored)
	if err != nil || len(stored) != 33 {
		return nil, keychainFailure(errors.New(errItem))
	}
	xonly := hex.EncodeToString(schnorr.SerializePubKey(pub))
	if g.approverKey != xonly {
		return nil, staticGateRefuse("KEY_MISMATCH")
	}
	access, inspectable, err := deps.signer.Access(label)
	if err != nil {
		return nil, keychainFailure(err)
	}
	if access != keypolicy.CurrentSet {
		return nil, staticGateRefuse("STATIC_GATE_KEY_ACCESS")
	}
	term, err := deps.terminal()
	if err != nil {
		return nil, keychainRefuse("NO_TERMINAL")
	}
	if err := term.Show(renderStaticGate(g, label, xonly, access, inspectable)); err != nil {
		return nil, keychainRefuse("NO_TERMINAL")
	}
	ok, err := term.Confirm("Type " + confirmWord + " to sign exactly the above, anything else declines: ")
	if err != nil || !ok {
		return nil, keychainRefuse("CONFIRMATION_DECLINED")
	}
	reason := fmt.Sprintf("sign %s %x… [access: %s]", PurposeStaticGate, g.digest[:8], access)
	sig, err := deps.signer.SignSchnorr(label, reason, g.digest, access)
	if err != nil {
		return nil, keychainFailure(err)
	}
	digest := hex.EncodeToString(g.digest)
	if !rental.VerifySignature(xonly, digest, hex.EncodeToString(sig)) {
		return nil, keychainRefuse("SIGNATURE_VERIFY")
	}
	return &StaticGateSignResult{PurposeStaticGate, label, xonly, access, r.StatementB64, digest, hex.EncodeToString(sig)}, nil
}

// requestSchema returns the top-level "schema" string of a request file, read
// by its exact name from JSON without duplicate names, or "" when there is
// none. It is the discriminator; no other member is looked at.
func requestSchema(raw []byte) string {
	if validateJSON(raw) != nil {
		return ""
	}
	var members map[string]json.RawMessage
	var schema string
	if json.Unmarshal(raw, &members) != nil || members["schema"] == nil || json.Unmarshal(members["schema"], &schema) != nil {
		return ""
	}
	return schema
}

// staticGateSignCommand takes the request only when its schema is exactly the
// static-gate one; handled is then true and the request is decoded as that
// closed shape, so a member of another schema beside it is BAD_INPUT. For
// every other file (unreadable and malformed ones included) it does nothing,
// and keychain sign reads and judges the file as it always did.
func staticGateSignCommand(deps keychainDeps, label, requestPath string) (result any, failure *Failure, handled bool) {
	f, err := os.OpenFile(requestPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 65536 {
		return nil, nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || requestSchema(raw) != KeychainSignStaticGateSchema {
		return nil, nil, false
	}
	var r StaticGateSignRequest
	if DecodeStrict(raw, &r) != nil {
		return nil, fail("BAD_INPUT"), true
	}
	signed, failure := deps.signStaticGate(label, r)
	if failure != nil {
		return nil, failure, true
	}
	return signed, nil, true
}
