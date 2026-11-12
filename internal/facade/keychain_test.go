package facade

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"golang.org/x/sys/unix"

	"github.com/relux-works/swarma-identity/internal/keychain/keychainfake"
	"github.com/relux-works/swarma-identity/internal/keysign"
)

const kcLabel = "test-grant"

// fakeTerminal records what is shown and answers the confirmation. Every
// call is appended to the shared log beside the store events.
type fakeTerminal struct {
	log    *[]string
	shown  bytes.Buffer
	answer string
}

func (t *fakeTerminal) Show(text string) error {
	*t.log = append(*t.log, "show")
	t.shown.WriteString(text)
	return nil
}

func (t *fakeTerminal) Confirm(prompt string) (bool, error) {
	*t.log = append(*t.log, "confirm")
	t.shown.WriteString(prompt)
	return t.answer == confirmWord, nil
}

type kcHarness struct {
	t     *testing.T
	store *keychainfake.Store
	term  *fakeTerminal
	log   []string
	deps  keychainDeps
	blobs [][]byte
}

type fixedReader []byte

func (r fixedReader) Read(p []byte) (int, error) { return copy(p, r), nil }

// newKC holds the landlord's published BIP-340 test key 1 in a fake store.
func newKC(t *testing.T, answer string) *kcHarness {
	h := &kcHarness{t: t, store: keychainfake.New()}
	h.term = &fakeTerminal{log: &h.log, answer: answer}
	h.store.OnEvent = func(e string) { h.log = append(h.log, e) }
	secret, _ := hex.DecodeString(bip340Secrets[keyLandlord])
	signer := keysign.NewWithStore(h.store, fixedReader(secret))
	if _, err := signer.Keygen(kcLabel); err != nil {
		t.Fatal(err)
	}
	h.log = nil
	h.deps = keychainDeps{signer: signer, terminal: func() (Terminal, error) { return h.term, nil }}
	return h
}

func (h *kcHarness) run(args ...string) (Envelope, int) {
	h.t.Helper()
	var out, diag bytes.Buffer
	code := run(context.Background(), append(args, "--json"), &out, &diag, h.deps)
	h.blobs = append(h.blobs, out.Bytes(), diag.Bytes(), h.term.shown.Bytes())
	if diag.Len() != 0 || !outputSafe(out.Bytes()) {
		h.t.Fatal("unsafe CLI output")
	}
	var e Envelope
	if json.Unmarshal(out.Bytes(), &e) != nil {
		h.t.Fatal("bad envelope")
	}
	return e, code
}

func (h *kcHarness) sign(r KeychainSignRequest) (Envelope, int) {
	return h.run("keychain", "sign", "--label", kcLabel, "--request", writeInput(h.t, r))
}

func (h *kcHarness) count(prefix string) int {
	n := 0
	for _, e := range h.log {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}

// sealSpendFor spends the draft's seal (P2PKH to the landlord key) to two
// outputs; value 100000 in, 99000 out.
func sealSpendFor(t *testing.T, d GrantDraft, script []byte) (*wire.MsgTx, SealSpend) {
	t.Helper()
	tx := wire.NewMsgTx(2)
	h, err := chainhash.NewHashFromStr(d.Seal.TxID)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := chainhash.NewHashFromStr(strings.Repeat("77", 32))
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(other, 0), nil, nil))
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(h, d.Seal.Vout), nil, nil))
	tx.AddTxOut(wire.NewTxOut(60000, script))
	tx.AddTxOut(wire.NewTxOut(39000, []byte{txscript.OP_RETURN, 0x04, 1, 2, 3, 4}))
	var b bytes.Buffer
	if err := tx.SerializeNoWitness(&b); err != nil {
		t.Fatal(err)
	}
	return tx, SealSpend{TxHex: hex.EncodeToString(b.Bytes()), InputIndex: 1, Prevouts: []Prevout{{ScriptHex: hex.EncodeToString(script), AmountSat: 1000}, {ScriptHex: hex.EncodeToString(script), AmountSat: 99000}}}
}

func landlordP2PKH(t *testing.T) []byte {
	raw, _ := hex.DecodeString(bip340Secrets[keyLandlord])
	_, pub := btcec.PrivKeyFromBytes(raw)
	return p2pkhScript(pub.SerializeCompressed())
}

// fullRequest asks for landlord_sig, the grant signature and the seal spend.
func fullRequest(t *testing.T, f *flow) KeychainSignRequest {
	_, spend := sealSpendFor(t, f.draft.Draft, landlordP2PKH(t))
	ev := f.consent.ConsentEvent
	return KeychainSignRequest{Schema: KeychainSignSchema, Draft: f.draft.Draft, ConsentEvent: &ev, LandlordSig: f.landlordSig, SealSpend: &spend,
		ToSign: []SigningDigest{
			digestSigner("landlord", f.draft.Draft.IssuerKey, PurposeContract, f.draft.Draft.ContractSHA256),
			digestSigner("landlord", f.draft.Draft.IssuerKey, PurposeGrant, f.stage1.GrantSigningHash),
		}}
}

func preparedFlow(t *testing.T) *flow {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	f.prepare(regtestRequest([]string{"instruct", "land", "spend"}, []string{"https://github.com/relux-works/swarma-identity"}, 25000))
	return f
}

// Claim: keychain sign shows every grant field, every digest and every
// seal-spend input, output, amount and the fee on the terminal, takes the
// confirmation, and only after both reads the secret, once per signature.
// The returned signatures are the ones PR 8's grant sign accepts: the grant
// signature completes the issuance, and the seal-spend signature executes.
func TestKeychainSignShowsEveryFieldBeforeKeyRead(t *testing.T) {
	f := preparedFlow(t)
	h := newKC(t, confirmWord)
	r := fullRequest(t, f)
	e, code := h.sign(r)
	mustOK(t, e, code)
	if e.Network != "regtest" {
		t.Fatalf("network %q", e.Network)
	}
	shown := h.term.shown.String()
	d := r.Draft
	for _, want := range []string{d.LandlordName, d.AgentName, d.GranteeKey, d.IssuerKey, "instruct", "land", "spend", "https://github.com/relux-works/swarma-identity", "pay", "repository.push",
		"25000 sat", fmt.Sprint(d.NotBefore), fmt.Sprint(d.NotAfter), utc(d.NotAfter), d.ContractSHA256, fmt.Sprintf("%s:%d", d.Seal.TxID, d.Seal.Vout),
		PurposeContract, PurposeGrant, f.stage1.GrantSigningHash, "99000 sat", "60000 sat", "39000 sat", "100000 sat", "fee              : 1000 sat", "SIGNED BY THIS KEY", strings.Repeat("77", 32) + ":0"} {
		if !strings.Contains(shown, want) {
			t.Fatalf("terminal display lacks %q", want)
		}
	}
	first := -1
	for i, ev := range h.log {
		if strings.HasPrefix(ev, "secret:") {
			first = i
			break
		}
	}
	if first < 2 || h.log[0] != "public:"+kcLabel || !strings.Contains(strings.Join(h.log[:first], ","), "show,confirm") {
		t.Fatalf("key read before display and confirmation: %v", h.log)
	}
	if h.count("secret:") != 3 {
		t.Fatalf("%d secret reads for 3 signatures", h.count("secret:"))
	}
	res := resultAs[KeychainSignResult](t, e)
	if len(res.Signatures) != 2 || res.SealSpend == nil || res.Key.XOnlyKey != d.IssuerKey {
		t.Fatalf("result %+v", res)
	}
	// The keychain landlord_sig and grant signature complete PR 8's flow.
	landlordSig := res.Signatures[0].Signature
	if !sigValid(d.IssuerKey, d.ContractSHA256, landlordSig) {
		t.Fatal("landlord_sig does not verify")
	}
	e, code = f.signCmd(GrantSignRequest{Schema: GrantSignSchema, Draft: d, ConsentEvent: f.consent.ConsentEvent, LandlordSig: f.landlordSig, GrantSig: res.Signatures[1].Signature})
	mustOK(t, e, code)
	if resultAs[GrantSignResult](t, e).Stage != "signed" {
		t.Fatal("grant not signed")
	}
	// The seal-spend signature executes as the P2PKH input script.
	tx, _ := sealSpendFor(t, d, landlordP2PKH(t))
	sig, _ := hex.DecodeString(res.SealSpend.Signature)
	pub, _ := hex.DecodeString(res.Key.CompressedPubkey)
	tx.TxIn[1].SignatureScript, _ = txscript.NewScriptBuilder().AddData(sig).AddData(pub).Script()
	vm, err := txscript.NewEngine(landlordP2PKH(t), tx, 1, txscript.StandardVerifyFlags, nil, nil, 99000, txscript.NewCannedPrevOutputFetcher(landlordP2PKH(t), 99000))
	if err != nil || vm.Execute() != nil {
		t.Fatal("seal-spend signature does not execute")
	}
}

// Claim: anything but the exact confirmation word declines with
// CONFIRMATION_DECLINED after the display and before any secret read.
func TestKeychainSignDeclined(t *testing.T) {
	f := preparedFlow(t)
	for _, answer := range []string{"", "no", "sign", "SIGN ", "yes"} {
		h := newKC(t, answer)
		e, code := h.sign(fullRequest(t, f))
		mustRefuse(t, e, code, "CONFIRMATION_DECLINED")
		if h.count("show") != 1 || h.count("secret:") != 0 {
			t.Fatalf("answer %q: %v", answer, h.log)
		}
	}
}

// Claim: a requested digest that is not re-derived from the shown draft, a
// key that is not the Keychain key, and a purpose the landlord key does not
// sign are refused before anything is shown or any secret is read. Each
// negative changes one member of the valid request used as positive control
// in TestKeychainSignShowsEveryFieldBeforeKeyRead.
func TestKeychainSignRefusesUnboundDigest(t *testing.T) {
	f := preparedFlow(t)
	flip := func(s string) string { return strings.Repeat("0", 63) + string("10"[strings.Count(s[63:], "0")]) }
	cases := []struct {
		name, want string
		edit       func(*KeychainSignRequest)
	}{
		{"contract-digest", "DIGEST_BINDING", func(r *KeychainSignRequest) { r.ToSign[0].Digest = flip(r.ToSign[0].Digest) }},
		{"grant-digest", "DIGEST_BINDING", func(r *KeychainSignRequest) { r.ToSign[1].Digest = r.Draft.ContractSHA256 }},
		{"grant-without-consent", "DIGEST_BINDING", func(r *KeychainSignRequest) { r.ConsentEvent = nil }},
		{"grant-forged-landlord-sig", "LANDLORD_SIGNATURE", func(r *KeychainSignRequest) { r.LandlordSig = strings.Repeat("ab", 64) }},
		{"consent-purpose", "DIGEST_BINDING", func(r *KeychainSignRequest) {
			r.ToSign[0] = digestSigner("landlord", r.Draft.IssuerKey, PurposeConsent, r.Draft.ConsentTemplate.ID)
		}},
		{"grantee-signer", "DIGEST_BINDING", func(r *KeychainSignRequest) { r.ToSign[0].Signer = "grantee" }},
		{"duplicate-purpose", "DIGEST_BINDING", func(r *KeychainSignRequest) { r.ToSign[1] = r.ToSign[0] }},
		{"foreign-key-entry", "DIGEST_BINDING", func(r *KeychainSignRequest) { r.ToSign[0].Key = testsigner_public(t, keyOther) }},
		{"draft-issuer-not-keychain-key", "KEY_MISMATCH", func(r *KeychainSignRequest) { r.Draft.IssuerKey = testsigner_public(t, keyRotated) }},
		{"draft-tampered", "CONTRACT_HASH", func(r *KeychainSignRequest) { r.Draft.ContractSHA256 = flip(r.Draft.ContractSHA256) }},
		{"nothing-to-sign", "BAD_INPUT", func(r *KeychainSignRequest) { r.ToSign = []SigningDigest{}; r.SealSpend = nil }},
		{"wrong-schema", "BAD_INPUT", func(r *KeychainSignRequest) { r.Schema = GrantSignSchema }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newKC(t, confirmWord)
			r := fullRequest(t, f)
			c.edit(&r)
			e, code := h.sign(r)
			mustRefuse(t, e, code, c.want)
			if h.count("show") != 0 || h.count("secret:") != 0 {
				t.Fatalf("refused request reached the display or the key: %v", h.log)
			}
		})
	}
}

// Claim: the seal spend is refused before display when the signed input is
// not the draft's seal, its prevout is not P2PKH to the Keychain key, the
// outputs exceed the inputs, an input is already signed, the prevouts do not
// match the inputs, or both or neither encodings are given; a PSBT carrying
// full previous transactions is the positive control and signs.
func TestKeychainSealSpendNegatives(t *testing.T) {
	f := preparedFlow(t)
	script := landlordP2PKH(t)
	reencode := func(tx *wire.MsgTx) string {
		var b bytes.Buffer
		tx.SerializeNoWitness(&b)
		return hex.EncodeToString(b.Bytes())
	}
	cases := []struct {
		name, want string
		edit       func(*SealSpend, *wire.MsgTx)
	}{
		{"other-outpoint", "SEAL_OUTPOINT_MISMATCH", func(s *SealSpend, tx *wire.MsgTx) { s.InputIndex = 0 }},
		{"not-landlord-script", "SEAL_SCRIPT_MISMATCH", func(s *SealSpend, tx *wire.MsgTx) {
			s.Prevouts[1].ScriptHex = hex.EncodeToString(p2pkhScript(make([]byte, 33)))
		}},
		{"outputs-exceed-inputs", "SEAL_SPEND_AMOUNT", func(s *SealSpend, tx *wire.MsgTx) { s.Prevouts[1].AmountSat = 90000 }},
		{"negative-amount", "SEAL_SPEND_PREVOUTS", func(s *SealSpend, tx *wire.MsgTx) { s.Prevouts[0].AmountSat = -1 }},
		{"already-signed", "SEAL_SPEND_SIGNED", func(s *SealSpend, tx *wire.MsgTx) {
			tx.TxIn[0].SignatureScript = []byte{txscript.OP_TRUE}
			s.TxHex = reencode(tx)
		}},
		{"prevout-count", "SEAL_SPEND_PREVOUTS", func(s *SealSpend, tx *wire.MsgTx) { s.Prevouts = s.Prevouts[:1] }},
		{"index-out-of-range", "SEAL_SPEND_SHAPE", func(s *SealSpend, tx *wire.MsgTx) { s.InputIndex = 2 }},
		{"trailing-bytes", "SEAL_SPEND_ENCODING", func(s *SealSpend, tx *wire.MsgTx) { s.TxHex += "00" }},
		{"both-encodings", "BAD_INPUT", func(s *SealSpend, tx *wire.MsgTx) { s.PSBT = "cHNidP8=" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newKC(t, confirmWord)
			r := fullRequest(t, f)
			tx, spend := sealSpendFor(t, r.Draft, script)
			c.edit(&spend, tx)
			r.SealSpend = &spend
			e, code := h.sign(r)
			mustRefuse(t, e, code, c.want)
			if h.count("show") != 0 || h.count("secret:") != 0 {
				t.Fatalf("refused spend reached the display or the key: %v", h.log)
			}
		})
	}
	t.Run("psbt-positive", func(t *testing.T) {
		h := newKC(t, confirmWord)
		r := fullRequest(t, f)
		tx, _ := sealSpendFor(t, r.Draft, script)
		// Previous transactions whose hashes are the outpoints' txids.
		prevA := wire.NewMsgTx(2)
		prevA.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, 0), nil, nil))
		prevA.AddTxOut(wire.NewTxOut(1000, script))
		prevB := wire.NewMsgTx(2)
		prevB.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{1}, 0), nil, nil))
		for i := uint32(0); i <= r.Draft.Seal.Vout; i++ {
			prevB.AddTxOut(wire.NewTxOut(99000, script))
		}
		tx.TxIn[0].PreviousOutPoint = *wire.NewOutPoint(ptr(prevA.TxHash()), 0)
		tx.TxIn[1].PreviousOutPoint = *wire.NewOutPoint(ptr(prevB.TxHash()), r.Draft.Seal.Vout)
		r.Draft = withSeal(t, f, prevB.TxHash().String())
		r.ToSign = []SigningDigest{digestSigner("landlord", r.Draft.IssuerKey, PurposeContract, r.Draft.ContractSHA256)}
		p, err := psbt.NewFromUnsignedTx(tx)
		if err != nil {
			t.Fatal(err)
		}
		p.Inputs[0].NonWitnessUtxo = prevA
		p.Inputs[1].NonWitnessUtxo = prevB
		var b bytes.Buffer
		if err := p.Serialize(&b); err != nil {
			t.Fatal(err)
		}
		r.SealSpend = &SealSpend{PSBT: base64.StdEncoding.EncodeToString(b.Bytes()), InputIndex: 1}
		e, code := h.sign(r)
		mustOK(t, e, code)
		if !strings.Contains(h.term.shown.String(), "txids verified") || h.count("secret:") != 2 {
			t.Fatalf("psbt spend: %v", h.log)
		}
		// A PSBT whose previous transaction does not hash to the outpoint is refused.
		p.Inputs[1].NonWitnessUtxo = prevA
		b.Reset()
		p.Serialize(&b)
		r.SealSpend.PSBT = base64.StdEncoding.EncodeToString(b.Bytes())
		h2 := newKC(t, confirmWord)
		e, code = h2.sign(r)
		mustRefuse(t, e, code, "SEAL_SPEND_PREVOUTS")
	})
}

func ptr(h chainhash.Hash) *chainhash.Hash { return &h }

// withSeal re-drafts the same grant on another seal outpoint.
func withSeal(t *testing.T, f *flow, txid string) GrantDraft {
	r := f.draftReq
	r.Seal = rental.Point{TxID: txid, Vout: r.Seal.Vout}
	e, code := f.draftCmd(r)
	mustOK(t, e, code)
	return resultAs[GrantDraftResult](t, e).Draft
}

// captureFDs runs fn with the process's stdout and stderr file descriptors
// redirected to a file, so a direct print from any package (Go or C) is
// seen, and returns what was written there.
func captureFDs(t *testing.T, fn func()) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fds")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	saved := [2]int{}
	for i, fd := range []int{1, 2} {
		if saved[i], err = unix.Dup(fd); err != nil {
			t.Fatal(err)
		}
		if err := unix.Dup2(int(f.Fd()), fd); err != nil {
			t.Fatal(err)
		}
	}
	fn()
	for i, fd := range []int{1, 2} {
		unix.Dup2(saved[i], fd)
		unix.Close(saved[i])
	}
	b, _ := os.ReadFile(path)
	return b
}

// Claim: no encoding of the key's secret appears in any stdout envelope,
// diagnostic stream, terminal display or anything written to the process's
// stdout/stderr descriptors across keygen, sign and refusals. Limit: the
// encodings secretEncodings lists; TestSecretGrepControl proves the scanner.
func TestKeychainOutputsNeverCarrySecret(t *testing.T) {
	f := preparedFlow(t)
	h := newKC(t, confirmWord)
	signer := keysign.NewWithStore(h.store, fixedReader(mustDecode(bip340Secrets[keyGrantee])))
	h.deps.signer = signer
	direct := captureFDs(t, func() {
		e, code := h.run("keychain", "keygen", "--label", "fresh-key", "--network", "regtest")
		mustOK(t, e, code)
		pub := resultAs[KeychainPublic](t, e)
		if pub.XOnlyKey != testsigner_public(t, keyGrantee) || !strings.HasPrefix(pub.P2PKHAddress, "m") && !strings.HasPrefix(pub.P2PKHAddress, "n") {
			t.Fatalf("keygen public data %+v", pub)
		}
		e, code = h.run("keychain", "keygen", "--label", "fresh-key")
		mustRefuse(t, e, code, "KEY_EXISTS")
		e, code = h.sign(fullRequest(t, f))
		mustOK(t, e, code)
		h.term.answer = "no"
		e, code = h.sign(fullRequest(t, f))
		mustRefuse(t, e, code, "CONFIRMATION_DECLINED")
	})
	assertNoSecrets(t, append(h.blobs, direct))
	if s, ok := h.store.SecretOf("fresh-key"); !ok || hex.EncodeToString(s[:]) != bip340Secrets[keyGrantee] {
		t.Fatal("keygen did not store the drawn secret")
	}
}

func mustDecode(s string) []byte { b, _ := hex.DecodeString(s); return b }

// Claim: keygen prints exactly the public data (label, network, x-only key,
// compressed key, P2PKH address) and refuses a bad label or network before
// touching the store; swarma-identity itself refuses both keychain commands
// with UNSUPPORTED_CAPABILITY because it links no signer.
func TestKeychainKeygenAndCapability(t *testing.T) {
	h := newKC(t, confirmWord)
	h.deps.signer = keysign.NewWithStore(h.store, fixedReader(mustDecode(bip340Secrets[keyRotated])))
	e, code := h.run("keychain", "keygen", "--label", "rotated")
	mustOK(t, e, code)
	var members map[string]any
	b, _ := json.Marshal(e.Result)
	json.Unmarshal(b, &members)
	if len(members) != 5 || e.Network != "main" {
		t.Fatalf("keygen result members %v", members)
	}
	pub := resultAs[KeychainPublic](t, e)
	if pub.XOnlyKey != testsigner_public(t, keyRotated) || !strings.HasPrefix(pub.P2PKHAddress, "M") && !strings.HasPrefix(pub.P2PKHAddress, "N") {
		t.Fatalf("keygen %+v", pub)
	}
	before := len(h.log)
	for _, args := range [][]string{{"--label", "Bad"}, {"--label", "x", "--network", "bitcoin"}, {"--label", "x", "--label", "y"}, {"--label"}, {"x"}} {
		e, code := h.run(append([]string{"keychain", "keygen"}, args...)...)
		mustRefuse(t, e, code, "BAD_INPUT")
	}
	if len(h.log) != before {
		t.Fatal("malformed keygen reached the store")
	}
	var out, diag bytes.Buffer
	if code := Run(context.Background(), []string{"keychain", "keygen", "--label", "x", "--json"}, &out, &diag); code != 3 || !strings.Contains(out.String(), "UNSUPPORTED_CAPABILITY") {
		t.Fatalf("swarma-identity keygen: %d %s", code, out.String())
	}
	out.Reset()
	if code := RunKeychain(context.Background(), []string{"grant", "draft", "--json"}, &out, &diag, nil); code != 2 {
		t.Fatalf("swarma-keychain admitted a non-keychain command: %d", code)
	}
}

// Claim: the swarma-identity binary links neither the signer, the Keychain
// store nor any test double, and swarma-keychain links the signer but no
// test double. The control half shows the listing sees keysign where it is
// linked.
func TestKeychainBinaryClosure(t *testing.T) {
	o, _ := controlScratch(t, "keychain-closure-")
	mod := "github.com/relux-works/swarma-identity/internal/"
	identity := string(o.goCommand(t, "deps-identity", "list", "-mod=readonly", "-deps", "./cmd/swarma-identity"))
	for _, p := range []string{"keysign", "keychain", "keychain/keychainfake", "testsigner"} {
		// facade must not even import the store package.
		if strings.Contains(identity, mod+p+"\n") {
			t.Fatalf("swarma-identity links %s", p)
		}
	}
	signer := string(o.goCommand(t, "deps-keychain", "list", "-mod=readonly", "-deps", "./cmd/swarma-keychain"))
	if !strings.Contains(signer, mod+"keysign\n") || !strings.Contains(signer, mod+"keychain\n") {
		t.Fatal("control: swarma-keychain listing does not show the signer")
	}
	for _, p := range []string{"keychain/keychainfake", "testsigner"} {
		if strings.Contains(signer, mod+p+"\n") {
			t.Fatalf("swarma-keychain links %s", p)
		}
	}
}

var _ = errors.New

func p2pkhPub(secret []byte) []byte {
	_, pub := btcec.PrivKeyFromBytes(secret)
	return pub.SerializeCompressed()
}

// DecodeStrictEnvelope decodes one CLI envelope.
func DecodeStrictEnvelope(b []byte, e *Envelope) error { return json.Unmarshal(b, e) }
