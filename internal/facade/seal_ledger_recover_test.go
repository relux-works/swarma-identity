package facade

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func (f *flow) recoverRun() (Envelope, int) {
	return f.run("grant", "ledger-recover", "--seal-ledger", f.ledger)
}

// recoverCmd runs grant ledger-recover and requires it to succeed.
func (f *flow) recoverCmd() LedgerRecoverResult {
	f.t.Helper()
	e, code := f.recoverRun()
	mustOK(f.t, e, code)
	return resultAs[LedgerRecoverResult](f.t, e)
}

// interruptedExchange issues A and then builds, with the product lock and the
// real exchange syscall, the state of a writer stopped between exchanging a
// foreign temporary file (one entry on seal B for another grant id) with the
// ledger and its undo, as hadar's witness does. It returns A's grant id, the
// ledger bytes after A, the foreign ledger bytes and the temporary path, which
// holds the previous ledger.
func interruptedExchange(t *testing.T, f *flow, a GrantSignRequest) (idA string, before, foreign []byte, tmpPath string) {
	t.Helper()
	idA = grantIDOf(t, f.signRun(context.Background(), a))
	before = readLedger(t, f.ledger)
	held, failure := openSealLedger(context.Background(), f.ledger, true)
	if failure != nil {
		t.Fatalf("fixture lock: %v", failure)
	}
	defer held.close()
	other := "ab" + idA[2:]
	if other == idA {
		other = "cd" + idA[2:]
	}
	foreign, _ = json.Marshal(sealLedgerFile{SealLedgerSchema, []SealEntry{{sealB, 1, other}}})
	tmp := held.tempPrefix() + "0102030405060708"
	tmpPath = filepath.Join(filepath.Dir(f.ledger), tmp)
	if err := os.WriteFile(tmpPath, foreign, 0600); err != nil {
		t.Fatal(err)
	}
	if err := exchangeAt(held.dir, tmp, held.name); err != nil {
		t.Fatalf("fixture exchange: %v", err)
	}
	if !bytes.Equal(readLedger(t, tmpPath), before) || !bytes.Equal(readLedger(t, f.ledger), foreign) {
		t.Fatal("fixture is not the stopped-before-undo state")
	}
	return idA, before, foreign, tmpPath
}

func ledgerEntries(t *testing.T, path string) []SealEntry {
	t.Helper()
	var doc sealLedgerFile
	if err := DecodeStrict(readLedger(t, path), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Seals
}

func hasEntry(entries []SealEntry, e SealEntry) bool {
	for _, x := range entries {
		if x == e {
			return true
		}
	}
	return false
}

// Claim: in the stopped-before-undo state (previous ledger under the
// temporary name, a foreign ledger under the ledger name), the final sign of
// C on A's seal, its grant_hash stage, a fresh seal's sign and the draft all
// refuse LEDGER_FILE with the recovery message before reading the ledger, and
// the ledger name and the temporary file keep their bytes. grant
// ledger-recover then restores A by the union with the foreign entry, removes
// the leftover, and C refuses SEAL_REUSED while re-signing A stays
// idempotent; a second recover finds nothing. Neighbour: the same flow
// without a leftover issues normally.
// Limit: the interrupted state is built with the real exchange under the real
// lock, not by killing a process.
func TestSealLedgerRecoverInterruptedExchange(t *testing.T) {
	normal := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	na, nb, nc := sealFixture(t, normal)
	grantIDOf(t, normal.signRun(context.Background(), na))
	grantIDOf(t, normal.signRun(context.Background(), nb))
	if got := normal.signRun(context.Background(), nc); !refusedWith(got, "SEAL_REUSED") {
		t.Fatalf("normal path: C on A's seal: exit %d %+v", got.code, got.envelope.Error)
	}

	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	a, _, c := sealFixture(t, f)
	idA, before, foreign, tmpPath := interruptedExchange(t, f, a)
	stage1 := c
	stage1.GrantSig = ""
	fresh := f.draftReq
	fresh.Seal.TxID = "7777777777777777777777777777777777777777777777777777777777777777"
	for name, run := range map[string]func() (Envelope, int){
		"final-sign":  func() (Envelope, int) { return f.signCmd(c) },
		"grant-hash":  func() (Envelope, int) { return f.signCmd(stage1) },
		"fresh-draft": func() (Envelope, int) { return f.draftCmd(fresh) },
	} {
		e, code := run()
		mustRefuse(t, e, code, "LEDGER_FILE")
		if e.Error.Message != ledgerRecoveryMessage {
			t.Fatalf("%s: fence refusal without the recovery message: %q", name, e.Error.Message)
		}
		if !bytes.Equal(readLedger(t, tmpPath), before) || !bytes.Equal(readLedger(t, f.ledger), foreign) {
			t.Fatalf("%s: a fenced command changed the ledger or the leftover", name)
		}
	}

	got := f.recoverCmd()
	entries := ledgerEntries(t, f.ledger)
	if !hasEntry(entries, SealEntry{sealA, 1, idA}) || len(entries) != 2 {
		t.Fatalf("recover lost the prior history: %+v", entries)
	}
	if got.Restored != 1 || got.Removed != 1 || got.Seals != 2 {
		t.Fatalf("recover result: %+v", got)
	}
	if _, err := os.Lstat(tmpPath); !os.IsNotExist(err) {
		t.Fatal("recover kept the leftover after restoring it")
	}
	if got := f.signRun(context.Background(), c); !refusedWith(got, "SEAL_REUSED") {
		t.Fatalf("reused seal after recover: exit %d %+v", got.code, got.envelope.Error)
	}
	if again := grantIDOf(t, f.signRun(context.Background(), a)); again != idA {
		t.Fatal("re-signing A after recover changed its grant id")
	}
	if again := f.recoverCmd(); again != (LedgerRecoverResult{2, 0, 0}) {
		t.Fatalf("second recover: %+v", again)
	}
}

// Claim: recover refuses, and leaves the ledger and every leftover byte for
// byte in place so the fence keeps holding, when a leftover ledger maps A's
// seal to another grant id or A's grant id to another seal
// (LEDGER_RECOVERY_CONFLICT), when a leftover is neither empty, a ledger nor
// a torn write of one (LEDGER_FILE), including a torn write that adds two
// entries, and when a leftover is not an owner-only regular file. Positive
// controls: an empty leftover, a torn prefix of the ledger, a torn write one
// entry past it, and a leftover ledger that is a subset of the ledger are
// removed with nothing restored; with no ledger, a leftover ledger is
// restored as the first record, after which C on A's seal refuses SEAL_REUSED
// and B issues. The CLI refuses --request, --config and a missing --json or
// --seal-ledger.
func TestSealLedgerRecoverRefusals(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	a, b, _ := sealFixture(t, f)
	idA := grantIDOf(t, f.signRun(context.Background(), a))
	committed := readLedger(t, f.ledger)
	dir := filepath.Dir(f.ledger)
	left := filepath.Join(dir, ".seal-ledger.json.tmp-a1b2c3d4e5f60718")
	doc := func(e ...SealEntry) []byte { raw, _ := compactJSON(sealLedgerFile{SealLedgerSchema, e}); return raw }
	otherID := "ab" + idA[2:]
	if otherID == idA {
		otherID = "cd" + idA[2:]
	}
	stem := committed[:len(committed)-2]
	entry, _ := compactJSON(SealEntry{sealB, 1, otherID})
	for _, tc := range []struct {
		name string
		raw  []byte
		mode os.FileMode
		want string
	}{
		{"seal-to-other-grant", doc(SealEntry{sealA, 1, otherID}), 0600, "LEDGER_RECOVERY_CONFLICT"},
		{"grant-to-other-seal", doc(SealEntry{sealB, 1, idA}), 0600, "LEDGER_RECOVERY_CONFLICT"},
		{"not-a-ledger", []byte("stale"), 0600, "LEDGER_FILE"},
		{"torn-two-entries", []byte(string(stem) + "," + string(entry) + "," + string(entry[:10])), 0600, "LEDGER_FILE"},
		{"group-readable", doc(SealEntry{sealB, 1, otherID}), 0640, "LEDGER_FILE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(left, tc.raw, tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(left, tc.mode); err != nil {
				t.Fatal(err)
			}
			e, code := f.recoverRun()
			mustRefuse(t, e, code, tc.want)
			if got, err := os.ReadFile(left); err != nil || !bytes.Equal(got, tc.raw) || !bytes.Equal(readLedger(t, f.ledger), committed) {
				t.Fatal("a refused recover changed the ledger or the leftover")
			}
			e, code = f.signCmd(b)
			mustRefuse(t, e, code, "LEDGER_FILE")
			if err := os.Remove(left); err != nil {
				t.Fatal(err)
			}
		})
	}

	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"torn-prefix", committed[:7]},
		{"torn-one-entry-past", []byte(string(stem) + "," + string(entry[:20]))},
		{"subset-ledger", committed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(left, tc.raw, 0600); err != nil {
				t.Fatal(err)
			}
			if got := f.recoverCmd(); got != (LedgerRecoverResult{1, 0, 1}) {
				t.Fatalf("recover result: %+v", got)
			}
			if _, err := os.Lstat(left); !os.IsNotExist(err) || !bytes.Equal(readLedger(t, f.ledger), committed) {
				t.Fatal("recover kept a removable leftover or changed the ledger")
			}
		})
	}

	// No ledger: the leftover holds the only history and becomes the ledger.
	g := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	_, gb, gc := sealFixture(t, g)
	gleft := filepath.Join(filepath.Dir(g.ledger), ".seal-ledger.json.tmp-0011223344556677")
	if err := os.WriteFile(gleft, committed, 0600); err != nil {
		t.Fatal(err)
	}
	if got := g.recoverCmd(); got != (LedgerRecoverResult{1, 1, 1}) {
		t.Fatalf("recover onto a missing ledger: %+v", got)
	}
	if !bytes.Equal(readLedger(t, g.ledger), committed) {
		t.Fatal("recover onto a missing ledger did not restore the leftover's history")
	}
	if got := g.signRun(context.Background(), gc); !refusedWith(got, "SEAL_REUSED") {
		t.Fatalf("reused seal after recover onto a missing ledger: exit %d %+v", got.code, got.envelope.Error)
	}
	grantIDOf(t, g.signRun(context.Background(), gb))

	for _, args := range [][]string{
		{"grant", "ledger-recover", "--json"},
		{"grant", "ledger-recover", "--seal-ledger", f.ledger, "--request", f.ledger, "--json"},
		{"grant", "ledger-recover", "--seal-ledger", f.ledger, "--config", f.node.config, "--json"},
		{"grant", "ledger-recover", "--seal-ledger", f.ledger},
	} {
		e, code, _ := runCLI(t, args...)
		if code == 0 || e.OK || e.Error == nil || (e.Error.Code != "BAD_INPUT" && e.Error.Code != "LEDGER_FILE") {
			t.Fatalf("recover admitted %v", args[2:])
		}
	}
}
