package facade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// setLedgerHook installs the ledger step hook for one test. No facade test
// runs in parallel, so the package-level hook is never shared between tests.
func setLedgerHook(t *testing.T, hook func(step string) error) {
	t.Helper()
	ledgerHook = hook
	t.Cleanup(func() { ledgerHook = nil })
}

// sealFixture prepares three final sign requests on one flow: A and C on
// sealA (different grants), B on sealB. Nothing is recorded yet.
func sealFixture(t *testing.T, f *flow) (a, b, c GrantSignRequest) {
	t.Helper()
	reqA := regtestRequest([]string{"instruct"}, []string{}, 0)
	f.prepare(reqA)
	a = f.finalRequest()
	reqB := reqA
	reqB.Seal.TxID = sealB
	reqB.Note = "second grant on a fresh seal"
	f.prepare(reqB)
	b = f.finalRequest()
	reqC := reqA
	reqC.Note = "different grant on the recorded seal"
	f.prepare(reqC)
	c = f.finalRequest()
	return a, b, c
}

// ledgerTemps lists the temporary-file names beside the ledger: every name
// that starts with ".<ledger name>.tmp".
func ledgerTemps(t *testing.T, ledger string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(ledger))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "."+filepath.Base(ledger)+".tmp") {
			names = append(names, e.Name())
		}
	}
	return names
}

func readLedger(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Claim: a failed ledger update never loses a committed seal. After grant A
// is recorded, an ENOSPC on B's write, or a failure just before B's commit
// rename, refuses B as LEDGER_FILE, leaves the ledger byte-identical with no
// temporary file behind, and a different grant C on A's seal still refuses
// SEAL_REUSED. Neighbours: B issues once the fault is gone, both seals are
// then recorded, and re-signing A stays idempotent.
// Limit: the faults are injected at the ledger's own step hook, not by the
// kernel; the reviewer's strace reproduction covers a real pwrite64 ENOSPC.
func TestSealLedgerWriteFailureKeepsHistory(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	a, b, c := sealFixture(t, f)
	e, code := f.signCmd(a)
	mustOK(t, e, code)
	idA := resultAs[GrantSignResult](t, e).GrantID
	e, code = f.signCmd(c)
	mustRefuse(t, e, code, "SEAL_REUSED")
	committed := readLedger(t, f.ledger)

	for _, step := range []string{"write", "rename"} {
		setLedgerHook(t, func(s string) error {
			if s == step {
				return syscall.ENOSPC
			}
			return nil
		})
		e, code = f.signCmd(b)
		mustRefuse(t, e, code, "LEDGER_FILE")
		ledgerHook = nil
		if got, _ := os.ReadFile(f.ledger); !bytes.Equal(got, committed) {
			t.Fatalf("a failed %s step changed the committed ledger", step)
		}
		if left := ledgerTemps(t, f.ledger); len(left) != 0 {
			t.Fatalf("a failed %s step left its temporary file %v", step, left)
		}
		e, code = f.signCmd(c)
		mustRefuse(t, e, code, "SEAL_REUSED")
	}

	e, code = f.signCmd(b) // neighbour: B on its fresh seal, no fault
	mustOK(t, e, code)
	idB := resultAs[GrantSignResult](t, e).GrantID
	after := readLedger(t, f.ledger)
	if !bytes.Contains(after, []byte(idA)) || !bytes.Contains(after, []byte(idB)) {
		t.Fatal("ledger does not hold both recorded seals")
	}
	e, code = f.signCmd(a) // neighbour: A again, idempotent
	mustOK(t, e, code)
	if !bytes.Equal(readLedger(t, f.ledger), after) {
		t.Fatal("idempotent re-sign changed the ledger")
	}
	e, code = f.signCmd(c)
	mustRefuse(t, e, code, "SEAL_REUSED")
}

// Claim: an existing ledger that is empty or truncated, which is what an
// in-place rewrite interrupted after its truncate leaves, is refused as
// LEDGER_FILE by draft and by both sign stages, for the reused seal and for a
// fresh one, and nothing is recorded; only a missing ledger reads as new. An
// update interrupted after writing its temporary file leaves the committed
// ledger in force: C still refuses SEAL_REUSED, and B issues and removes the
// stale temporary file.
// Limit: the interrupted states are planted on disk, not produced by killing
// a process mid-update.
func TestSealLedgerInterruptedUpdate(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	a, b, c := sealFixture(t, f)
	e, code := f.signCmd(a)
	mustOK(t, e, code)
	committed := readLedger(t, f.ledger)

	for _, tc := range []struct {
		name string
		raw  []byte
	}{{"post-truncate-empty", nil}, {"truncated-prefix", committed[:len(committed)/2]}} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(f.ledger, tc.raw, 0600); err != nil {
				t.Fatal(err)
			}
			for _, req := range []GrantSignRequest{c, b} {
				e, code := f.signCmd(req)
				mustRefuse(t, e, code, "LEDGER_FILE")
				stage1 := req
				stage1.GrantSig = ""
				e, code = f.signCmd(stage1)
				mustRefuse(t, e, code, "LEDGER_FILE")
			}
			e, code := f.draftCmd(f.draftReq)
			mustRefuse(t, e, code, "LEDGER_FILE")
			if !bytes.Equal(readLedger(t, f.ledger), tc.raw) {
				t.Fatal("a refused sign rewrote a damaged ledger")
			}
		})
	}

	// An interrupted update of the current design: the committed ledger plus a
	// partial temporary file.
	if err := os.WriteFile(f.ledger, committed, 0600); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(filepath.Dir(f.ledger), ".seal-ledger.json.tmp-00112233445566ff")
	if err := os.WriteFile(stale, committed[:7], 0600); err != nil {
		t.Fatal(err)
	}
	e, code = f.signCmd(c)
	mustRefuse(t, e, code, "SEAL_REUSED")
	e, code = f.signCmd(b) // neighbour: B issues over the stale temporary file
	mustOK(t, e, code)
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatal("stale temporary file survived a committed update")
	}
	e, code = f.signCmd(c)
	mustRefuse(t, e, code, "SEAL_REUSED")

	// Neighbour: a missing ledger is a new ledger, and B issues there.
	f.ledger = filepath.Join(canonicalTemp(t), "new-ledger.json")
	e, code = f.signCmd(b)
	mustOK(t, e, code)
}

// Claim: the ledger directory checked at open is the one the issuance uses.
// A parent directory replaced by a symlink to an empty directory, or by a new
// real directory, after the walk and before the lock refuses as LEDGER_FILE;
// replaced after the lock, the issuance stays bound to the original
// directory and still refuses SEAL_REUSED. Either way nothing is written to
// the substitute directory and the original ledger is unchanged. Neighbour:
// with the hook observing but not substituting, re-signing A succeeds.
// Limit: the substitution runs at the ledger's step hook in-process; the
// reviewer's strace reproduction delays a real openat instead.
func TestSealLedgerParentSubstitution(t *testing.T) {
	for _, tc := range []struct {
		name, step string
		symlink    bool
		want       string
	}{
		{"symlink-before-lock", "walked", true, "LEDGER_FILE"},
		{"directory-before-lock", "walked", false, "LEDGER_FILE"},
		{"symlink-after-lock", "locked", true, "SEAL_REUSED"},
		{"stable", "", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
			root := canonicalTemp(t)
			parent, parked, outside := filepath.Join(root, "parent"), filepath.Join(root, "parked"), filepath.Join(root, "outside")
			if os.Mkdir(parent, 0700) != nil || os.Mkdir(outside, 0700) != nil {
				t.Fatal("mkdir fixture")
			}
			f.ledger = filepath.Join(parent, "ledger.json")
			a, _, c := sealFixture(t, f)
			e, code := f.signCmd(a)
			mustOK(t, e, code)
			committed := readLedger(t, f.ledger)
			fired := false
			setLedgerHook(t, func(step string) error {
				if step != tc.step || fired {
					return nil
				}
				fired = true
				if err := os.Rename(parent, parked); err != nil {
					return err
				}
				if tc.symlink {
					return os.Symlink(outside, parent)
				}
				return os.Mkdir(parent, 0700)
			})
			if tc.want == "" {
				e, code = f.signCmd(a)
				mustOK(t, e, code)
				return
			}
			e, code = f.signCmd(c)
			if !fired {
				t.Fatal("substitution did not run")
			}
			mustRefuse(t, e, code, tc.want)
			for _, dir := range []string{outside, parent} {
				if entries, err := os.ReadDir(dir); err == nil && len(entries) != 0 {
					t.Fatalf("substitute directory written: %s", entries[0].Name())
				}
			}
			if !bytes.Equal(readLedger(t, filepath.Join(parked, "ledger.json")), committed) {
				t.Fatal("original ledger changed")
			}
		})
	}
}

// Claim: the directory walk refuses relative, unclean and dot paths and a
// symlink at any directory component, and opens a plain absolute path.
func TestOpenLedgerDir(t *testing.T) {
	root := canonicalTemp(t)
	if os.MkdirAll(filepath.Join(root, "a", "b"), 0700) != nil || os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "link")) != nil {
		t.Fatal("fixture")
	}
	for _, path := range []string{"", "rel/ledger.json", root + "/a/../a/b/ledger.json", root + "/a//b/ledger.json", "/", root + "/link/b/ledger.json", root + "/a/b/missing/ledger.json"} {
		if fd, _, err := openLedgerDir(path); err == nil {
			syscall.Close(fd)
			t.Fatalf("walk accepted %q", path)
		}
	}
	fd, name, err := openLedgerDir(root + "/a/b/ledger.json")
	if err != nil || name != "ledger.json" {
		t.Fatalf("walk refused a plain path: %v", err)
	}
	syscall.Close(fd)
	if _, _, err := openLedgerDir(root + "/link/b/ledger.json"); !errors.Is(err, syscall.ELOOP) && !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("symlinked component refused for another reason: %v", err)
	}
}

// Review witness: an explicit empty grant_id in an existing entry is invalid
// ledger state, not evidence that the referenced seal is unused. A valid
// committed control refuses another grant; rejection must preserve disk bytes.
func TestReviewPR8EmptyGrantID(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	a, _, c := sealFixture(t, f)
	e, code := f.signCmd(a)
	mustOK(t, e, code)
	id := resultAs[GrantSignResult](t, e).GrantID
	e, code = f.signCmd(c)
	mustRefuse(t, e, code, "SEAL_REUSED")
	committed := readLedger(t, f.ledger)
	if bytes.Count(committed, []byte(id)) != 1 {
		t.Fatal("witness setup: grant id not unique")
	}
	bad := bytes.Replace(committed, []byte(id), nil, 1)
	if err := os.WriteFile(f.ledger, bad, 0600); err != nil {
		t.Fatal(err)
	}
	e, code = f.signCmd(c)
	if code == 0 || e.OK || e.Error == nil || e.Error.Code != "LEDGER_FILE" || e.Result != nil {
		t.Errorf("invalid ledger grant_id must refuse LEDGER_FILE without result: exit%d ok=%t error=%v", code, e.OK, e.Error)
	}
	if !bytes.Equal(readLedger(t, f.ledger), bad) {
		t.Error("refused invalid ledger was modified: reused seal received another grant")
	}
}

// Review witness: a caller with an expired deadline cannot wait indefinitely
// on another writer's ledger flock. Hold only our fixture lock; after the
// 16-second observation release it and join the call so no goroutine is left.
func TestReviewPR8LedgerLockDeadline(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	f.prepare(regtestRequest([]string{"instruct"}, []string{}, 0))
	req := f.finalRequest()
	e, code := f.signCmd(req)
	mustOK(t, e, code)
	before := readLedger(t, f.ledger)
	held, failure := openSealLedger(context.Background(), f.ledger, true)
	if failure != nil {
		t.Fatalf("fixture lock: %v", failure)
	}
	defer held.close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	args := []string{"grant", "sign", "--config", f.node.config, "--request", writeInput(t, req), "--seal-ledger", f.ledger, "--json"}
	type outcome struct {
		code     int
		envelope Envelope
	}
	done := make(chan outcome, 1)
	go func() {
		var out, errout bytes.Buffer
		code := Run(ctx, args, &out, &errout)
		var e Envelope
		_ = json.Unmarshal(out.Bytes(), &e)
		done <- outcome{code, e}
	}()
	var got outcome
	finished := false
	select {
	case got = <-done:
		finished = true
	case <-time.After(16 * time.Second):
		t.Error("grant sign exceeded 15-second total bound while waiting on ledger flock despite expired caller deadline")
	}
	held.close()
	if !finished {
		select {
		case got = <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("call did not finish after releasing fixture lock")
		}
	}
	if got.code == 0 || got.envelope.OK || got.envelope.Result != nil || got.envelope.Error == nil || (got.envelope.Error.Code != "LEDGER_FILE" && got.envelope.Error.Code != "RPC_UNAVAILABLE") {
		t.Errorf("deadline outcome was not the intended closed refusal: exit%d error=%v", got.code, got.envelope.Error)
	}
	if !bytes.Equal(readLedger(t, f.ledger), before) {
		t.Error("deadline call changed ledger")
	}
}
