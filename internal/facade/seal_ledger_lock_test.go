package facade

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type signOutcome struct {
	code     int
	envelope Envelope
	elapsed  time.Duration
}

// signRun runs one final "grant sign" through the public dispatcher with the
// given context, so it can run concurrently with another sign.
func (f *flow) signRun(ctx context.Context, req GrantSignRequest) signOutcome {
	args := []string{"grant", "sign", "--config", f.node.config, "--request", writeInput(f.t, req), "--seal-ledger", f.ledger, "--json"}
	var out, errout bytes.Buffer
	start := time.Now()
	code := Run(ctx, args, &out, &errout)
	var e Envelope
	_ = json.Unmarshal(out.Bytes(), &e)
	return signOutcome{code, e, time.Since(start)}
}

func refusedWith(o signOutcome, want string) bool {
	return o.code != 0 && !o.envelope.OK && o.envelope.Result == nil && o.envelope.Error != nil && o.envelope.Error.Code == want
}

func grantIDOf(t *testing.T, o signOutcome) string {
	t.Helper()
	if o.code != 0 || !o.envelope.OK {
		t.Fatalf("command refused: exit %d %+v", o.code, o.envelope.Error)
	}
	return resultAs[GrantSignResult](t, o.envelope).GrantID
}

// Claim: the platform lock is a lock on the directory inode. On a directory
// handle held with LOCK_EX, a second handle's non-blocking attempt fails with
// EWOULDBLOCK, also when that second handle is opened after the directory was
// renamed; after the holder closes, the second handle locks. lockDir with an
// expired context returns without the lock. This runs on the CI's macOS as
// well, which is how the directory-flock semantics are validated there.
func TestSealLedgerDirectoryLockExcludes(t *testing.T) {
	root := canonicalTemp(t)
	dir := filepath.Join(root, "ledger-dir")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	holder, _, err := openLedgerDir(filepath.Join(dir, "seal-ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := lockDir(context.Background(), holder); err != nil {
		t.Fatalf("uncontended lock: %v", err)
	}
	moved := filepath.Join(root, "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	other, _, err := openLedgerDir(filepath.Join(moved, "seal-ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(other)
	if err := unix.Flock(other, unix.LOCK_EX|unix.LOCK_NB); err != unix.EWOULDBLOCK {
		t.Fatalf("second handle on the locked directory: %v, want EWOULDBLOCK", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := lockDir(ctx, other); err == nil {
		t.Fatal("lockDir took a held lock")
	}
	expired, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	unix.Close(holder)
	if err := lockDir(expired, other); err == nil {
		t.Fatal("lockDir ran with an expired context")
	}
	if err := lockDir(context.Background(), other); err != nil {
		t.Fatalf("lock after the holder closed: %v", err)
	}
}

// Claim: replacing a "<ledger>.lock" sidecar while a final sign holds the
// ledger lock does not admit a second writer. Writer 1 (grant A on seal A)
// holds the lock after reading the ledger; the sidecar name is then replaced
// by a fresh file, and writer 2 (a different grant C on seal A) with a
// one-second deadline refuses LEDGER_FILE with no result. Writer 1 commits
// its own record; C then refuses SEAL_REUSED. Neighbour: without the
// substitution the same overlap refuses writer 2 the same way, and a grant B
// on a fresh seal then issues, so both seals stay recorded.
// Limit: the substitution runs at the ledger's step hook in-process.
func TestSealLedgerLockSubstitution(t *testing.T) {
	for _, substitute := range []bool{true, false} {
		f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
		a, b, c := sealFixture(t, f)
		sidecar := f.ledger + ".lock"
		if err := os.WriteFile(sidecar, nil, 0600); err != nil {
			t.Fatal(err)
		}
		var second signOutcome
		var fired atomic.Bool
		setLedgerHook(t, func(step string) error {
			if step != "loaded" || !fired.CompareAndSwap(false, true) {
				return nil
			}
			if substitute {
				if err := os.Rename(sidecar, sidecar+".parked"); err != nil {
					return err
				}
				if err := os.WriteFile(sidecar, nil, 0600); err != nil {
					return err
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			second = f.signRun(ctx, c)
			return nil
		})
		first := f.signRun(context.Background(), a)
		ledgerHook = nil
		if !refusedWith(second, "LEDGER_FILE") {
			t.Fatalf("substitute=%t: both writers ran: second exit %d %+v", substitute, second.code, second.envelope.Error)
		}
		idA := grantIDOf(t, first)
		if !bytes.Contains(readLedger(t, f.ledger), []byte(idA)) {
			t.Fatalf("substitute=%t: the first writer's seal is not recorded", substitute)
		}
		e, code := f.signCmd(c)
		mustRefuse(t, e, code, "SEAL_REUSED")
		e, code = f.signCmd(b)
		mustOK(t, e, code)
		idB := resultAs[GrantSignResult](t, e).GrantID
		after := readLedger(t, f.ledger)
		if !bytes.Contains(after, []byte(idA)) || !bytes.Contains(after, []byte(idB)) {
			t.Fatalf("substitute=%t: a recorded seal was lost", substitute)
		}
	}
}

// Claim: a final sign commits only its own temporary file, and refusing a
// foreign one leaves the committed state as it was. Another file, here a
// complete ledger that omits seal A and records seal B under another grant
// id, is renamed onto B's temporary name after it was written and synced and
// before the commit. With a committed ledger holding A, B refuses LEDGER_FILE
// with no result, the ledger stays byte-identical, no temporary file is left,
// and a different grant C on A's seal still refuses SEAL_REUSED. On the first
// record, with no ledger yet, B refuses the same way and no ledger is left
// behind. Neighbours: with the hook only observing, B issues and the ledger
// holds every seal; after each refusal B issues once the hook is gone.
// Limit: the swap runs at the ledger's step hook in-process, not by a racing
// process at a native syscall boundary.
func TestSealLedgerForeignTempCommit(t *testing.T) {
	for _, tc := range []struct {
		name        string
		first, swap bool
	}{{"recorded-swap", false, true}, {"recorded-stable", false, false}, {"first-swap", true, true}, {"first-stable", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
			a, b, c := sealFixture(t, f)
			idA := ""
			if !tc.first {
				idA = grantIDOf(t, f.signRun(context.Background(), a))
			}
			other := "c0ffee" + sealA[6:]
			foreign := filepath.Join(filepath.Dir(f.ledger), "foreign.json")
			raw, _ := json.Marshal(sealLedgerFile{SealLedgerSchema, []SealEntry{{sealB, 1, other}}})
			if err := os.WriteFile(foreign, raw, 0600); err != nil {
				t.Fatal(err)
			}
			before, beforeErr := os.ReadFile(f.ledger)
			fired := false
			setLedgerHook(t, func(step string) error {
				if step != "rename" || fired {
					return nil
				}
				fired = true
				temps := ledgerTemps(t, f.ledger)
				if len(temps) != 1 {
					t.Errorf("want one temporary file, have %v", temps)
					return nil
				}
				if tc.swap {
					return os.Rename(foreign, filepath.Join(filepath.Dir(f.ledger), temps[0]))
				}
				return nil
			})
			got := f.signRun(context.Background(), b)
			ledgerHook = nil
			if !fired {
				t.Fatal("hook did not run")
			}
			if tc.swap {
				if !refusedWith(got, "LEDGER_FILE") {
					t.Fatalf("committed a temporary file that is not its own: exit %d %+v", got.code, got.envelope.Error)
				}
				after, afterErr := os.ReadFile(f.ledger)
				if tc.first && !os.IsNotExist(afterErr) {
					t.Fatalf("a refused first record left a ledger: %v", afterErr)
				}
				if !tc.first && (beforeErr != nil || afterErr != nil || !bytes.Equal(after, before)) {
					t.Fatal("a refused foreign commit changed the committed ledger")
				}
				if left := ledgerTemps(t, f.ledger); len(left) != 0 {
					t.Fatalf("a refused foreign commit left temporary files %v", left)
				}
				if !tc.first {
					if reused := f.signRun(context.Background(), c); !refusedWith(reused, "SEAL_REUSED") {
						t.Fatalf("seal A reusable after a refused foreign commit: exit %d %+v", reused.code, reused.envelope.Error)
					}
				}
				got = f.signRun(context.Background(), b)
			}
			idB := grantIDOf(t, got)
			after := readLedger(t, f.ledger)
			if !bytes.Contains(after, []byte(idB)) || !bytes.Contains(after, []byte(idA)) || bytes.Contains(after, []byte(other)) {
				t.Fatal("neighbour: ledger does not hold exactly the issued seals")
			}
		})
	}
}

// Claim: each final sign writes its own temporary file, named
// ".<ledger>.tmp-" plus 16 random lower-case hex digits and distinct between
// writers, and removes it by committing it. A leftover matching that exact
// pattern fences the next sign (LEDGER_FILE) and is kept, and every other
// name is left untouched and does not fence.
// Limit: the near-miss names differ from the stale name by more than letter
// case, because the default macOS file system is case-insensitive.
func TestSealLedgerTempOwnership(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	a, b, _ := sealFixture(t, f)
	dir := filepath.Dir(f.ledger)
	pattern := regexp.MustCompile(`^\.seal-ledger\.json\.tmp-[0-9a-f]{16}$`)
	stale := filepath.Join(dir, ".seal-ledger.json.tmp-0123456789abcdef")
	kept := map[string][]byte{}
	for _, name := range []string{".seal-ledger.json.tmp", ".seal-ledger.json.tmp-0123", ".seal-ledger.json.tmp-0123456789abcdeg", ".seal-ledger.json.tmp-0123456789abcdef0", "other.json.tmp-0123456789abcdef"} {
		kept[name] = []byte("not a temporary file of this ledger: " + name)
		if err := os.WriteFile(filepath.Join(dir, name), kept[name], 0600); err != nil {
			t.Fatal(err)
		}
	}
	var seen []string
	setLedgerHook(t, func(step string) error {
		if step == "write" {
			for _, name := range ledgerTemps(t, f.ledger) {
				if pattern.MatchString(name) {
					seen = append(seen, name)
				}
			}
		}
		return nil
	})
	for _, req := range []GrantSignRequest{a, b} {
		grantIDOf(t, f.signRun(context.Background(), req))
	}
	if err := os.WriteFile(stale, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := f.signRun(context.Background(), a); !refusedWith(got, "LEDGER_FILE") {
		t.Fatalf("a leftover in the exact pattern did not fence: exit %d %+v", got.code, got.envelope.Error)
	}
	if got, err := os.ReadFile(stale); err != nil || string(got) != "stale" {
		t.Fatal("a fenced sign removed or changed the leftover")
	}
	if len(seen) != 2 || seen[0] == seen[1] {
		t.Fatalf("writers did not use their own temporary files: %v", seen)
	}
	for name, raw := range kept {
		if got, err := os.ReadFile(filepath.Join(dir, name)); err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("a name outside the temporary pattern was touched: %s", name)
		}
	}
}

// Claim: overlapping final signs serialize and lose no seal. Writer 1 (A on
// seal A) holds the lock after reading the ledger while writer 2 (B on seal
// B) starts and is given 300 ms; both then issue and the ledger holds both
// seals. Two signs of different grants on one seal started together end with
// exactly one success and one SEAL_REUSED, and the ledger records the winner.
// Limit: in-process goroutines; each opens its own directory handle, so they
// contend on the lock as separate processes do.
func TestSealLedgerConcurrentWriters(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	a, b, c := sealFixture(t, f)
	done := make(chan signOutcome, 1)
	var fired atomic.Bool
	setLedgerHook(t, func(step string) error {
		if step == "loaded" && fired.CompareAndSwap(false, true) {
			go func() { done <- f.signRun(context.Background(), b) }()
			time.Sleep(300 * time.Millisecond)
		}
		return nil
	})
	idA := grantIDOf(t, f.signRun(context.Background(), a))
	idB := grantIDOf(t, <-done)
	ledgerHook = nil
	after := readLedger(t, f.ledger)
	if !bytes.Contains(after, []byte(idA)) || !bytes.Contains(after, []byte(idB)) {
		t.Fatal("an overlapping writer lost a recorded seal")
	}

	g := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	a, _, c = sealFixture(t, g)
	var wg sync.WaitGroup
	outcomes := make([]signOutcome, 2)
	for i, req := range []GrantSignRequest{a, c} {
		wg.Add(1)
		go func() { defer wg.Done(); outcomes[i] = g.signRun(context.Background(), req) }()
	}
	wg.Wait()
	winners, reused := 0, 0
	var winner string
	for _, o := range outcomes {
		if o.code == 0 && o.envelope.OK {
			winners++
			winner = grantIDOf(t, o)
		} else if refusedWith(o, "SEAL_REUSED") {
			reused++
		}
	}
	if winners != 1 || reused != 1 || !bytes.Contains(readLedger(t, g.ledger), []byte(winner)) {
		t.Fatalf("one seal, two grants: %d successes, %d SEAL_REUSED", winners, reused)
	}
}

// holdLedgerLock takes the writer lock of the flow's ledger as another
// writer would, and returns its release.
func holdLedgerLock(t *testing.T, f *flow) func() {
	t.Helper()
	held, failure := openSealLedger(context.Background(), f.ledger, true)
	if failure != nil {
		t.Fatalf("fixture lock: %v", failure)
	}
	var once sync.Once
	release := func() { once.Do(held.close) }
	t.Cleanup(release)
	return release
}

// Claim: a final sign waiting on a held ledger lock honours the caller's
// deadline. With a 100 ms caller context it refuses LEDGER_FILE within two
// seconds, with no result and the ledger unchanged; a sign that waited for
// the 15-second total bound instead fails this test. Neighbour: once the lock
// is free, the same sign with a two-second caller context issues.
func TestSealLedgerLockCallerDeadline(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	a, b, _ := sealFixture(t, f)
	grantIDOf(t, f.signRun(context.Background(), a))
	before := readLedger(t, f.ledger)
	release := holdLedgerLock(t, f)
	done := make(chan signOutcome, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	go func() { done <- f.signRun(ctx, b) }()
	var got signOutcome
	select {
	case got = <-done:
	case <-time.After(2 * time.Second):
		release()
		<-done
		t.Fatal("a sign with a 100 ms caller deadline was still waiting on the ledger lock after 2 s")
	}
	if !refusedWith(got, "LEDGER_FILE") || !bytes.Equal(readLedger(t, f.ledger), before) {
		t.Fatalf("deadline refusal: exit %d %+v, ledger changed %t", got.code, got.envelope.Error, !bytes.Equal(readLedger(t, f.ledger), before))
	}
	release()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	grantIDOf(t, f.signRun(ctx2, b))
}

// Claim: with no caller deadline, a final sign waiting on a held ledger lock
// stops at the 15-second total bound: it refuses LEDGER_FILE after at least
// 14 and at most 18 seconds, with no result and the ledger unchanged.
// Neighbour: once the lock is free, the same sign with no caller deadline
// issues.
func TestSealLedgerLockTotalBound(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	a, b, _ := sealFixture(t, f)
	grantIDOf(t, f.signRun(context.Background(), a))
	before := readLedger(t, f.ledger)
	release := holdLedgerLock(t, f)
	done := make(chan signOutcome, 1)
	go func() { done <- f.signRun(context.Background(), b) }()
	var got signOutcome
	select {
	case got = <-done:
	case <-time.After(18 * time.Second):
		release()
		<-done
		t.Fatal("a sign waited on the ledger lock past the 15-second total bound")
	}
	if !refusedWith(got, "LEDGER_FILE") || got.elapsed < 14*time.Second || !bytes.Equal(readLedger(t, f.ledger), before) {
		t.Fatalf("total-bound refusal after %s: exit %d %+v", got.elapsed, got.code, got.envelope.Error)
	}
	release()
	grantIDOf(t, f.signRun(context.Background(), b))
}

// Claim: an existing ledger whose entries this CLI would not write is
// damaged, never a source of free seals. An empty, upper-case, short or
// non-hex grant_id, a malformed txid, a seal or grant id recorded twice, and
// an empty or null seal list each refuse LEDGER_FILE with no result at draft,
// at both sign stages for the recorded seal A (grant C) and for the fresh
// seal B, and the file is left byte-identical. Neighbour: with the committed
// ledger restored, C refuses SEAL_REUSED and B issues.
func TestSealLedgerMalformedEntries(t *testing.T) {
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	a, b, c := sealFixture(t, f)
	idA := grantIDOf(t, f.signRun(context.Background(), a))
	committed := readLedger(t, f.ledger)
	doc := func(seals ...SealEntry) []byte {
		raw, _ := json.Marshal(sealLedgerFile{SealLedgerSchema, seals})
		return raw
	}
	other := "ab" + idA[2:]
	if other == idA {
		other = "cd" + idA[2:]
	}
	cases := map[string][]byte{
		"empty-grant-id":     doc(SealEntry{sealA, 1, ""}),
		"upper-grant-id":     doc(SealEntry{sealA, 1, "AB" + idA[2:]}),
		"short-grant-id":     doc(SealEntry{sealA, 1, idA[:62]}),
		"non-hex-grant-id":   doc(SealEntry{sealA, 1, "zz" + idA[2:]}),
		"bad-txid":           doc(SealEntry{sealA[:62], 1, idA}),
		"duplicate-seal":     doc(SealEntry{sealA, 1, idA}, SealEntry{sealA, 1, other}),
		"duplicate-grant-id": doc(SealEntry{sealA, 1, idA}, SealEntry{sealB, 1, idA}),
		"empty-list":         doc(),
		"null-list":          []byte(`{"schema":"swarma-identity/seal-ledger/1","seals":null}`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(f.ledger, raw, 0600); err != nil {
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
			if !bytes.Equal(readLedger(t, f.ledger), raw) {
				t.Fatal("a refused command changed a malformed ledger")
			}
		})
	}
	if err := os.WriteFile(f.ledger, committed, 0600); err != nil {
		t.Fatal(err)
	}
	e, code := f.signCmd(c)
	mustRefuse(t, e, code, "SEAL_REUSED")
	e, code = f.signCmd(b)
	mustOK(t, e, code)
}

// Claim: a refused update must not forget a previously committed seal when
// only the writer's temporary pathname is substituted before its rename.
// The neighbour performs the same update without substitution. This is an
// in-process hook-controlled fixture, not native syscall-scheduling evidence.
func TestReviewPR8ForeignTempKeepsHistory(t *testing.T) {
	for _, swap := range []bool{false, true} {
		t.Run(map[bool]string{false: "stable-temp", true: "substituted-temp"}[swap], func(t *testing.T) {
			f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
			a, b, c := sealFixture(t, f)
			idA := grantIDOf(t, f.signRun(context.Background(), a))
			before := readLedger(t, f.ledger)
			other := "ab" + idA[2:]
			if other == idA {
				other = "cd" + idA[2:]
			}
			foreign := filepath.Join(filepath.Dir(f.ledger), "foreign-review.json")
			raw, _ := json.Marshal(sealLedgerFile{SealLedgerSchema, []SealEntry{{sealB, 1, other}}})
			if err := os.WriteFile(foreign, raw, 0600); err != nil {
				t.Fatal(err)
			}
			fired := false
			setLedgerHook(t, func(step string) error {
				if step != "rename" || fired {
					return nil
				}
				fired = true
				if !swap {
					return nil
				}
				names := ledgerTemps(t, f.ledger)
				if len(names) != 1 {
					t.Fatalf("fixture temp count %d", len(names))
				}
				return os.Rename(foreign, filepath.Join(filepath.Dir(f.ledger), names[0]))
			})
			got := f.signRun(context.Background(), b)
			ledgerHook = nil
			if !fired {
				t.Fatal("control did not reach rename hook")
			}
			if swap {
				if !refusedWith(got, "LEDGER_FILE") {
					t.Errorf("substitution must refuse before releasing grant: %+v", got)
				}
				if !bytes.Equal(readLedger(t, f.ledger), before) {
					t.Error("refused temporary substitution replaced prior committed ledger")
				}
			} else {
				grantIDOf(t, got)
				if !bytes.Contains(readLedger(t, f.ledger), []byte(idA)) {
					t.Error("valid neighbour lost prior seal")
				}
			}
			reused := f.signRun(context.Background(), c)
			if !refusedWith(reused, "SEAL_REUSED") {
				t.Errorf("prior seal reusable after temporary substitution: exit%d error=%v", reused.code, reused.envelope.Error)
			}
		})
	}
}

// Claim: restart admission must not forget previously issued A when a writer
// stopped between exchanging a foreign temporary file and its undo. Construct
// that documented on-disk state using the actual exchange syscall, release its
// fixture lock, and invoke the unchanged public CLI. This is an interrupted-
// state fixture, not a native process-kill or power-loss experiment.
func TestReviewPR8InterruptedForeignExchange(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		t.Run(map[bool]string{false: "undo-completed", true: "stopped-before-undo"}[interrupted], func(t *testing.T) {
			f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
			a, _, c := sealFixture(t, f)
			idA := grantIDOf(t, f.signRun(context.Background(), a))
			before := readLedger(t, f.ledger)
			held, failure := openSealLedger(context.Background(), f.ledger, true)
			if failure != nil {
				t.Fatalf("fixture lock: %v", failure)
			}
			defer held.close()
			other := "ab" + idA[2:]
			if other == idA {
				other = "cd" + idA[2:]
			}
			foreign, _ := json.Marshal(sealLedgerFile{SealLedgerSchema, []SealEntry{{sealB, 1, other}}})
			tmp := held.tempPrefix() + "0102030405060708"
			tmpPath := filepath.Join(filepath.Dir(f.ledger), tmp)
			if err := os.WriteFile(tmpPath, foreign, 0600); err != nil {
				t.Fatal(err)
			}
			if err := exchangeAt(held.dir, tmp, held.name); err != nil {
				t.Fatalf("fixture exchange: %v", err)
			}
			if !bytes.Equal(readLedger(t, tmpPath), before) {
				t.Fatal("fixture missing intact previous ledger under temp name")
			}
			if !interrupted {
				if err := exchangeAt(held.dir, tmp, held.name); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(tmpPath); err != nil {
					t.Fatal(err)
				}
			}
			held.close()
			got := f.signRun(context.Background(), c)
			if !refusedWith(got, "SEAL_REUSED") && !(interrupted && refusedWith(got, "LEDGER_FILE")) {
				t.Errorf("previous seal reusable after interrupted exchange: exit%d error=%v", got.code, got.envelope.Error)
			}
			if interrupted {
				ledger, _ := os.ReadFile(f.ledger)
				saved, _ := os.ReadFile(tmpPath)
				if !bytes.Equal(ledger, before) && !bytes.Equal(saved, before) {
					t.Error("restart cleanup destroyed the only preserved prior ledger")
				}
			}
		})
	}
}
