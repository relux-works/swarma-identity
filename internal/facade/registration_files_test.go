//go:build linux || darwin

package facade

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A safe one-link 0600 file is a positive control for each isolated mode/link/
// ancestry/type mutation. Frozen identity and mtime checks detect later changes;
// this does not promise hostile same-user atomicity.
func TestRegistrationInputFiles(t *testing.T) {
	for _, variant := range []string{"mode", "symlink", "hardlink", "ancestor", "directory", "replaced", "modified", "expectation", "role"} {
		t.Run(variant, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "input")
			raw := []byte("safe")
			regTestWrite(t, path, raw)
			z := newRegFreezer()
			if b, f := z.read(path, 64, regDigest(raw), "test"); f != nil || !bytes.Equal(raw, b) {
				t.Fatal(f)
			}
			switch variant {
			case "mode":
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+"-real", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+"-link"); err != nil {
					t.Fatal(err)
				}
			case "ancestor":
				if err := os.Chmod(dir, 0770); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Rename(path, path+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "replaced":
				if err := os.Rename(path, path+"-old"); err != nil {
					t.Fatal(err)
				}
				regTestWrite(t, path, raw)
			case "modified":
				if err := os.Chtimes(path, time.Now(), time.Now().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
			hash, role := regDigest(raw), "test"
			if variant == "expectation" {
				hash = regDigest([]byte("other"))
			}
			if variant == "role" {
				role = "other"
			}
			if b, f := z.read(path, 64, hash, role); b != nil || f == nil || f.Code != "REGISTRATION_FILES" {
				t.Fatalf("%s admitted", variant)
			}
		})
	}
}

// Every independent per-file ceiling is reached with real regular file bytes;
// these are transport predicates, not claims of semantic PSBT/funding maxima.
func TestRegistrationFileCaps(t *testing.T) {
	caps := []int{256, 16384, 65536, 1 << 20, 2 << 20, 4 << 20, 6 << 20, 8 << 20}
	dir := t.TempDir()
	for _, cap := range caps {
		for _, size := range []int{cap - 1, cap, cap + 1} {
			t.Run(fmt.Sprintf("%d-%d", cap, size), func(t *testing.T) {
				path := filepath.Join(dir, fmt.Sprintf("file-%d-%d", cap, size))
				raw := bytes.Repeat([]byte("x"), size)
				regTestWrite(t, path, raw)
				z := newRegFreezer()
				b, f := z.read(path, cap, regDigest(raw), "test")
				if size <= cap {
					if f != nil || !bytes.Equal(raw, b) {
						t.Fatal(f)
					}
				} else if f == nil || f.Code != "REGISTRATION_FILES" || b != nil {
					t.Fatal("oversize admitted")
				}
			})
		}
	}
}

// Distinct file and aggregate frozen-byte budgets are enforced separately.
// Shared exact paths count once; differing expectations are forbidden above.
func TestRegistrationAggregateBudgets(t *testing.T) {
	t.Run("files", func(t *testing.T) {
		dir := t.TempDir()
		z := newRegFreezer()
		for i := 0; i < 129; i++ {
			path := filepath.Join(dir, fmt.Sprint(i))
			regTestWrite(t, path, []byte("x"))
			b, f := z.read(path, 1, regDigest([]byte("x")), "test")
			if i < 128 {
				if f != nil || len(b) != 1 {
					t.Fatal(f)
				}
				if _, f = z.read(path, 1, regDigest([]byte("x")), "test"); f != nil {
					t.Fatal("shared file counted again")
				}
			} else if f == nil || b != nil {
				t.Fatal("file budget admitted")
			}
		}
	})
	t.Run("bytes", func(t *testing.T) {
		dir := t.TempDir()
		z := newRegFreezer()
		raw := bytes.Repeat([]byte("x"), 8<<20)
		for i := 0; i < 16; i++ {
			path := filepath.Join(dir, fmt.Sprint(i))
			regTestWrite(t, path, raw)
			if _, f := z.read(path, len(raw), regDigest(raw), "test"); f != nil {
				t.Fatal(f)
			}
		}
		path := filepath.Join(dir, "over")
		regTestWrite(t, path, []byte("x"))
		if b, f := z.read(path, 1, regDigest([]byte("x")), "test"); b != nil || f == nil || f.Code != "REGISTRATION_FILES" {
			t.Fatal("byte budget admitted")
		}
	})
}

type regInterruptContext struct {
	context.Context
	calls, at int
}

func (c *regInterruptContext) Err() error {
	c.calls++
	if c.calls >= c.at {
		return context.Canceled
	}
	return nil
}

// Interruptions before the index preserve payload leftovers, emit no usable
// bundle and cannot resume. An index left after a later interruption is also
// not a reported success and must undergo complete future readback/admission.
func TestRegistrationInterruptedCommit(t *testing.T) {
	for _, at := range []int{3, 4} {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "bundle")
			payload := map[string][]byte{"account-pin.json": []byte("public")}
			ctx := &regInterruptContext{Context: context.Background(), at: at}
			success, f := regCommit(ctx, path, "account-pin", "", regDigest(payload["account-pin.json"]), payload)
			if success != nil || f == nil || f.Code != "REGISTRATION_FILES" {
				t.Fatal("interruption reported success")
			}
			if b := regTestRead(t, filepath.Join(path, "account-pin.json")); !bytes.Equal(b, payload["account-pin.json"]) {
				t.Fatal("failure lost payload")
			}
			index := filepath.Join(path, "bundle.json")
			_, err := os.Lstat(index)
			if at == 3 && !os.IsNotExist(err) {
				t.Fatal("index committed before all interruption checks")
			}
			if at == 4 && err != nil {
				t.Fatal("fixture did not reach post-index interruption")
			}
			before := regTestRead(t, filepath.Join(path, "account-pin.json"))
			success, f = regCommit(context.Background(), path, "account-pin", "", regDigest(before), payload)
			if success != nil || f == nil {
				t.Fatal("automatic resume admitted")
			}
			if !bytes.Equal(before, regTestRead(t, filepath.Join(path, "account-pin.json"))) {
				t.Fatal("retry changed leftovers")
			}
		})
	}
}

// Existing and symlinked outputs refuse without overwriting their contents;
// normal success has exact modes, ordered index commitments and readback.
func TestRegistrationOutputCustody(t *testing.T) {
	e, reservation, parent := regTestFrozen(t, "two-stage")
	var index regBundle
	if !regState(regTestRead(t, reservation), &index, "bundle") {
		t.Fatal("index")
	}
	for _, row := range append(append([]regFile(nil), index.Files...), regFile{Name: "bundle.json"}) {
		path := filepath.Join(filepath.Dir(reservation), row.Name)
		var st unix.Stat_t
		if unix.Lstat(path, &st) != nil || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
			t.Fatal("output file custody")
		}
	}
	existing := filepath.Join(e.dir, "existing")
	if err := os.Mkdir(existing, 0700); err != nil {
		t.Fatal(err)
	}
	regTestWrite(t, filepath.Join(existing, "sentinel"), []byte("preserve"))
	input := filepath.Join(e.dir, "check.json")
	regTestWrite(t, input, regTestJSON(t, regTestCheck(parent)))
	en, exit := regTestInvoke(t, e.args("check-result", input, existing))
	if en.Error == nil || en.Error.Code != "REGISTRATION_FILES" || exit != 1 || en.Result != nil {
		t.Fatal("existing output accepted")
	}
	if string(regTestRead(t, filepath.Join(existing, "sentinel"))) != "preserve" {
		t.Fatal("existing output changed")
	}
	symlink := filepath.Join(e.dir, "symlink")
	if err := os.Symlink(existing, symlink); err != nil {
		t.Fatal(err)
	}
	en, exit = regTestInvoke(t, e.args("check-result", input, symlink))
	if en.Error == nil || en.Error.Code != "REGISTRATION_FILES" || exit != 1 {
		t.Fatal("symlink output accepted")
	}
	// An index does not conceal a missing retained payload on a later read.
	if err := os.Rename(filepath.Join(filepath.Dir(reservation), "A.psbt"), filepath.Join(filepath.Dir(reservation), "A.missing")); err != nil {
		t.Fatal(err)
	}
	out, en, exit := e.run(t, "check-result", "missing-payload", regTestCheck(parent))
	regTestRefusal(t, en, exit, "REGISTRATION_FILES", out)
}

// An inert stat projection proves the current-user owner predicate without
// chown/root or foreign data. Real safe-file admission is exercised separately;
// no on-disk foreign-owner integration result is claimed on this host.
func TestRegistrationOwnerPredicate(t *testing.T) {
	st := unix.Stat_t{Mode: unix.S_IFREG | 0600, Uid: uint32(os.Geteuid()), Nlink: 1}
	if !regFileStatSafe(st) {
		t.Fatal("own-file control refused")
	}
	st.Uid++
	if regFileStatSafe(st) {
		t.Fatal("foreign uid admitted")
	}
}

// Concurrent create-only attempts have exactly one complete winner. The loser
// cannot mix payload/index bytes or overwrite the winning private directory.
func TestRegistrationConcurrentCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle")
	type verdict struct {
		success *regSuccess
		failure *Failure
		raw     []byte
	}
	results := make(chan verdict, 2)
	for _, raw := range [][]byte{[]byte("public-one"), []byte("public-two")} {
		go func(raw []byte) {
			s, f := regCommit(context.Background(), path, "account-pin", "", regDigest(raw), map[string][]byte{"account-pin.json": raw})
			results <- verdict{s, f, raw}
		}(raw)
	}
	wins := 0
	var winner []byte
	for range 2 {
		v := <-results
		if v.success != nil && v.failure == nil {
			wins++
			winner = v.raw
		} else if v.success != nil || v.failure == nil || v.failure.Code != "REGISTRATION_FILES" {
			t.Fatal("concurrent creation verdict")
		}
	}
	if wins != 1 || !bytes.Equal(regTestRead(t, filepath.Join(path, "account-pin.json")), winner) {
		t.Fatal("concurrent creation mixed or lost winner")
	}
	var index regBundle
	if !regState(regTestRead(t, filepath.Join(path, "bundle.json")), &index, "bundle") || index.PinHash != regDigest(winner) || index.Files[0].Hash != regDigest(winner) {
		t.Fatal("winning index differs")
	}
}
