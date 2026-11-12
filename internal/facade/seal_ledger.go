package facade

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const SealLedgerSchema = "swarma-identity/seal-ledger/1"

const sealLedgerMax = 65536

// SealEntry records that a seal backs exactly one signed grant.
type SealEntry struct {
	TxID    string `json:"txid"`
	Vout    uint32 `json:"vout"`
	GrantID string `json:"grant_id"`
}

type sealLedgerFile struct {
	Schema string      `json:"schema"`
	Seals  []SealEntry `json:"seals"`
}

// The issuer's local seal ledger: one owner-only regular file, never behind a
// symlink, holding every seal this issuer has signed into a grant. A seal is
// recorded before the signed grant is released, so a second grant on the same
// seal is refused as SEAL_REUSED. The ledger is public data, not a secret.
//
// The parent directory is opened one component at a time without following
// symlinks, and every later step works relative to that directory handle. A
// writer holds an exclusive flock on that directory handle itself from before
// it reads the ledger until it closes, so the lock follows the directory
// inode and no pathname change can move it. The lock is taken with
// non-blocking attempts that stop when the caller's context is done, so a
// wait for a held lock never outlasts the caller's deadline. A writer commits
// an update by writing its own uniquely named temporary file, syncing it,
// renaming it over the
// ledger, checking that the ledger name now denotes that file, syncing the
// directory and checking that the path still names the locked directory. A
// failed or interrupted update therefore leaves the last committed ledger in
// place. A missing ledger is a new, empty ledger; an existing ledger must be
// a complete ledger document, so an empty or truncated file is refused, and
// every entry must be one this CLI writes: a lower-case hex txid and grant id
// and no seal or grant id recorded twice.
type sealLedger struct {
	dir     int  // the verified parent directory, or -1
	locked  bool // this writer holds the exclusive flock on dir
	path    string
	name    string
	entries []SealEntry
}

// ledgerHook is nil in production. Tests set it to act at a named step
// ("walked", "locked", "loaded", "write", "rename"); an error it returns
// fails that step.
var ledgerHook func(step string) error

func ledgerStep(step string) error {
	if ledgerHook == nil {
		return nil
	}
	return ledgerHook(step)
}

var errLedgerPath = errors.New("ledger path")

func retryEINTR[T any](call func() (T, error)) (T, error) {
	for {
		v, err := call()
		if err != unix.EINTR {
			return v, err
		}
	}
}

func openAt(dir int, name string, flags int, mode uint32) (int, error) {
	return retryEINTR(func() (int, error) { return unix.Openat(dir, name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode) })
}

// openLedgerDir opens the parent directory of an absolute, clean path from
// "/" one component at a time, each relative to the handle before it and
// with O_NOFOLLOW, so a symlink at any component is refused, not followed.
func openLedgerDir(path string) (int, string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, "", errLedgerPath
	}
	parent, name := filepath.Split(path)
	if name == "" || name == "." || name == ".." {
		return -1, "", errLedgerPath
	}
	dir, err := retryEINTR(func() (int, error) {
		return unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	})
	if err != nil {
		return -1, "", err
	}
	for _, c := range strings.Split(strings.Trim(parent, "/"), "/") {
		if c == "" {
			continue
		}
		if c == "." || c == ".." {
			unix.Close(dir)
			return -1, "", errLedgerPath
		}
		next, err := openAt(dir, c, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		unix.Close(dir)
		if err != nil {
			return -1, "", err
		}
		dir = next
	}
	return dir, name, nil
}

func ownerOnlyRegular(st os.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && st.Mode().IsRegular() && st.Mode().Perm()&0077 == 0 && sys.Uid == uint32(os.Getuid()) && sys.Nlink == 1
}

func sameFile(a, b *unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }

// bound reports whether the path still names the directory this ledger holds.
func (l *sealLedger) bound() bool {
	again, _, err := openLedgerDir(l.path)
	if err != nil {
		return false
	}
	defer unix.Close(again)
	var held, now unix.Stat_t
	return unix.Fstat(l.dir, &held) == nil && unix.Fstat(again, &now) == nil && sameFile(&held, &now)
}

// ledgerLockPoll is the wait between two non-blocking lock attempts.
const ledgerLockPoll = 10 * time.Millisecond

// lockDir takes an exclusive flock on the directory handle without ever
// blocking in the kernel: it retries a non-blocking attempt until it holds
// the lock or ctx is done. A failed attempt holds nothing, so giving up leaks
// no lock.
func lockDir(ctx context.Context, fd int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := retryEINTR(func() (int, error) { return 0, unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) })
		if err != unix.EWOULDBLOCK {
			return err
		}
		wait := time.NewTimer(ledgerLockPoll)
		select {
		case <-ctx.Done():
			wait.Stop()
			return ctx.Err()
		case <-wait.C:
		}
	}
}

// openSealLedger opens the ledger. With create it takes the writer lock, an
// exclusive flock on the verified directory handle bounded by ctx, and
// creates nothing; the ledger file itself is created by the first record.
// Without create it only reads: a missing ledger reads as empty. The caller
// must close the ledger, which releases the lock.
func openSealLedger(ctx context.Context, path string, create bool) (*sealLedger, *Failure) {
	dir, name, err := openLedgerDir(path)
	if err != nil {
		return nil, refuse("LEDGER_FILE")
	}
	l := &sealLedger{dir: dir, path: path, name: name}
	if ledgerStep("walked") != nil {
		l.close()
		return nil, refuse("LEDGER_FILE")
	}
	if create {
		if lockDir(ctx, dir) != nil || !l.bound() || ledgerStep("locked") != nil {
			l.close()
			return nil, refuse("LEDGER_FILE")
		}
		l.locked = true
	}
	if f := l.load(); f != nil {
		l.close()
		return nil, f
	}
	if ledgerStep("loaded") != nil {
		l.close()
		return nil, refuse("LEDGER_FILE")
	}
	return l, nil
}

// load reads the committed ledger relative to the verified directory.
func (l *sealLedger) load() *Failure {
	fd, err := openAt(l.dir, l.name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return refuse("LEDGER_FILE")
	}
	f := os.NewFile(uintptr(fd), l.name)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !ownerOnlyRegular(st) || st.Size() == 0 || st.Size() > sealLedgerMax {
		return refuse("LEDGER_FILE")
	}
	raw, err := io.ReadAll(io.LimitReader(f, sealLedgerMax+1))
	var doc sealLedgerFile
	if err != nil || int64(len(raw)) != st.Size() || DecodeStrict(raw, &doc) != nil || doc.Schema != SealLedgerSchema || !validEntries(doc.Seals) {
		return refuse("LEDGER_FILE")
	}
	l.entries = doc.Seals
	return nil
}

// validEntries admits only entries this CLI records: at least one, each a
// lower-case hex txid and grant id, and no seal or grant id recorded twice.
// Anything else, an empty grant_id included, is a damaged ledger and never
// reads as a free seal.
func validEntries(entries []SealEntry) bool {
	if len(entries) == 0 {
		return false
	}
	seals, grants := map[string]bool{}, map[string]bool{}
	for _, e := range entries {
		seal := e.TxID + ":" + strconv.FormatUint(uint64(e.Vout), 10)
		if !lowerHex(e.TxID, 32) || !lowerHex(e.GrantID, 32) || seals[seal] || grants[e.GrantID] {
			return false
		}
		seals[seal], grants[e.GrantID] = true, true
	}
	return true
}

// close releases the writer lock, if held, by closing the directory handle.
func (l *sealLedger) close() {
	if l.dir >= 0 {
		unix.Close(l.dir)
		l.dir = -1
	}
	l.locked = false
}

// lookup returns the grant id recorded for the seal, or "" when the seal is
// not recorded. load admits no empty grant id, so "" always means free.
func (l *sealLedger) lookup(txid string, vout uint32) string {
	for _, e := range l.entries {
		if e.TxID == txid && e.Vout == vout {
			return e.GrantID
		}
	}
	return ""
}

// tempPrefix starts every writer's temporary file name; a writer appends 16
// random lower-case hex digits, so no two writers share a temporary file.
func (l *sealLedger) tempPrefix() string { return "." + l.name + ".tmp-" }

// removeStaleTemps runs only under the writer lock. Every writer creates its
// temporary file while holding that lock and removes or commits it before
// releasing it, so a file matching the exact temporary pattern found here was
// left by an interrupted writer. Other names are never touched. Removal is
// best effort: a stale file is never read.
func (l *sealLedger) removeStaleTemps() {
	fd, err := openAt(l.dir, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return
	}
	d := os.NewFile(uintptr(fd), ".")
	names, _ := d.Readdirnames(-1)
	d.Close()
	prefix := l.tempPrefix()
	for _, n := range names {
		if strings.HasPrefix(n, prefix) && lowerHex(n[len(prefix):], 8) {
			unix.Unlinkat(l.dir, n, 0)
		}
	}
}

// record commits one more entry under the held lock. The new ledger is
// written and synced to this writer's own temporary file, created exclusively
// in the verified directory, and renamed over the ledger. After the rename
// the ledger name must denote that same file and, after the directory sync,
// the path must still name the locked directory; otherwise the record is
// refused. Until the rename the committed ledger is untouched; a failure
// before it removes the writer's temporary file and refuses.
func (l *sealLedger) record(e SealEntry) *Failure {
	if !l.locked || l.dir < 0 {
		return refuse("LEDGER_FILE")
	}
	raw, ok := compactJSON(sealLedgerFile{SealLedgerSchema, append(append([]SealEntry{}, l.entries...), e)})
	if !ok || len(raw) > sealLedgerMax {
		return refuse("LEDGER_FILE")
	}
	l.removeStaleTemps()
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return refuse("LEDGER_FILE")
	}
	tmp := l.tempPrefix() + hex.EncodeToString(suffix[:])
	fd, err := openAt(l.dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		return refuse("LEDGER_FILE")
	}
	f := os.NewFile(uintptr(fd), tmp)
	renamed := false
	defer func() {
		f.Close()
		if !renamed {
			unix.Unlinkat(l.dir, tmp, 0)
		}
	}()
	if ledgerStep("write") != nil {
		return refuse("LEDGER_FILE")
	}
	var mine, committed unix.Stat_t
	if n, err := f.WriteAt(raw, 0); err != nil || n != len(raw) || f.Sync() != nil || unix.Fstat(fd, &mine) != nil || ledgerStep("rename") != nil {
		return refuse("LEDGER_FILE")
	}
	if unix.Renameat(l.dir, tmp, l.dir, l.name) != nil {
		return refuse("LEDGER_FILE")
	}
	renamed = true
	if unix.Fstatat(l.dir, l.name, &committed, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameFile(&mine, &committed) {
		return refuse("LEDGER_FILE") // the committed ledger is not this writer's file
	}
	if _, err := retryEINTR(func() (int, error) { return 0, unix.Fsync(l.dir) }); err != nil {
		return refuse("LEDGER_FILE")
	}
	if !l.bound() {
		return refuse("LEDGER_FILE") // the path no longer names the locked directory
	}
	l.entries = append(l.entries, e)
	return nil
}
