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
// an update by writing its own uniquely named temporary file, syncing it and
// atomically exchanging it with the ledger it read (see record), so a refused
// commit can put that ledger back; it then syncs the directory and checks
// that the path still names the locked directory. A failed or refused update
// therefore leaves the last committed ledger in place. A writer stopped
// between its exchange and the undo can leave the previous ledger under its
// temporary name, so every reader and writer, under the lock and before it
// reads the ledger, refuses while any leftover temporary file exists (the
// recovery fence); only grant ledger-recover clears it, by merging the
// leftovers into the ledger before removing them. A missing ledger is a new,
// empty ledger; an existing ledger must be a
// complete ledger document, so an empty or truncated file is refused, and
// every entry must be one this CLI writes: a lower-case hex txid and grant id
// and no seal or grant id recorded twice.
type sealLedger struct {
	dir     int  // the verified parent directory, or -1
	locked  bool // this writer holds the exclusive flock on dir
	path    string
	name    string
	held    *unix.Stat_t // device and inode of the ledger file read, nil when there was none
	entries []SealEntry
}

// ledgerHook is nil in production. Tests set it to act at a named step
// ("walked", "locked", "loaded", "write", "rename", and "readback" in a
// recover just before it reads the committed ledger back); an error it
// returns fails that step.
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
	return flockWithin(ctx, fd, unix.LOCK_EX|unix.LOCK_NB)
}

// lockDirShared takes a shared flock on the directory handle the same way. A
// reader holds it while it checks for leftover temporary files and reads the
// ledger, so it never sees a writer's own temporary file as a leftover.
func lockDirShared(ctx context.Context, fd int) error {
	return flockWithin(ctx, fd, unix.LOCK_SH|unix.LOCK_NB)
}

func flockWithin(ctx context.Context, fd, how int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := retryEINTR(func() (int, error) { return 0, unix.Flock(fd, how) })
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
// Without create it takes a shared flock the same way and only reads: a
// missing ledger reads as empty. Either way, before the ledger is read, the
// recovery fence refuses while a leftover temporary file exists (see fence).
// The caller must close the ledger, which releases the lock.
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
	} else if lockDirShared(ctx, dir) != nil || !l.bound() {
		l.close()
		return nil, refuse("LEDGER_FILE")
	}
	if f := l.fence(); f != nil {
		l.close()
		return nil, f
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
	var held unix.Stat_t
	if unix.Fstat(fd, &held) != nil {
		return refuse("LEDGER_FILE")
	}
	l.entries, l.held = doc.Seals, &held
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

// leftovers lists the names in the locked directory that match the exact
// temporary pattern. Every writer creates its temporary file while holding
// the exclusive lock and removes or commits it before releasing it, so under
// either lock, before this process creates its own, every such name was left
// by an interrupted writer. Other names are never listed.
func (l *sealLedger) leftovers() ([]string, error) {
	fd, err := openAt(l.dir, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	d := os.NewFile(uintptr(fd), ".")
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return nil, err
	}
	prefix := l.tempPrefix()
	var found []string
	for _, n := range names {
		if strings.HasPrefix(n, prefix) && lowerHex(n[len(prefix):], 8) {
			found = append(found, n)
		}
	}
	return found, nil
}

// errRecoveryRequired is the fence refusal. Its code is LEDGER_FILE; its
// fixed message names the recovery command.
func errRecoveryRequired() *Failure {
	return &Failure{Code: "LEDGER_FILE", Message: ledgerRecoveryMessage, Exit: 3}
}

const ledgerRecoveryMessage = "A seal-ledger temporary file left by an interrupted update may hold earlier seals; run grant ledger-recover."

// fence refuses, before the ledger is read, while any leftover temporary
// file exists: a writer stopped between its exchange and the undo leaves the
// previous ledger under the temporary name and another file under the ledger
// name, so the ledger name alone is not the history. Nothing is read, written
// or removed; only grant ledger-recover clears the fence. A directory that
// cannot be listed refuses as plain LEDGER_FILE (fail closed).
func (l *sealLedger) fence() *Failure {
	names, err := l.leftovers()
	if err != nil {
		return refuse("LEDGER_FILE")
	}
	if len(names) != 0 {
		return errRecoveryRequired()
	}
	return nil
}

// record commits one more entry under the held lock.
func (l *sealLedger) record(e SealEntry) *Failure {
	return l.commit(append(append([]SealEntry{}, l.entries...), e))
}

// commit replaces the ledger with entries under the held lock. The new ledger is
// written and synced to this writer's own temporary file, created exclusively
// in the verified directory. It is committed by one atomic exchange of the
// temporary name and the ledger name, so the ledger it displaces stays whole
// under the temporary name until the commit is accepted; the first record,
// with no ledger to displace, is renamed onto the ledger name only while that
// name is free. The commit stands only when the ledger name then denotes this
// writer's file and the displaced file is the ledger this writer read.
// Otherwise the record is refused and the change is undone: the exchange is
// made again, which puts the displaced ledger back, and the ledger name must
// then denote that displaced file again; a first record is renamed back off
// the ledger name, which must then be free. A platform or file system without
// the atomic exchange or the no-replace rename refuses the record; there is no
// plain-rename fallback. After a commit that stands the directory is synced
// and the path must still name the locked directory. Until the exchange the
// committed ledger is untouched; a failure before it removes the writer's
// temporary file and refuses. The only temporary file a commit removes is its
// own: before the exchange it holds this writer's uncommitted ledger, after a
// verified undo the same, and after a commit that stands the ledger this
// writer read, every entry of which is in the new ledger. A temporary file
// whose undo was not verified is kept, and the fence then holds.
func (l *sealLedger) commit(entries []SealEntry) *Failure {
	if !l.locked || l.dir < 0 {
		return refuse("LEDGER_FILE")
	}
	raw, ok := compactJSON(sealLedgerFile{SealLedgerSchema, entries})
	if !ok || len(raw) > sealLedgerMax {
		return refuse("LEDGER_FILE")
	}
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
	keepTemp := false
	defer func() {
		f.Close()
		if !keepTemp {
			unix.Unlinkat(l.dir, tmp, 0)
		}
	}()
	if ledgerStep("write") != nil {
		return refuse("LEDGER_FILE")
	}
	var mine unix.Stat_t
	if n, err := f.WriteAt(raw, 0); err != nil || n != len(raw) || f.Sync() != nil || unix.Fstat(fd, &mine) != nil || ledgerStep("rename") != nil {
		return refuse("LEDGER_FILE")
	}
	var stands bool
	if l.held == nil {
		stands, keepTemp = l.commitFirst(tmp, &mine)
	} else {
		stands, keepTemp = l.commitExchange(tmp, &mine)
	}
	if !stands {
		return refuse("LEDGER_FILE") // the ledger is not this writer's file, or nothing was committed
	}
	if _, err := retryEINTR(func() (int, error) { return 0, unix.Fsync(l.dir) }); err != nil {
		return refuse("LEDGER_FILE")
	}
	if !l.bound() {
		return refuse("LEDGER_FILE") // the path no longer names the locked directory
	}
	l.entries = entries
	l.held = &mine
	return nil
}

// statName stats a name in the verified directory without following a
// symlink.
func (l *sealLedger) statName(name string, st *unix.Stat_t) error {
	return unix.Fstatat(l.dir, name, st, unix.AT_SYMLINK_NOFOLLOW)
}

// syncDir makes an undo durable where it can; the record is refused either way.
func (l *sealLedger) syncDir() {
	retryEINTR(func() (int, error) { return 0, unix.Fsync(l.dir) })
}

// commitExchange commits the synced temporary file over the ledger this writer
// read by one atomic exchange. It reports whether the commit stands and
// whether the temporary name must be kept because an undo was not verified
// and that name may hold the displaced ledger.
func (l *sealLedger) commitExchange(tmp string, mine *unix.Stat_t) (stands, keep bool) {
	var now, displaced unix.Stat_t
	if l.statName(l.name, &now) != nil || !sameFile(&now, l.held) {
		return false, false // the ledger read under the lock is no longer in place; nothing moved
	}
	if exchangeAt(l.dir, tmp, l.name) != nil {
		return false, false // no exchange, so nothing moved and nothing is committed
	}
	nameErr, tmpErr := l.statName(l.name, &now), l.statName(tmp, &displaced)
	if nameErr == nil && tmpErr == nil && sameFile(&now, mine) && sameFile(&displaced, l.held) {
		return true, false // the temporary name now holds the previous ledger, which is removed
	}
	// The ledger name denotes a file that is not this writer's, or the file
	// displaced is not the ledger it read: exchange again to put back exactly
	// what the first exchange displaced, and check that it is back.
	if tmpErr != nil || exchangeAt(l.dir, tmp, l.name) != nil || l.statName(l.name, &now) != nil || !sameFile(&now, &displaced) {
		return false, true
	}
	l.syncDir()
	return false, false
}

// commitFirst commits the first record, when no ledger existed at load: the
// temporary file is renamed onto the ledger name only while that name is free.
// It reports whether the commit stands and whether the temporary name must be
// kept because the undo was not verified.
func (l *sealLedger) commitFirst(tmp string, mine *unix.Stat_t) (stands, keep bool) {
	if renameNewAt(l.dir, tmp, l.name) != nil {
		return false, false // a ledger appeared, or no no-replace rename: nothing moved
	}
	var now unix.Stat_t
	if l.statName(l.name, &now) == nil && sameFile(&now, mine) {
		return true, false
	}
	// Not this writer's file: rename it back off the ledger name, which must
	// then be free again, as it was before this record.
	if renameNewAt(l.dir, l.name, tmp) != nil || l.statName(l.name, &now) != unix.ENOENT {
		return false, true
	}
	l.syncDir()
	return false, false
}
