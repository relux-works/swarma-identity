package facade

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

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
// writer holds an exclusive lock on the owner-only sidecar "<name>.lock",
// which is never replaced, and commits an update by writing a temporary file,
// syncing it, renaming it over the ledger and syncing the directory. A failed
// or interrupted update therefore leaves the last committed ledger in place.
// A missing ledger is a new, empty ledger; an existing ledger must be a
// complete ledger document, so an empty or truncated file is refused.
type sealLedger struct {
	dir     int // the verified parent directory, or -1
	lock    *os.File
	path    string
	name    string
	entries []SealEntry
}

// ledgerHook is nil in production. Tests set it to act at a named step
// ("walked", "locked", "write", "rename"); an error it returns fails that step.
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

// bound reports whether the path still names the directory this ledger holds
// and the lock file at its name is the one this ledger has locked.
func (l *sealLedger) bound() bool {
	again, _, err := openLedgerDir(l.path)
	if err != nil {
		return false
	}
	defer unix.Close(again)
	var held, now, locked, named unix.Stat_t
	if unix.Fstat(l.dir, &held) != nil || unix.Fstat(again, &now) != nil || !sameFile(&held, &now) {
		return false
	}
	return unix.Fstat(int(l.lock.Fd()), &locked) == nil &&
		unix.Fstatat(l.dir, l.name+".lock", &named, unix.AT_SYMLINK_NOFOLLOW) == nil && sameFile(&locked, &named)
}

// openSealLedger opens the ledger. With create it takes the writer lock,
// creating the lock file at 0600 when missing; the ledger file itself is
// created by the first record. Without create it only reads: a missing ledger
// reads as empty and nothing is created. The caller must close the ledger.
func openSealLedger(path string, create bool) (*sealLedger, *Failure) {
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
		fd, err := openAt(dir, name+".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NONBLOCK, 0600)
		if err != nil {
			l.close()
			return nil, refuse("LEDGER_FILE")
		}
		l.lock = os.NewFile(uintptr(fd), name+".lock")
		st, err := l.lock.Stat()
		if err != nil || !ownerOnlyRegular(st) {
			l.close()
			return nil, refuse("LEDGER_FILE")
		}
		if _, err := retryEINTR(func() (int, error) { return 0, unix.Flock(fd, unix.LOCK_EX) }); err != nil || !l.bound() || ledgerStep("locked") != nil {
			l.close()
			return nil, refuse("LEDGER_FILE")
		}
	}
	if f := l.load(); f != nil {
		l.close()
		return nil, f
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
	if err != nil || int64(len(raw)) != st.Size() || DecodeStrict(raw, &doc) != nil || doc.Schema != SealLedgerSchema {
		return refuse("LEDGER_FILE")
	}
	l.entries = doc.Seals
	return nil
}

func (l *sealLedger) close() {
	if l.lock != nil {
		l.lock.Close()
		l.lock = nil
	}
	if l.dir >= 0 {
		unix.Close(l.dir)
		l.dir = -1
	}
}

// lookup returns the grant id recorded for the seal, or "".
func (l *sealLedger) lookup(txid string, vout uint32) string {
	for _, e := range l.entries {
		if e.TxID == txid && e.Vout == vout {
			return e.GrantID
		}
	}
	return ""
}

// record commits one more entry under the held lock: the new ledger is
// written and synced to a temporary file in the verified directory, renamed
// over the ledger, and the directory is synced. Until the rename the
// committed ledger is untouched; a failure before it removes the temporary
// file and refuses.
func (l *sealLedger) record(e SealEntry) *Failure {
	if l.lock == nil || l.dir < 0 {
		return refuse("LEDGER_FILE")
	}
	raw, ok := compactJSON(sealLedgerFile{SealLedgerSchema, append(append([]SealEntry{}, l.entries...), e)})
	if !ok || len(raw) > sealLedgerMax {
		return refuse("LEDGER_FILE")
	}
	tmp := "." + l.name + ".tmp"
	if err := unix.Unlinkat(l.dir, tmp, 0); err != nil && err != unix.ENOENT { // left by an interrupted update
		return refuse("LEDGER_FILE")
	}
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
	if n, err := f.WriteAt(raw, 0); err != nil || n != len(raw) || f.Sync() != nil || ledgerStep("rename") != nil {
		return refuse("LEDGER_FILE")
	}
	if unix.Renameat(l.dir, tmp, l.dir, l.name) != nil {
		return refuse("LEDGER_FILE")
	}
	renamed = true
	if _, err := retryEINTR(func() (int, error) { return 0, unix.Fsync(l.dir) }); err != nil {
		return refuse("LEDGER_FILE")
	}
	l.entries = append(l.entries, e)
	return nil
}
