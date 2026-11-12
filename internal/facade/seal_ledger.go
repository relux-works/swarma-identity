package facade

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const SealLedgerSchema = "swarma-identity/seal-ledger/1"

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
type sealLedger struct {
	f       *os.File
	entries []SealEntry
}

// ledgerPathOK refuses relative, unclean or symlinked paths, including a
// symlink in any directory component.
func ledgerPathOK(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	return err == nil && dir == filepath.Dir(path)
}

func ownerOnlyRegular(st os.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && st.Mode().IsRegular() && st.Mode().Perm()&0077 == 0 && sys.Uid == uint32(os.Getuid()) && sys.Nlink == 1
}

// openSealLedger opens and exclusively locks the ledger. With create, a missing
// ledger is created at 0600; without it, a missing ledger reads as empty and
// no file is created. The caller must close the returned ledger.
func openSealLedger(path string, create bool) (*sealLedger, *Failure) {
	if !ledgerPathOK(path) {
		return nil, refuse("LEDGER_FILE")
	}
	flags := os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags |= os.O_CREATE
	}
	f, err := os.OpenFile(path, flags, 0600)
	if os.IsNotExist(err) && !create {
		return &sealLedger{}, nil
	}
	if err != nil {
		return nil, refuse("LEDGER_FILE")
	}
	l := &sealLedger{f: f}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX) != nil {
		l.close()
		return nil, refuse("LEDGER_FILE")
	}
	st, err := f.Stat()
	if err != nil || !ownerOnlyRegular(st) || st.Size() > 65536 {
		l.close()
		return nil, refuse("LEDGER_FILE")
	}
	if st.Size() == 0 {
		return l, nil
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	var doc sealLedgerFile
	if err != nil || DecodeStrict(raw, &doc) != nil || doc.Schema != SealLedgerSchema {
		l.close()
		return nil, refuse("LEDGER_FILE")
	}
	l.entries = doc.Seals
	return l, nil
}

func (l *sealLedger) close() {
	if l.f != nil {
		l.f.Close()
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

// record appends one entry under the held lock and syncs it to disk.
func (l *sealLedger) record(e SealEntry) *Failure {
	if l.f == nil {
		return refuse("LEDGER_FILE")
	}
	raw, ok := compactJSON(sealLedgerFile{SealLedgerSchema, append(append([]SealEntry{}, l.entries...), e)})
	if !ok || len(raw) > 65536 {
		return refuse("LEDGER_FILE")
	}
	if l.f.Truncate(0) != nil {
		return refuse("LEDGER_FILE")
	}
	if _, err := l.f.WriteAt(raw, 0); err != nil || l.f.Sync() != nil {
		return refuse("LEDGER_FILE")
	}
	l.entries = append(l.entries, e)
	return nil
}
