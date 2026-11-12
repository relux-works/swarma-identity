package facade

import (
	"bytes"
	"context"
	"io"
	"os"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"
)

// LedgerRecoverResult reports one grant ledger-recover run.
type LedgerRecoverResult struct {
	Seals    int `json:"seals"`    // entries in the committed ledger after recovery
	Restored int `json:"restored"` // entries taken from leftover files into the ledger
	Removed  int `json:"removed"`  // leftover temporary files removed
}

// leftoverFile is one leftover temporary file as classified under the lock.
type leftoverFile struct {
	name    string
	st      unix.Stat_t
	entries []SealEntry // its entries when it is a complete ledger, else nil
	raw     []byte
}

// RecoverSealLedger clears the recovery fence. Under the exclusive lock it
// reads the ledger and every leftover temporary file and classifies each
// leftover: an empty file; a complete ledger document, whose entries are
// merged into the ledger; or a torn write, a prefix of a ledger document that
// extends the ledger or a leftover ledger by at most one entry, which a
// writer had not committed. Any other leftover refuses as LEDGER_FILE. The
// merge is the union of entries and refuses as LEDGER_RECOVERY_CONFLICT when
// one seal maps to two grant ids or one grant id to two seals. A union larger
// than the ledger is committed by the same exchange protocol as a sign; the
// ledger is then read back and must hold exactly the union. Only after that
// are the leftovers removed, each only while its name still denotes the file
// classified. A refusal before the read-back leaves the ledger and every
// leftover as they were, so the fence keeps holding; after it, the ledger
// already holds the union, so a leftover removed by then is merged.
func RecoverSealLedger(ctx context.Context, path string) (*LedgerRecoverResult, *Failure) {
	ctx, cancel := context.WithTimeout(ctx, grantSignBound)
	defer cancel()
	dir, name, err := openLedgerDir(path)
	if err != nil {
		return nil, refuse("LEDGER_FILE")
	}
	l := &sealLedger{dir: dir, path: path, name: name}
	defer l.close()
	if lockDir(ctx, dir) != nil || !l.bound() {
		return nil, refuse("LEDGER_FILE")
	}
	l.locked = true
	names, err := l.leftovers()
	if err != nil {
		return nil, refuse("LEDGER_FILE")
	}
	if f := l.load(); f != nil {
		return nil, f
	}
	var found []leftoverFile
	ledgers := [][]SealEntry{l.entries}
	for _, n := range names {
		lf, ok := l.readLeftover(n)
		if !ok {
			return nil, refuse("LEDGER_FILE")
		}
		if lf.entries != nil {
			ledgers = append(ledgers, lf.entries)
		}
		found = append(found, lf)
	}
	for _, lf := range found {
		if lf.entries == nil && len(lf.raw) != 0 && !tornWrite(lf.raw, ledgers) {
			return nil, refuse("LEDGER_FILE") // not a ledger and not a torn write of one: kept for the owner
		}
	}
	union, ok := mergeEntries(ledgers)
	if !ok {
		return nil, refuse("LEDGER_RECOVERY_CONFLICT")
	}
	restored := len(union) - len(l.entries)
	if restored > 0 {
		if f := l.commit(union); f != nil {
			return nil, f
		}
	}
	if !l.verify(union) {
		return nil, refuse("LEDGER_FILE")
	}
	for _, lf := range found {
		var now unix.Stat_t
		if l.statName(lf.name, &now) != nil || !sameFile(&now, &lf.st) || unix.Unlinkat(l.dir, lf.name, 0) != nil {
			return nil, refuse("LEDGER_FILE")
		}
	}
	if _, err := retryEINTR(func() (int, error) { return 0, unix.Fsync(l.dir) }); err != nil || !l.bound() {
		return nil, refuse("LEDGER_FILE")
	}
	return &LedgerRecoverResult{len(union), restored, len(found)}, nil
}

// readLeftover reads one leftover relative to the locked directory. It must
// be an owner-only regular file with one link and at most the ledger size
// bound; its entries are set only when it is a complete ledger document.
func (l *sealLedger) readLeftover(name string) (leftoverFile, bool) {
	lf := leftoverFile{name: name}
	fd, err := openAt(l.dir, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return lf, false
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !ownerOnlyRegular(st) || st.Size() > sealLedgerMax || unix.Fstat(fd, &lf.st) != nil {
		return lf, false
	}
	raw, err := io.ReadAll(io.LimitReader(f, sealLedgerMax+1))
	if err != nil || int64(len(raw)) != st.Size() {
		return lf, false
	}
	lf.raw = raw
	var doc sealLedgerFile
	if len(raw) != 0 && DecodeStrict(raw, &doc) == nil && doc.Schema == SealLedgerSchema && validEntries(doc.Seals) {
		lf.entries = doc.Seals
	}
	return lf, true
}

// tornWrite reports whether raw, which is not a complete ledger, is a prefix
// of a ledger document that extends one of bases by at most one entry: the
// bytes a writer that read that base left when it stopped mid-write. Such a
// file was never under the ledger name, since a writer syncs its whole file
// before the exchange, so it holds no seal that a released grant uses.
func tornWrite(raw []byte, bases [][]SealEntry) bool {
	empty, _ := compactJSON(SealEntry{})
	for _, base := range bases {
		full, ok := compactJSON(sealLedgerFile{SealLedgerSchema, append(slices.Clone(base), SealEntry{})})
		if !ok {
			continue
		}
		stem := full[:len(full)-len(empty)-2] // the document up to where the next entry starts
		if bytes.HasPrefix(stem, raw) || (bytes.HasPrefix(raw, stem) && bytes.Count(raw[len(stem):], []byte("{")) <= 1) {
			return true
		}
	}
	return false
}

// mergeEntries returns the union of the ledgers' entries, the first ledger's
// order first. It reports false when one seal maps to two grant ids or one
// grant id to two seals.
func mergeEntries(ledgers [][]SealEntry) ([]SealEntry, bool) {
	var union []SealEntry
	bySeal, byGrant := map[string]string{}, map[string]string{}
	for _, entries := range ledgers {
		for _, e := range entries {
			seal := e.TxID + ":" + strconv.FormatUint(uint64(e.Vout), 10)
			g, sealSeen := bySeal[seal]
			s, grantSeen := byGrant[e.GrantID]
			if sealSeen || grantSeen {
				if g != e.GrantID || s != seal {
					return nil, false
				}
				continue
			}
			bySeal[seal], byGrant[e.GrantID] = e.GrantID, seal
			union = append(union, e)
		}
	}
	return union, true
}

// verify reads the committed ledger back and reports whether it holds exactly
// the entries given, in any order.
func (l *sealLedger) verify(entries []SealEntry) bool {
	again := &sealLedger{dir: l.dir, path: l.path, name: l.name}
	if again.load() != nil || len(again.entries) != len(entries) {
		return false
	}
	want := map[SealEntry]bool{}
	for _, e := range entries {
		want[e] = true
	}
	for _, e := range again.entries {
		if !want[e] {
			return false
		}
	}
	return true
}
