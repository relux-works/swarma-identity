package facade

import (
	"bytes"
	"context"
	"io"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"

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
// merged into the ledger; or a torn write, a proper prefix of the bytes the
// writer serializes for the ledger or a leftover ledger extended by at most
// one entry, which a writer had not committed (see tornWrite). Any other
// leftover refuses as LEDGER_FILE and is kept, so the fence holds. The
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
	if ledgerStep("readback") != nil {
		return nil, refuse("LEDGER_FILE")
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

// tornWrite reports whether raw, which is not a complete ledger, is a proper
// prefix of the bytes the writer serializes for one of bases extended by at
// most one entry: the bytes a writer that read that base left when it stopped
// mid-write. Such a file was never under the ledger name, since a writer syncs
// its whole file before the exchange, so it holds no seal that a released
// grant uses. Past the base's own bytes the file must follow the writer's
// grammar for one entry exactly, and at least one entry the writer could
// still have completed it to must be one a writer records (see tornEntry);
// otherwise the file is unclassifiable.
func tornWrite(raw []byte, bases [][]SealEntry) bool {
	empty, _ := compactJSON(SealEntry{})
	for _, base := range bases {
		full, ok := compactJSON(sealLedgerFile{SealLedgerSchema, append(slices.Clone(base), SealEntry{})})
		if !ok {
			continue
		}
		stem := full[:len(full)-len(empty)-2] // the document up to where the next entry starts
		// A writer refuses a document past sealLedgerMax before it writes a
		// byte. Only the vout varies in width: full holds a one-digit vout
		// and two empty 64-digit values, so this many vout digits still fit.
		room := sealLedgerMax - len(full) - 2*64 + 1
		if (bytes.HasPrefix(stem, raw) && tornEntry(nil, base, room)) || (bytes.HasPrefix(raw, stem) && tornEntry(raw[len(stem):], base, room)) {
			return true
		}
	}
	return false
}

// Value slots in tornEntryGrammar; neither occurs in a literal part.
const (
	tornHexValue  = "\x00hex"
	tornVoutValue = "\x00vout"
)

// tornEntryGrammar is what compactJSON writes for one SealEntry followed by
// the document close, split at the entry's values: the txid, the vout and the
// grant id. TestTornEntryGrammar pins it to the serializer's output.
var tornEntryGrammar = []string{`{"txid":"`, tornHexValue, `","vout":`, tornVoutValue, `,"grant_id":"`, tornHexValue, `"}]}`}

// tornEntry reports whether tail, the bytes after a base's stem, is a proper
// prefix of what the writer appends for one new entry and the document close,
// and that prefix can still be completed to an entry a writer records. The
// writer writes a txid and a grant id of 64 lower-case hex digits and a vout
// in canonical decimal no larger than a uint32; a byte the writer never
// writes at that position, a value it never writes, or the complete entry and
// close (a complete document, not a torn write) is not a torn write. Where
// the tail stops, inside a value or after it, what decides is the set of
// entries it can still become (see permittedCompletion), not that it ends.
func tornEntry(tail []byte, base []SealEntry, room int) bool {
	var values []string // the txid, the vout digits and the grant id, as far as tail holds them
	for _, part := range tornEntryGrammar {
		n, complete := 0, false
		switch part {
		case tornHexValue:
			for n < len(tail) && n < 64 && (tail[n] >= '0' && tail[n] <= '9' || tail[n] >= 'a' && tail[n] <= 'f') {
				n++
			}
			complete = n == 64
		case tornVoutValue:
			for n < len(tail) && tail[n] >= '0' && tail[n] <= '9' {
				n++
			}
			v, err := strconv.ParseUint(string(tail[:n]), 10, 32)
			if n != 0 && (err != nil || strconv.FormatUint(v, 10) != string(tail[:n])) {
				return false // a leading zero or a value past uint32: no prefix of a vout the writer writes
			}
			complete = n != 0 && n < len(tail) // digits end only where the next part starts
		default:
			n = min(len(tail), len(part))
			if string(tail[:n]) != part[:n] {
				return false
			}
			complete = n == len(part)
		}
		slot := part == tornHexValue || part == tornVoutValue
		if slot {
			values = append(values, string(tail[:n]))
		}
		if !complete {
			// The write stopped inside this part; otherwise a byte the writer never writes here follows.
			return n == len(tail) && permittedCompletion(values, slot, base, room)
		}
		tail = tail[n:]
	}
	return false
}

// permittedCompletion reports whether at least one entry the writer can still
// complete values to is one it records: a seal and a grant id that base does
// not hold, since a sign records only a free seal and a recover merges
// duplicates away, and a vout that keeps the document within sealLedgerMax
// (room digits). values holds the txid, the vout digits and the grant id as
// far as the tail reaches; the last is a prefix when open, and a value the
// tail does not reach is an empty prefix. Each set is counted, capped just
// above the base's size, and compared with the base entries it contains;
// validEntries holds base to distinct seals and grant ids.
func permittedCompletion(values []string, open bool, base []SealEntry, room int) bool {
	at := func(i int) (prefix string, final bool) {
		if i >= len(values) {
			return "", false
		}
		return values[i], i < len(values)-1 || !open
	}
	txid, _ := at(0)
	vout, voutFinal := at(1)
	grant, _ := at(2)
	// A set of limit values holds one base does not. The seal product stays
	// below 2^41: limit is under 2^10 and a vout set under 2^33.
	limit := uint64(len(base)) + 1
	seals := min(hexCompletions(len(txid), limit)*voutCompletions(vout, voutFinal, room), limit)
	grants := hexCompletions(len(grant), limit)
	var heldSeals, heldGrants uint64
	for _, b := range base {
		if strings.HasPrefix(b.TxID, txid) && voutIn(b.Vout, vout, voutFinal, room) {
			heldSeals++
		}
		if strings.HasPrefix(b.GrantID, grant) {
			heldGrants++
		}
	}
	return seals > heldSeals && grants > heldGrants
}

// hexCompletions counts the 64-digit lower-case hex values that start with a
// given n digits, capped at limit.
func hexCompletions(n int, limit uint64) uint64 {
	c := uint64(1)
	for ; n < 64 && c < limit; n++ {
		c *= 16
	}
	return min(c, limit)
}

// voutCompletions counts the vouts the writer can still write for digits d:
// the canonical decimal of a uint32 at most room digits long that is d, when
// d is final, or starts with d. voutIn reports whether v is one of them.
// TestVoutCompletions checks the two against each other.
func voutCompletions(d string, final bool, room int) uint64 {
	if final {
		if len(d) <= room {
			return 1
		}
		return 0
	}
	var prefix, count uint64
	if d != "" {
		prefix, _ = strconv.ParseUint(d, 10, 32)
	}
	for l := max(len(d), 1); l <= min(10, room); l++ {
		scale := pow10(l - len(d))
		lo, hi := prefix*scale, (prefix+1)*scale-1
		if l > 1 {
			lo = max(lo, pow10(l-1)) // no leading zero
		}
		hi = min(hi, math.MaxUint32)
		if hi >= lo {
			count += hi - lo + 1
		}
	}
	return count
}

func voutIn(v uint32, d string, final bool, room int) bool {
	s := strconv.FormatUint(uint64(v), 10)
	return len(s) <= room && (s == d || !final && strings.HasPrefix(s, d))
}

func pow10(n int) uint64 {
	p := uint64(1)
	for ; n > 0; n-- {
		p *= 10
	}
	return p
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
