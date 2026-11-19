package facade

import (
	"bytes"
	"context"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const sealJournalSchema = "swarma-identity/seal-journal/1"
const sealJournalMax = 512 << 10

type sealStep struct {
	State     string `json:"state"`
	Attempted bool   `json:"broadcast_attempted"`
	At        string `json:"at"`
}

type sealJournal struct {
	Schema        string           `json:"schema"`
	Request       SealPlanRequest  `json:"request"`
	Plan          GrantTransaction `json:"plan"`
	GrantID       string           `json:"grant_id"`
	State         string           `json:"state"`
	SignedTxHex   string           `json:"signed_tx_hex"`
	Attempted     bool             `json:"broadcast_attempted"`
	Confirmations int64            `json:"confirmations"`
	ObservedTip   Tip              `json:"observed_tip"`
	History       []sealStep       `json:"history"`
	guard         *sealLedger
}

func openSealJournal(ctx context.Context, path string, request *SealPlanRequest) (*sealJournal, *Failure) {
	dir, name, err := openLedgerDir(path)
	if err != nil {
		return nil, refuse("SEAL_JOURNAL_FILE")
	}
	guard := &sealLedger{dir: dir, path: path, name: name}
	good := false
	defer func() {
		if !good {
			guard.close()
		}
	}()
	if lockDir(ctx, dir) != nil || !guard.bound() {
		return nil, refuse("SEAL_JOURNAL_FILE")
	}
	guard.locked = true
	leftovers, err := guard.leftovers()
	if err != nil {
		return nil, refuse("SEAL_JOURNAL_FILE")
	}
	if len(leftovers) != 0 {
		return nil, refuse("SEAL_JOURNAL_RECOVERY_REQUIRED")
	}
	journal := &sealJournal{guard: guard}
	fd, err := openAt(dir, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err == unix.ENOENT && request != nil {
		id, plan, failure := sealPlan(*request)
		if failure != nil {
			return nil, failure
		}
		if name != id+".seal.json" {
			return nil, refuse("SEAL_JOURNAL_NAME")
		}
		journal.Schema, journal.Request, journal.Plan, journal.GrantID, journal.State = sealJournalSchema, *request, *plan, id, "planned"
		if failure := journal.save(); failure != nil {
			return nil, failure
		}
	} else {
		if err != nil {
			return nil, refuse("SEAL_JOURNAL_FILE")
		}
		file := os.NewFile(uintptr(fd), name)
		defer file.Close()
		stat, err := file.Stat()
		if err != nil || !ownerOnlyRegular(stat) || stat.Size() < 1 || stat.Size() > sealJournalMax {
			return nil, refuse("SEAL_JOURNAL_FILE")
		}
		raw, err := io.ReadAll(io.LimitReader(file, sealJournalMax+1))
		if err != nil || int64(len(raw)) != stat.Size() || DecodeStrict(raw, journal) != nil {
			return nil, refuse("SEAL_JOURNAL_FILE")
		}
		var held unix.Stat_t
		if unix.Fstat(fd, &held) != nil {
			return nil, refuse("SEAL_JOURNAL_FILE")
		}
		guard.held = &held
		if failure := journal.validate(); failure != nil {
			return nil, failure
		}
		if name != journal.GrantID+".seal.json" {
			return nil, refuse("SEAL_JOURNAL_NAME")
		}
		if request != nil {
			oldBytes, _ := compactJSON(journal.Request)
			newBytes, _ := compactJSON(request)
			if !bytes.Equal(oldBytes, newBytes) {
				return nil, refuse("SEAL_JOURNAL_CONFLICT")
			}
		}
	}
	good = true
	return journal, nil
}

func (journal *sealJournal) validate() *Failure {
	id, plan, failure := sealPlan(journal.Request)
	if failure != nil {
		return failure
	}
	actual, _ := compactJSON(journal.Plan)
	want, _ := compactJSON(plan)
	if journal.Schema != sealJournalSchema || id != journal.GrantID || !bytes.Equal(actual, want) || len(journal.History) == 0 || len(journal.History) > 1024 || journal.Confirmations < 0 {
		return refuse("SEAL_JOURNAL_INVALID")
	}
	previous := sealStep{}
	for index, step := range journal.History {
		if _, err := time.Parse(time.RFC3339Nano, step.At); err != nil {
			return refuse("SEAL_JOURNAL_INVALID")
		}
		valid := false
		if index == 0 {
			valid = step.State == "planned" && !step.Attempted
		} else {
			switch previous.State + "/" + step.State {
			case "planned/signed", "signed/accepted":
				valid = !previous.Attempted && !step.Attempted
			case "accepted/accepted":
				valid = !previous.Attempted && step.Attempted
			case "accepted/broadcast":
				valid = previous.Attempted && step.Attempted
			case "broadcast/broadcast", "broadcast/confirmed", "confirmed/confirmed", "confirmed/broadcast":
				valid = previous.Attempted && step.Attempted
			}
		}
		if !valid {
			return refuse("SEAL_JOURNAL_INVALID")
		}
		previous = step
	}
	if previous.State != journal.State || previous.Attempted != journal.Attempted {
		return refuse("SEAL_JOURNAL_INVALID")
	}
	if journal.State == "planned" {
		if journal.SignedTxHex != "" {
			return refuse("SEAL_JOURNAL_INVALID")
		}
	} else if failure := journal.verifySigned(); failure != nil {
		return failure
	}
	if journal.State == "confirmed" && (journal.Confirmations < journal.Request.MinConfirmations || !hashValid(journal.ObservedTip.Hash) || journal.ObservedTip.Height < 0) {
		return refuse("SEAL_JOURNAL_INVALID")
	}
	if (journal.State == "planned" || journal.State == "signed" || journal.State == "accepted") && (journal.Confirmations != 0 || journal.ObservedTip != (Tip{})) {
		return refuse("SEAL_JOURNAL_INVALID")
	}
	return nil
}

func (journal *sealJournal) save() *Failure {
	step := sealStep{State: journal.State, Attempted: journal.Attempted, At: time.Now().UTC().Format(time.RFC3339Nano)}
	if len(journal.History) == 0 || journal.History[len(journal.History)-1].State != step.State || journal.History[len(journal.History)-1].Attempted != step.Attempted {
		journal.History = append(journal.History, step)
	}
	if failure := journal.validate(); failure != nil {
		return failure
	}
	raw, ok := compactJSON(journal)
	if !ok || len(raw) > sealJournalMax {
		return refuse("SEAL_JOURNAL_FILE")
	}
	if failure := journal.guard.commitDocument(raw); failure != nil {
		return refuse("SEAL_JOURNAL_FILE")
	}
	return nil
}
