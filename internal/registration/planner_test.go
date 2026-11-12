package registration

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type coreSlot struct {
	TxID         string `json:"txid"`
	UnsignedHex  string `json:"unsigned_hex"`
	UnsignedPSBT string `json:"unsigned_psbt"`
	SignedVSize  uint32 `json:"vsize"`
}

func fixture(t *testing.T, mode string) (*Planner, ReservationInput, RevealInput, map[string]coreSlot, []byte, []byte) {
	t.Helper()
	read := func(name string) []byte {
		b, e := os.ReadFile(filepath.Join("testdata", "core28", name))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	var rm reservationManifest
	var vm revealManifest
	rawR, rawV := read(mode+"/reservation-manifest.json"), read(mode+"/reveal-manifest.json")
	if e := json.Unmarshal(rawR, &rm); e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(rawV, &vm); e != nil {
		t.Fatal(e)
	}
	p, e := NewPlanner(read("account-pin.json"), Profile{Network: rm.Network, Genesis: rm.Genesis, Policy: rm.Policy})
	if e != nil {
		t.Fatal(e)
	}
	var in ReservationInput
	in.Funding = Funding{TxHex: rm.Funding.TxHex, TxID: rm.Funding.TxID, Vout: rm.Funding.Vout, Path: rm.Transactions[0].Inputs[0].Path}
	for i, r := range rm.Registrations {
		in.Registrations[i] = Registration{Name: string(mustHex(t, r.NameHex)), RandHex: r.RandHex, NameOutputPath: r.NameOutputPath}
		if r.FutureValue.State == "fixed" {
			in.Registrations[i].FixedValue = mustHex(t, r.FutureValue.ValueHex)
		}
		in.ChangePaths[i], in.Fees[i] = rm.Transactions[i].Outputs[1].Path, 100000
	}
	var reveal RevealInput
	copy(reveal.Parents[:], vm.ParentResults)
	reveal.ValuesPin = read(mode + "/trusted-reveal-values-pin.json")
	for i := range 2 {
		reveal.ChangePaths[i], reveal.Fees[i] = vm.Transactions[i].Outputs[1].Path, 100000
	}
	var graph map[string]coreSlot
	if e := json.Unmarshal(read(mode+"/core-graph.json"), &graph); e != nil {
		t.Fatal(e)
	}
	return p, in, reveal, graph, rawR, rawV
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// Both release modes reproduce independently executed Core transaction/PSBT
// bytes and the agreed immutable phase manifests. This does not test signing,
// protected receipt provenance, presence, chain state or release permission.
func TestCore28PhaseParity(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		t.Run(mode, func(t *testing.T) {
			p, in, rv, graph, rawR, rawV := fixture(t, mode)
			r, e := p.Reserve(in, p.profile.Policy.CreatedAt+60)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(r.Manifest(), rawR) {
				t.Fatalf("reservation differs\ngot %s\nwant %s", r.Manifest(), rawR)
			}
			v, e := p.Reveal(r, rv, p.profile.Policy.CreatedAt+60)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(v.Manifest(), rawV) {
				t.Fatalf("reveal differs\ngot %s\nwant %s", v.Manifest(), rawV)
			}
			for _, plan := range []*Plan{r, v} {
				for _, tx := range plan.Transactions() {
					g := graph[tx.Slot]
					if tx.TxID != g.TxID || tx.UnsignedTxHex != g.UnsignedHex || tx.PSBT != g.UnsignedPSBT {
						t.Fatalf("slot%s differs from Core", tx.Slot)
					}
					if tx.UnsignedVSize != uint32(len(g.UnsignedHex)/2) || g.SignedVSize < tx.SignedVSizeMin || g.SignedVSize > tx.SignedVSizeMax {
						t.Fatalf("slot%s signed-size interval excludes actual Core size", tx.Slot)
					}
				}
			}
			for phase, plan := range map[string]*Plan{"reservation": r, "reveal": v} {
				b, e := os.ReadFile(filepath.Join("testdata", "core28", mode, phase+"-commitment.json"))
				if e != nil {
					t.Fatal(e)
				}
				var expected struct {
					PlanSHA256 string `json:"plan_sha256"`
				}
				if json.Unmarshal(b, &expected) != nil || plan.Hash() != expected.PlanSHA256 {
					t.Fatalf("%s plan commitment differs", phase)
				}
			}
			b := r.Manifest()
			b[0] ^= 1
			if !bytes.Equal(r.Manifest(), rawR) {
				t.Fatal("manifest aliases caller")
			}
			txs := r.Transactions()
			txs[0].PSBT = "changed"
			if r.Transactions()[0].PSBT == "changed" {
				t.Fatal("transaction aliases caller")
			}
		})
	}
}

// Each refusal has the valid Core-derived reservation as a nearby control;
// rejected planning returns no partial plan and cannot call external services.
func TestReservationRefusals(t *testing.T) {
	p, valid, _, _, _, _ := fixture(t, "all-four-before-release")
	for _, tc := range []struct {
		name string
		edit func(*ReservationInput)
		want error
	}{
		{"fee-cap-plus-one", func(x *ReservationInput) { x.Fees[0] = 100001 }, ErrPolicy},
		{"wrong-funding-txid", func(x *ReservationInput) { x.Funding.TxID = strings.Repeat("00", 32) }, ErrFunding},
		{"missing-funding-vout", func(x *ReservationInput) { x.Funding.Vout = 100 }, ErrFunding},
		{"wrong-owned-funding-path", func(x *ReservationInput) { x.Funding.Path = "m/84h/7h/0h/0/2" }, ErrFunding},
		{"trailing-previous-tx", func(x *ReservationInput) { x.Funding.TxHex += "00" }, ErrFunding},
		{"noncanonical-path", func(x *ReservationInput) { x.ChangePaths[0] = "m/84h/7h/0h/1/01" }, ErrInput},
		{"hardened-child", func(x *ReservationInput) { x.ChangePaths[0] = "m/84h/7h/0h/1/1h" }, ErrInput},
		{"wrong-name-pair", func(x *ReservationInput) { x.Registrations[1].Name = "d/another" }, ErrInput},
		{"short-opening", func(x *ReservationInput) { x.Registrations[0].RandHex = "11" }, ErrInput},
		{"future-id-value", func(x *ReservationInput) { x.Registrations[0].FixedValue = []byte("forbidden") }, ErrInput},
		{"missing-fixed-d", func(x *ReservationInput) { x.Registrations[1].FixedValue = nil }, ErrInput},
		{"fee-below-minimum", func(x *ReservationInput) { x.Fees[0] = 1 }, ErrPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := p.Reserve(valid, p.profile.Policy.CreatedAt+60); e != nil {
				t.Fatal(e)
			}
			bad := valid
			tc.edit(&bad)
			v, e := p.Reserve(bad, p.profile.Policy.CreatedAt+60)
			if !errors.Is(e, tc.want) || v != nil {
				t.Fatalf("plan=%v error=%v want=%v", v, e, tc.want)
			}
		})
	}
	for _, now := range []uint64{p.profile.Policy.CreatedAt - 1, p.profile.Policy.ReleaseNotAfter} {
		if x, e := p.Reserve(valid, now); !errors.Is(e, ErrPolicy) || x != nil {
			t.Fatal("accepted invalid planning time")
		}
	}
}

// Reveals preserve the fixed discovery value, immutable predecessor and
// aggregate cap; parent metadata is only a public reference, never custody proof.
func TestRevealRefusals(t *testing.T) {
	p, in, valid, _, _, _ := fixture(t, "two-stage")
	now := p.profile.Policy.CreatedAt + 60
	r, e := p.Reserve(in, now)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name string
		edit func(*RevealInput)
		want error
	}{
		{"wrong-parent-txid", func(x *RevealInput) { x.Parents[0].UnsignedTxID = strings.Repeat("00", 32) }, ErrParents},
		{"short-parent-request", func(x *RevealInput) { x.Parents[0].RequestID = "00" }, ErrParents},
		{"swapped-parents", func(x *RevealInput) { x.Parents[0], x.Parents[1] = x.Parents[1], x.Parents[0] }, ErrParents},
		{"wrong-predecessor", func(x *RevealInput) {
			x.ValuesPin = bytes.Replace(x.ValuesPin, []byte(r.Hash()), []byte(strings.Repeat("00", 32)), 1)
		}, ErrValue},
		{"unknown-values-pin-member", func(x *RevealInput) {
			x.ValuesPin = append(append([]byte{}, x.ValuesPin[:len(x.ValuesPin)-1]...), []byte(",\"extra\":1}")...)
		}, ErrValue},
		{"reveal-fee-cap-plus-one", func(x *RevealInput) { x.Fees[1] = 100001 }, ErrPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := p.Reveal(r, valid, now); e != nil {
				t.Fatal(e)
			}
			bad := valid
			tc.edit(&bad)
			v, e := p.Reveal(r, bad, now)
			if !errors.Is(e, tc.want) || v != nil {
				t.Fatalf("plan=%v error=%v want=%v", v, e, tc.want)
			}
		})
	}
	profile := p.profile
	profile.Policy.TotalFeeCapAtoms = "399999"
	tight, e := NewPlanner(p.pinBytes, profile)
	if e != nil {
		t.Fatal(e)
	}
	r, e = tight.Reserve(in, now)
	if e != nil {
		t.Fatal(e)
	}
	// The value pin binds the new reservation hash after the trusted cap changes.
	valid.ValuesPin = bytes.Replace(valid.ValuesPin, []byte(p.mustReservationHash(t, in, now)), []byte(r.Hash()), 1)
	if v, e := tight.Reveal(r, valid, now); !errors.Is(e, ErrPolicy) || v != nil {
		t.Fatal("aggregate cap+1 admitted")
	}
	valid.Fees[1] = 99999
	if _, e := tight.Reveal(r, valid, now); e != nil {
		t.Fatalf("aggregate cap inclusive: %v", e)
	}
}

func (p *Planner) mustReservationHash(t *testing.T, in ReservationInput, now uint64) string {
	t.Helper()
	r, e := p.Reserve(in, now)
	if e != nil {
		t.Fatal(e)
	}
	return r.Hash()
}

// The actual builder path extracts distinct social/grant keys and retains exact
// accepted bytes; malformed or noncanonical values cannot masquerade as either.
func TestTypedRegistrationValue(t *testing.T) {
	_, _, rv, _, _, _ := fixture(t, "all-four-before-release")
	var pin struct {
		Registrations []struct {
			ValueHex string `json:"value_hex"`
		} `json:"registrations"`
	}
	if e := json.Unmarshal(rv.ValuesPin, &pin); e != nil {
		t.Fatal(e)
	}
	combined := mustHex(t, pin.Registrations[0].ValueHex)
	socialOnly := mustHex(t, pin.Registrations[1].ValueHex)
	v, e := ParseValue(combined)
	if e != nil || v.SocialKey == "" || v.GrantKey == "" || v.SocialKey == v.GrantKey || !bytes.Equal(v.Bytes, combined) {
		t.Fatalf("combined extraction %v %v", v, e)
	}
	v, e = ParseValue(socialOnly)
	if e != nil || v.SocialKey == "" || v.GrantKey != "" || !bytes.Equal(v.Bytes, socialOnly) {
		t.Fatalf("nostr extraction %v %v", v, e)
	}
	for _, bad := range [][]byte{append(append([]byte{}, combined...), '\n'), []byte(`{"nostr":null}`), bytes.Replace(combined, []byte(`"nostr"`), []byte(`"Nostr"`), 1), append(append([]byte{}, combined[:len(combined)-1]...), []byte(`,"extra":1}`)...), []byte(strings.Repeat("x", 521)), bytes.Replace(combined, []byte(v.SocialKey), []byte(strings.Repeat("ff", 32)), 1)} {
		if _, e := ParseValue(bad); !errors.Is(e, ErrValue) {
			t.Fatalf("accepted malformed value, error=%v", e)
		}
	}
}

// Trusted profiles and public pins are explicit positive forms. Request data
// cannot change network/genesis/mode, and aliases/null/duplicates are refused.
func TestProfileAndPinBoundary(t *testing.T) {
	p, _, _, _, _, _ := fixture(t, "all-four-before-release")
	if _, e := NewPlanner(p.pinBytes, p.profile); e != nil {
		t.Fatal(e)
	}
	main := p.profile
	main.Network = "namecoin-mainnet"
	main.Genesis = MainnetGenesis
	if _, e := NewPlanner(p.pinBytes, main); e != nil {
		t.Fatal(e)
	}
	for _, edit := range []func(*Profile){func(x *Profile) { x.Genesis = MainnetGenesis }, func(x *Profile) { x.Network = "regtest" }, func(x *Profile) { x.Policy.ReleaseMode = "auto" }, func(x *Profile) { x.Policy.PerTxFeeCapAtoms = "100001" }, func(x *Profile) { x.Policy.TotalFeeCapAtoms = "400001" }, func(x *Profile) { x.Policy.ReleaseNotAfter = x.Policy.CreatedAt + 86401 }, func(x *Profile) { x.Policy.MinFeeRateAtomsPerKVB = "0100000" }, func(x *Profile) { x.Policy.DustRelayFeeAtomsPerKVB = "18446744073709551615" }} {
		x := p.profile
		edit(&x)
		if v, e := NewPlanner(p.pinBytes, x); !errors.Is(e, ErrPolicy) || v != nil {
			t.Fatalf("profile admitted: %v", e)
		}
	}
	for _, bad := range [][]byte{
		bytes.Replace(p.pinBytes, []byte(`"schema"`), []byte(`"Schema"`), 1),
		bytes.Replace(p.pinBytes, []byte(`"master_fingerprint":"3442193e"`), []byte(`"master_fingerprint":null`), 1),
		append(append([]byte{}, p.pinBytes[:len(p.pinBytes)-1]...), []byte(`,"schema":"keyvault-namecoin-account-pin/1"}`)...),
		bytes.Replace(p.pinBytes, []byte(p.pin.AccountXPub), []byte(strings.Repeat("1", 121)), 1),
	} {
		if v, e := NewPlanner(bad, p.profile); !errors.Is(e, ErrInput) || v != nil {
			t.Fatalf("pin admitted: %v", e)
		}
	}
	// Member order is not a pin parser restriction; exact selected bytes still
	// get a different commitment, rather than being silently reserialized.
	var m map[string]string
	if json.Unmarshal(p.pinBytes, &m) != nil {
		t.Fatal("fixture pin")
	}
	reordered, _ := json.Marshal(m)
	other, e := NewPlanner(reordered, p.profile)
	if e != nil || other.pinHash == p.pinHash {
		t.Fatalf("legitimate reordered pin: %v", e)
	}
}

// A fixed discovery value cannot be replaced by changing its matching public
// hash in the reveal pin; empty/opaque id values and duplicate pins also refuse.
func TestFinalValueLineage(t *testing.T) {
	p, in, reveal, _, _, _ := fixture(t, "all-four-before-release")
	now := p.profile.Policy.CreatedAt + 60
	r, e := p.Reserve(in, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := p.Reveal(r, reveal, now); e != nil {
		t.Fatal(e)
	}
	var pin struct {
		Schema      string `json:"schema"`
		Reservation string `json:"reservation_plan_sha256"`
		Rows        []struct {
			Name  string `json:"name_hex"`
			Value string `json:"value_hex"`
			Hash  string `json:"value_sha256"`
		} `json:"registrations"`
	}
	if json.Unmarshal(reveal.ValuesPin, &pin) != nil {
		t.Fatal("fixture pin")
	}
	for _, index := range []int{0, 1} {
		x := pin
		x.Rows = append(x.Rows[:0:0], pin.Rows...)
		x.Rows[index].Value = hex.EncodeToString([]byte(`{"changed":true}`))
		x.Rows[index].Hash = digest([]byte(`{"changed":true}`))
		bad := reveal
		bad.ValuesPin, _ = json.Marshal(x)
		if v, e := p.Reveal(r, bad, now); !errors.Is(e, ErrValue) || v != nil {
			t.Fatalf("changed value%d admitted: %v", index, e)
		}
	}
	bad := reveal
	bad.ValuesPin = append(append([]byte{}, reveal.ValuesPin[:len(reveal.ValuesPin)-1]...), []byte(`,"schema":"keyvault-namecoin-reveal-values/1"}`)...)
	if v, e := p.Reveal(r, bad, now); !errors.Is(e, ErrValue) || v != nil {
		t.Fatal("duplicate pin admitted")
	}
}

// Core's dust threshold uses the whole prefixed output and ceils fee/1000.
// A tight but valid funding amount succeeds; one atom below its change dust
// threshold fails without any partial plan. Parent output overflow also refuses.
func TestFundingAndDustBounds(t *testing.T) {
	p, in, _, _, _, _ := fixture(t, "all-four-before-release")
	now := p.profile.Policy.CreatedAt + 60
	tx, e := parseTx(in.Funding.TxHex)
	if e != nil {
		t.Fatal(e)
	}
	// Two reservations need two name amounts, two fees, then294 atoms of
	// ordinary P2WPKH change at dust rate3000 atoms/kvB.
	tx.TxOut[0].Value = int64(2*nameAmount + in.Fees[0] + in.Fees[1] + 294)
	in.Funding.TxHex = txHex(tx)
	in.Funding.TxID = tx.TxHash().String()
	if _, e := p.Reserve(in, now); e != nil {
		t.Fatalf("dust boundary positive: %v", e)
	}
	tx.TxOut[0].Value--
	in.Funding.TxHex = txHex(tx)
	in.Funding.TxID = tx.TxHash().String()
	if v, e := p.Reserve(in, now); !errors.Is(e, ErrPolicy) || v != nil {
		t.Fatalf("dust-1 admitted: %v", e)
	}
	tx.TxOut[0].Value = int64(maxMoney) + 1
	in.Funding.TxHex = txHex(tx)
	in.Funding.TxID = tx.TxHash().String()
	if v, e := p.Reserve(in, now); !errors.Is(e, ErrFunding) || v != nil {
		t.Fatal("amount overflow admitted")
	}
}

// The same complete funding transaction is accepted with or without witness;
// manifests/PSBTs retain its canonical non-witness body and stable txid.
func TestFundingWitnessSerialization(t *testing.T) {
	p, in, _, _, rawR, _ := fixture(t, "all-four-before-release")
	b, e := os.ReadFile("testdata/core28/all-four-before-release/funding-signed-full.json")
	if e != nil {
		t.Fatal(e)
	}
	var final struct {
		Hex string `json:"hex"`
	}
	if json.Unmarshal(b, &final) != nil || final.Hex == "" {
		t.Fatal("fixture funding")
	}
	in.Funding.TxHex = final.Hex
	r, e := p.Reserve(in, p.profile.Policy.CreatedAt+60)
	if e != nil || !bytes.Equal(r.Manifest(), rawR) {
		t.Fatalf("witness funding changed plan: %v", e)
	}
}

// Both conservative signed-size endpoints affect rate admission. A valid
// adjacent profile passes; one unit across the corresponding bound refuses.
func TestSignedRateIntervalEndpoints(t *testing.T) {
	p, in, _, _, _, _ := fixture(t, "all-four-before-release")
	now := p.profile.Policy.CreatedAt + 60
	r, e := p.Reserve(in, now)
	if e != nil {
		t.Fatal(e)
	}
	tx := r.Transactions()[0]
	scaled := in.Fees[0] * 1000
	minRate := scaled / uint64(tx.SignedVSizeMax)
	maxRate := (scaled + uint64(tx.SignedVSizeMin) - 1) / uint64(tx.SignedVSizeMin)
	for _, lower := range []bool{true, false} {
		profile := p.profile
		if lower {
			profile.Policy.MinFeeRateAtomsPerKVB = strconv.FormatUint(minRate, 10)
		} else {
			profile.Policy.MaxFeeRateAtomsPerKVB = strconv.FormatUint(maxRate, 10)
		}
		good, e := NewPlanner(p.pinBytes, profile)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := good.Reserve(in, now); e != nil {
			t.Fatalf("valid endpoint: %v", e)
		}
		if lower {
			profile.Policy.MinFeeRateAtomsPerKVB = strconv.FormatUint(minRate+1, 10)
		} else {
			profile.Policy.MaxFeeRateAtomsPerKVB = strconv.FormatUint(maxRate-1, 10)
		}
		bad, e := NewPlanner(p.pinBytes, profile)
		if e != nil {
			t.Fatal(e)
		}
		if plan, e := bad.Reserve(in, now); !errors.Is(e, ErrPolicy) || plan != nil {
			t.Fatalf("rate endpoint violation admitted: %v", e)
		}
	}
}
