package facade

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// Public BIP84 account fixture; no seed or private derivation is used by these tests.
const bip84Public = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"

func publicFixture(t *testing.T, version [4]byte) string {
	t.Helper()
	payload, _, err := base58.CheckDecode(bip84Public)
	if err != nil {
		t.Fatal(err)
	}
	// CheckDecode separates one version byte, so retain the other three below.
	copy(payload[:3], version[1:])
	return base58.CheckEncode(payload, version[0])
}

func validDerivation(t *testing.T) DeriveRequest {
	return DeriveRequest{Schema: DeriveSchema, Network: "main", XPub: publicFixture(t, [4]byte{4, 136, 178, 30}), RelativePath: []uint32{0}, Start: 0, Count: 2, AddressType: "p2wpkh"}
}

// BIP32 vector 2's public root -> /0 is checked against the independently
// published child serialization, without deriving or loading a private key.
func TestBIP32PublicVector(t *testing.T) {
	const parent = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	const child = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
	payload, _, err := base58.CheckDecode(child)
	if err != nil {
		t.Fatal(err)
	}
	r := DeriveRequest{Schema: DeriveSchema, Network: "main", XPub: parent, RelativePath: []uint32{}, Count: 1, AddressType: "p2pkh"}
	rows, f := Derive(r)
	if f != nil || len(rows) != 1 || rows[0].PublicKeyHex != hex.EncodeToString(payload[44:]) || rows[0].Index != 0 || len(rows[0].RelativePath) != 1 || rows[0].RelativePath[0] != 0 {
		t.Fatal("BIP32 public vector mismatch")
	}
}

// The BIP84 public-key and witness-program vectors agree at exact requested indices;
// Namecoin changes the address HRP, not the underlying public derivation.
func TestBIP84PublicVectors(t *testing.T) {
	r := validDerivation(t)
	got, failure := Derive(r)
	if failure != nil {
		t.Fatal(failure.Code)
	}
	wantKeys := []string{"0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c", "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77"}
	wantBTC := []string{"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"}
	if len(got) != 2 {
		t.Fatalf("rows=%d", len(got))
	}
	for i, row := range got {
		if row.PublicKeyHex != wantKeys[i] || row.Index != uint32(i) || len(row.RelativePath) != 2 || row.RelativePath[0] != 0 || row.RelativePath[1] != uint32(i) {
			t.Fatalf("wrong public vector at %d", i)
		}
		hrp, data, err := bech32.Decode(row.Address)
		if err != nil || hrp != "nc" || data[0] != 0 {
			t.Fatalf("invalid Namecoin witness encoding %d", i)
		}
		btcHRP, btcData, err := bech32.Decode(wantBTC[i])
		if err != nil || btcHRP != "bc" || string(data) != string(btcData) {
			t.Fatalf("BIP84 program mismatch %d", i)
		}
		program, err := bech32.ConvertBits(data[1:], 5, 8, false)
		if err != nil || len(program) != 20 || row.scriptHex != "0014"+hex.EncodeToString(program) {
			t.Fatalf("wrong script %d", i)
		}
	}
}

// A nearby valid public request is retained for each forbidden input family.
// Refusal returns no partial derived address set and never echoes supplied key material.
func TestDeriveRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(*DeriveRequest)
	}{
		{"network", func(r *DeriveRequest) { r.Network = "bitcoin" }},
		{"address-type", func(r *DeriveRequest) { r.AddressType = "p2tr" }},
		{"hardened-path", func(r *DeriveRequest) { r.RelativePath = []uint32{1 << 31} }},
		{"hardened-start", func(r *DeriveRequest) { r.Start = 1 << 31 }},
		{"overflow-range", func(r *DeriveRequest) { r.Start = 1<<31 - 1; r.Count = 2 }},
		{"empty-range", func(r *DeriveRequest) { r.Count = 0 }},
		{"large-range", func(r *DeriveRequest) { r.Count = 101 }},
		{"deep-path", func(r *DeriveRequest) { r.RelativePath = make([]uint32, 9) }},
		{"wrong-version", func(r *DeriveRequest) { r.XPub = publicFixture(t, [4]byte{4, 53, 135, 207}) }},
		{"checksum", func(r *DeriveRequest) {
			last := "1"
			if strings.HasSuffix(r.XPub, last) {
				last = "2"
			}
			r.XPub = r.XPub[:len(r.XPub)-1] + last
		}},
		{"invalid-point", func(r *DeriveRequest) {
			b, v, _ := base58.CheckDecode(r.XPub)
			for i := 45; i < len(b); i++ {
				b[i] = 255
			}
			r.XPub = base58.CheckEncode(b, v)
		}},
		{"inconsistent-root", func(r *DeriveRequest) {
			b, v, _ := base58.CheckDecode(r.XPub)
			b[3] = 0
			b[4] = 1
			r.XPub = base58.CheckEncode(b, v)
		}},
		{"depth-overflow", func(r *DeriveRequest) {
			b, v, _ := base58.CheckDecode(r.XPub)
			b[3] = 255
			r.XPub = base58.CheckEncode(b, v)
		}},
		{"private-payload", func(r *DeriveRequest) {
			b, v, e := base58.CheckDecode(r.XPub)
			if e != nil {
				t.Fatal(e)
			}
			b[44] = 0
			r.XPub = base58.CheckEncode(b, v)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validDerivation(t)
			tc.change(&r)
			rows, f := Derive(r)
			if f == nil || f.Code != "BAD_INPUT" || len(rows) != 0 || strings.Contains(f.Message, r.XPub) {
				t.Fatalf("wrong refusal: %#v", f)
			}
			if rows, f := Derive(validDerivation(t)); f != nil || len(rows) != 2 {
				t.Fatal("positive control refused")
			}
		})
	}
}

// Explicit networks select the pinned nc28.0 HRPs; P2PKH remains a separate positive.
func TestNetworkAddressProfiles(t *testing.T) {
	for _, tc := range []struct {
		network, hrp string
		version      [4]byte
	}{{"main", "nc", [4]byte{4, 136, 178, 30}}, {"test", "tn", [4]byte{4, 53, 135, 207}}, {"regtest", "ncrt", [4]byte{4, 53, 135, 207}}} {
		r := validDerivation(t)
		r.Network = tc.network
		r.XPub = publicFixture(t, tc.version)
		r.Count = 1
		rows, f := Derive(r)
		if f != nil {
			t.Fatal(f.Code)
		}
		hrp, _, err := bech32.Decode(rows[0].Address)
		if err != nil || hrp != tc.hrp {
			t.Fatal("wrong HRP")
		}
		r.AddressType = "p2pkh"
		rows, f = Derive(r)
		if f != nil {
			t.Fatal(f.Code)
		}
		payload, v, err := base58.CheckDecode(rows[0].Address)
		want := byte(111)
		if tc.network == "main" {
			want = 52
		}
		if err != nil || v != want || len(payload) != 20 {
			t.Fatal("wrong P2PKH")
		}
	}
}

// Duplicate/aliased members and invalid JSON refuse before any derivation.
func TestStrictPublicRequest(t *testing.T) {
	for _, raw := range []string{`{"schema":"x","schema":"x"}`, `{"schema":"x","\u0073chema":"x"}`, `{"Schema":"x"}`, `{"schema":null}`, `{"schema":"x"} {}`, string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'})} {
		var req DeriveRequest
		if DecodeStrict([]byte(raw), &req) == nil {
			t.Fatal("accepted invalid public request")
		}
	}
}

// The JSON boundary preserves valid surrogate pairs and literal escape text,
// while refusing a lone surrogate rather than normalizing an exact name.
func TestUnicodeEscapes(t *testing.T) {
	for _, raw := range []string{`{"name":"\ud83d\ude00"}`, `{"name":"\\ud800"}`, `{"name":"d/example"}`} {
		var r struct {
			Name string `json:"name"`
		}
		if DecodeStrict([]byte(raw), &r) != nil {
			t.Fatal("valid unicode refused")
		}
	}
	for _, raw := range []string{`{"name":"\ud800"}`, `{"name":"\udc00"}`, `{"name":"\ud800\u0041"}`} {
		var r struct {
			Name string `json:"name"`
		}
		if DecodeStrict([]byte(raw), &r) == nil {
			t.Fatal("lone surrogate admitted")
		}
	}
}

// This independent output checker detects wrong HRP, checksum family, checksum
// corruption and mixed case beside a valid v0 address. Addresses are outputs,
// not an additional caller-input API.
func TestWitnessEncodingCheckerControls(t *testing.T) {
	rows, f := Derive(validDerivation(t))
	if f != nil {
		t.Fatal(f.Code)
	}
	valid := rows[0].Address
	_, data, _ := bech32.Decode(valid)
	wrongHRP, _ := bech32.Encode("bc", data)
	wrongFamily, _ := bech32.EncodeM("nc", data)
	last := "q"
	if strings.HasSuffix(valid, last) {
		last = "p"
	}
	check := func(address string) bool {
		hrp, d, v, e := bech32.DecodeGeneric(address)
		if e != nil || v != bech32.Version0 || hrp != "nc" || address != strings.ToLower(address) || len(d) == 0 || d[0] != 0 {
			return false
		}
		p, e := bech32.ConvertBits(d[1:], 5, 8, false)
		return e == nil && len(p) == 20
	}
	if !check(valid) {
		t.Fatal("valid v0 refused")
	}
	for _, a := range []string{wrongHRP, wrongFamily, valid[:len(valid)-1] + last, "NC" + valid[2:]} {
		if check(a) {
			t.Fatal("encoding control was not detected")
		}
	}
}
