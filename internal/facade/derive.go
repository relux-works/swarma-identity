package facade

import (
	"bytes"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

type DeriveRequest struct {
	Schema       string   `json:"schema"`
	Network      string   `json:"network"`
	XPub         string   `json:"xpub"`
	RelativePath []uint32 `json:"relative_path"`
	Start        uint32   `json:"start"`
	Count        uint32   `json:"count"`
	AddressType  string   `json:"address_type"`
}

type Address struct {
	RelativePath []uint32 `json:"relative_path"`
	Index        uint32   `json:"index"`
	PublicKeyHex string   `json:"public_key_hex"`
	Address      string   `json:"address"`
	scriptHex    string
}

func networkParams(network string) (*chaincfg.Params, bool) {
	p := &chaincfg.Params{Name: network, PubKeyHashAddrID: 111, Bech32HRPSegwit: "tn", HDPublicKeyID: [4]byte{4, 53, 135, 207}}
	switch network {
	case "main":
		p.PubKeyHashAddrID = 52
		p.Bech32HRPSegwit = "nc"
		p.HDPublicKeyID = [4]byte{4, 136, 178, 30}
	case "test":
	case "regtest":
		p.Bech32HRPSegwit = "ncrt"
	default:
		return nil, false
	}
	return p, true
}

// Only public keys and exact non-hardened indices enter the derivation library.
func Derive(r DeriveRequest) ([]Address, *Failure) {
	return deriveRange(r, 100)
}

func deriveRange(r DeriveRequest, limit uint32) ([]Address, *Failure) {
	p, ok := networkParams(r.Network)
	if !ok || r.Schema != DeriveSchema || len(r.XPub) > 120 || len(r.RelativePath) > 8 || r.Count == 0 || r.Count > limit || uint64(r.Start)+uint64(r.Count) > 1<<31 || (r.AddressType != "p2wpkh" && r.AddressType != "p2pkh") {
		return nil, fail("BAD_INPUT")
	}
	decoded := base58.Decode(r.XPub)
	if len(decoded) != 82 || !bytes.Equal(decoded[:4], p.HDPublicKeyID[:]) || (decoded[45] != 2 && decoded[45] != 3) {
		return nil, fail("BAD_INPUT")
	}
	if decoded[4] == 0 && !bytes.Equal(decoded[5:13], make([]byte, 8)) {
		return nil, fail("BAD_INPUT")
	}
	if int(decoded[4])+len(r.RelativePath)+1 > 255 {
		return nil, fail("BAD_INPUT")
	}
	key, err := hdkeychain.NewKeyFromString(r.XPub)
	if err != nil || key.IsPrivate() {
		return nil, fail("BAD_INPUT")
	}
	for _, index := range r.RelativePath {
		if index >= 1<<31 {
			return nil, fail("BAD_INPUT")
		}
		key, err = key.Derive(index)
		if err != nil {
			return nil, fail("BAD_INPUT")
		}
	}
	rows := make([]Address, 0, r.Count)
	for index := r.Start; uint64(index) < uint64(r.Start)+uint64(r.Count); index++ {
		child, e := key.Derive(index)
		if e != nil {
			return nil, fail("BAD_INPUT")
		}
		pub, e := child.ECPubKey()
		if e != nil {
			return nil, fail("BAD_INPUT")
		}
		serialized := pub.SerializeCompressed()
		h := btcutil.Hash160(serialized)
		var addr string
		var script string
		if r.AddressType == "p2wpkh" {
			a, e := btcutil.NewAddressWitnessPubKeyHash(h, p)
			if e != nil {
				return nil, fail("BAD_INPUT")
			}
			addr = a.EncodeAddress()
			script = "0014" + hex.EncodeToString(h)
		} else {
			a, e := btcutil.NewAddressPubKeyHash(h, p)
			if e != nil {
				return nil, fail("BAD_INPUT")
			}
			addr = a.EncodeAddress()
			script = "76a914" + hex.EncodeToString(h) + "88ac"
		}
		path := append(append([]uint32{}, r.RelativePath...), index)
		rows = append(rows, Address{RelativePath: path, Index: index, PublicKeyHex: hex.EncodeToString(serialized), Address: addr, scriptHex: script})
	}
	return rows, nil
}
