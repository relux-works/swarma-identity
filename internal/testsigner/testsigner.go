// Package testsigner is a TEST-ONLY BIP-340 signer standing in for the
// external signers (a Secure Enclave keyvault, a Mac Keychain, a NIP-07
// extension) that hold real grant and Nostr keys. The swarma-identity binary
// never imports it; a test asserts that.
//
// It loads only the secret keys published in the BIP-340 test vectors and
// refuses every other key, so it cannot be used with a real key. The key file
// must be an owner-only (0600) regular file of exactly 32 bytes at an absolute
// path with no symlink in any component.
package testsigner

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// PublishedKeys are the x-only public keys of BIP-340 test vectors 0 to 3,
// whose secret keys are published in BIP-340 and are never anyone's keys.
var PublishedKeys = map[string]int{
	"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9": 0,
	"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659": 1,
	"dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8": 2,
	"25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517": 3,
}

var (
	ErrKeyPath    = errors.New("KEY_PATH")
	ErrKeyFile    = errors.New("KEY_FILE")
	ErrNotTestKey = errors.New("KEY_NOT_TEST_VECTOR")
	ErrDigest     = errors.New("DIGEST")
)

// Signer holds one published test key in memory until Close.
type Signer struct {
	key    *btcec.PrivateKey
	public string
}

func ownerOnly(st os.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && st.Mode().IsRegular() && st.Mode().Perm() == 0600 && sys.Uid == uint32(os.Getuid()) && sys.Nlink == 1
}

// Open reads a 32-byte test key file under the custody rules above.
func Open(path string) (*Signer, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrKeyPath
	}
	if real, err := filepath.EvalSymlinks(path); err != nil || real != path {
		return nil, ErrKeyPath
	}
	before, err := os.Lstat(path)
	if err != nil || !ownerOnly(before) || before.Size() != 32 {
		return nil, ErrKeyFile
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrKeyFile
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) || !ownerOnly(info) || info.Size() != 32 {
		return nil, ErrKeyFile
	}
	raw, err := io.ReadAll(io.LimitReader(f, 33))
	defer clear(raw)
	if err != nil || len(raw) != 32 {
		return nil, ErrKeyFile
	}
	if after, err := f.Stat(); err != nil || !ownerOnly(after) || after.Size() != 32 {
		return nil, ErrKeyFile
	}
	key, _ := btcec.PrivKeyFromBytes(raw)
	public := hex.EncodeToString(schnorr.SerializePubKey(key.PubKey()))
	if _, ok := PublishedKeys[public]; !ok {
		key.Zero()
		return nil, ErrNotTestKey
	}
	return &Signer{key, public}, nil
}

// PublicKey returns the x-only public key in 64 lowercase hex.
func (s *Signer) PublicKey() string { return s.public }

// Sign returns a BIP-340 signature, 128 lowercase hex, over a 32-byte digest
// given in 64 lowercase hex, with aux_rand of 32 zero bytes as the LIP-0013
// vectors use, so every signature is reproducible.
func (s *Signer) Sign(digestHex string) (string, error) {
	return s.SignAux(digestHex, [32]byte{})
}

// SignAux signs with explicit aux_rand, for checks against BIP-340 vectors.
func (s *Signer) SignAux(digestHex string, aux [32]byte) (string, error) {
	digest, err := hex.DecodeString(digestHex)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != digestHex {
		return "", ErrDigest
	}
	sig, err := schnorr.Sign(s.key, digest, schnorr.CustomNonce(aux))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig.Serialize()), nil
}

// Close zeroes the in-memory key.
func (s *Signer) Close() {
	if s.key != nil {
		s.key.Zero()
	}
}
