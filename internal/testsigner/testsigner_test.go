package testsigner

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// BIP-340 test vectors 0 to 3 (bip-0340/test-vectors.csv): secret key,
// public key, aux_rand, message and signature, all published.
var bip340 = []struct{ secret, public, aux, msg, sig string }{
	{"0000000000000000000000000000000000000000000000000000000000000003", "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"},
	{"b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "0000000000000000000000000000000000000000000000000000000000000001", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a"},
	{"c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9", "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8", "c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906", "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c", "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7"},
	{"0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710", "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3"},
}

// canonicalTemp returns a fresh test directory with every symlink resolved.
// The key-file and ledger rules refuse any symlink path component, and on
// macOS the default temporary directory is under /var, a symlink to
// /private/var. Without this, every custody negative there would refuse for
// the wrong reason and every positive control would fail.
func canonicalTemp(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func keyFile(t *testing.T, dir, secret string, mode os.FileMode) string {
	t.Helper()
	raw, _ := hex.DecodeString(secret)
	p := filepath.Join(dir, "key")
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// Claim: the signer reproduces the published BIP-340 vectors 0 to 3 byte for
// byte (key, aux_rand, message → signature), and Sign uses aux_rand of 32 zero
// bytes, which reproduces vector 0 and the LIP-0013 E-V1 envelope signature.
func TestSignerReproducesBIP340Vectors(t *testing.T) {
	for i, v := range bip340 {
		s, err := Open(keyFile(t, canonicalTemp(t), v.secret, 0600))
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		var aux [32]byte
		b, _ := hex.DecodeString(v.aux)
		copy(aux[:], b)
		sig, err := s.SignAux(v.msg, aux)
		if err != nil || sig != v.sig || s.PublicKey() != v.public || PublishedKeys[v.public] != i {
			t.Fatalf("vector %d differs", i)
		}
		s.Close()
	}
	s, _ := Open(keyFile(t, canonicalTemp(t), bip340[0].secret, 0600))
	defer s.Close()
	if sig, _ := s.Sign(bip340[0].msg); sig != bip340[0].sig {
		t.Fatal("Sign does not use zero aux_rand")
	}
	// LIP-0013 vector E-V1-instruct: event id and signature by bip340-0.
	if sig, _ := s.Sign("8df013a2bad205050b5a032bcda457b08b52a31acf0651bfdd0292c70895fee4"); sig != "a97b41107ff29d05e797cfbcf2e26db0a670d3d15122cbb371ab029dcdabd218dceab2ff46106e702df8e00e7c47b58476666349fbe5d70df2fea59a75a3dc37" {
		t.Fatal("E-V1 envelope signature not reproduced")
	}
	if _, err := s.Sign("ABCD"); !errors.Is(err, ErrDigest) {
		t.Fatal("malformed digest accepted")
	}
}

// Claim: only an owner-only 0600 regular 32-byte file at a clean absolute path
// without any symlink component opens, and only for a published test key. A
// 0644, 0640 or 0400 file, a symlinked file, a file behind a symlinked
// directory, a relative path, a wrong size, a directory and a non-vector key
// (the secret 1, whose public key is the generator) are refused.
func TestSignerKeyFileCustody(t *testing.T) {
	good := bip340[1].secret
	if s, err := Open(keyFile(t, canonicalTemp(t), good, 0600)); err != nil {
		t.Fatalf("neighbour 0600 key refused: %v", err)
	} else {
		s.Close()
	}
	for _, mode := range []os.FileMode{0644, 0640, 0400} {
		if _, err := Open(keyFile(t, canonicalTemp(t), good, mode)); !errors.Is(err, ErrKeyFile) {
			t.Fatalf("mode %o: %v", mode, err)
		}
	}
	dir := canonicalTemp(t)
	real := filepath.Join(dir, "real")
	os.Mkdir(real, 0700)
	keyFile(t, real, good, 0600)
	os.Symlink(real, filepath.Join(dir, "linkdir"))
	if _, err := Open(filepath.Join(dir, "linkdir", "key")); !errors.Is(err, ErrKeyPath) {
		t.Fatalf("key behind a symlinked directory: %v", err)
	}
	target := keyFile(t, dir, good, 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	if _, err := Open(link); !errors.Is(err, ErrKeyPath) {
		t.Fatalf("symlinked key file: %v", err)
	}
	if _, err := Open("key"); !errors.Is(err, ErrKeyPath) {
		t.Fatal("relative path accepted")
	}
	if _, err := Open(dir + "/./real/key"); !errors.Is(err, ErrKeyPath) {
		t.Fatal("unclean path accepted")
	}
	short := filepath.Join(canonicalTemp(t), "short")
	os.WriteFile(short, make([]byte, 31), 0600)
	if _, err := Open(short); !errors.Is(err, ErrKeyFile) {
		t.Fatal("31-byte key accepted")
	}
	if _, err := Open(canonicalTemp(t)); !errors.Is(err, ErrKeyFile) {
		t.Fatal("directory accepted")
	}
	one := "0000000000000000000000000000000000000000000000000000000000000001"
	if _, err := Open(keyFile(t, canonicalTemp(t), one, 0600)); !errors.Is(err, ErrNotTestKey) {
		t.Fatalf("non-vector key: %v", err)
	}
}
