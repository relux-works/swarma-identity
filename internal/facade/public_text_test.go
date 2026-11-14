package facade

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Audit tokens are assembled in fragments so this checker does not add a new
// personal example to the public source. These are bounded known identifiers,
// not a claim to recognize every possible person's name.
var personalTokens = []string{
	"iv" + "an", "opa" + "rin", "alex" + "ey", "alex" + "ei",
	"gri" + "gorev", "gri" + "goryev", "ив" + "ан", "оп" + "арин",
	"алек" + "сей", "гри" + "горьев",
}
var vectorNameTokens = []string{"sa" + "toshi", "naka" + "moto", "al" + "an", "tur" + "ing", "ali" + "ce", "bo" + "b", "ca" + "rol", "pie" + "ter", "jo" + "nas"}
var personalPattern = regexp.MustCompile("(?i)(" + strings.Join(personalTokens, "|") + "|\\b(" + strings.Join(vectorNameTokens, "|") + ")\\b)")

// Whole-file exemptions are immutable provenance/legal records, not directory
// exclusions. Any byte change requires a renewed explicit exception decision.
var personalFilePins = map[string]string{
	"NOTICE": "83a47352ea77cd23d88452932aaf3b8e108fa270fb2582c238d4133a418067f6",
	"internal/facade/testdata/lip0013/trust-vectors.json": "9c29cddd739d56c5d15f4663c3cc923c6ea016730fc62634bff4b4214bf27ff8",
}

// This one line contains the independently sourced mainnet agent value at tip
// 851209. Only its exact source bytes qualify, not the rest of identity_test.go.
const publishedAgentSourceSHA256 = "a7782199120f99f27fd699197eac0896257c81d0831f5a72e16de5f8b117545e"

// Published RFC6979/low-S messages must retain their exact signed bytes.
// Only these three source lines qualify; the signer test file is not exempt.
var personalLinePins = map[string][]string{
	"internal/facade/identity_test.go": {publishedAgentSourceSHA256},
	"internal/keysign/keysign_test.go": {"3b6389119ff7a15d8e1cddef05ee1dad9e74c80e8c4cf3d3f1ede98004f2c9ff", "cedf37ab744d21bf240a04d3e4af6aafef65b6fbb644702a6a0a0fc9828647b2", "b5a991cf6e27713311780780ee3620cb8962711dbec91ebed22373b556d1f7db"},
}

func personalViolations(path string, data []byte) []string {
	filePinned := personalFilePins[path] != "" && fmt.Sprintf("%x", sha256.Sum256(data)) == personalFilePins[path]
	var violations []string
	for i, line := range bytes.Split(data, []byte("\n")) {
		if personalPattern.Match(line) {
			linePinned := false
			for _, pin := range personalLinePins[path] {
				if fmt.Sprintf("%x", sha256.Sum256(line)) == pin {
					linePinned = true
				}
			}
			if !filePinned && !linePinned {
				violations = append(violations, fmt.Sprintf("%s:%d", path, i+1))
			}
		}
	}
	return violations
}

// Claim: every tracked source/document/fixture path is scanned for the bounded
// known identifiers; only unchanged external vectors, mainnet/spec message lines and
// legal attribution are exempt. Positive marker and neutral controls make a
// disabled scanner fail this same regression. Symlinks are scanned as link
// text, never followed outside the tree. Ignored scratch/Git history are outside
// this public-source contract; this is not a general personal-data detector.
func TestPublicPersonalIdentifiersWholeTree(t *testing.T) {
	for _, token := range append(append([]string{}, personalTokens...), vectorNameTokens...) {
		if got := personalViolations("README.md", []byte("the owner\n"+strings.ToUpper(token))); len(got) != 1 || got[0] != "README.md:2" {
			t.Fatal("known-positive identifier control was not detected")
		}
	}
	if got := personalViolations("README.md", []byte("the owner; example-owner; owner-grant-1; works.relux.swarma-keychain")); len(got) != 0 {
		t.Fatal("neutral negative control was refused")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = root
	files, err := cmd.Output()
	if err != nil {
		t.Fatalf("tracked-tree inventory unavailable: %v", err)
	}
	count := 0
	for _, name := range bytes.Split(files, []byte{0}) {
		if len(name) == 0 {
			continue
		}
		path := string(name)
		full := filepath.Join(root, path)
		info, err := os.Lstat(full)
		if err != nil {
			t.Fatal(err)
		}
		var data []byte
		if info.Mode()&os.ModeSymlink != 0 {
			var target string
			target, err = os.Readlink(full)
			data = []byte(target)
		} else if info.Mode().IsRegular() {
			data, err = os.ReadFile(full)
		} else {
			t.Fatalf("unsupported tracked entry: %s", path)
		}
		if err != nil {
			t.Fatal(err)
		}
		count++
		for _, hit := range personalViolations(path, data) {
			t.Errorf("unqualified personal identifier: %s", hit)
		}
	}
	if count == 0 {
		t.Fatal("empty tracked-tree inventory")
	}
	t.Logf("scanned %d tracked entries; exact provenance/legal exceptions only", count)
}

// Claim: the exceptions fail closed when their bytes change or their text is
// copied to an unapproved path. The exact real records are positive controls;
// changing one byte in either a pinned file or the retained line is refused.
func TestPublicPersonalIdentifierExceptionPins(t *testing.T) {
	for path := range personalFilePins {
		data, err := os.ReadFile(filepath.Join("../..", path))
		if err != nil {
			t.Fatal(err)
		}
		if !personalPattern.Match(data) || len(personalViolations(path, data)) != 0 {
			t.Fatalf("pinned positive control failed: %s", path)
		}
		if len(personalViolations(path, append(bytes.Clone(data), '\n'))) == 0 {
			t.Fatalf("changed pin was exempt: %s", path)
		}
		if len(personalViolations("README.md", data)) == 0 {
			t.Fatalf("path-wide bypass: %s", path)
		}
	}
	for path, pins := range personalLinePins {
		data, err := os.ReadFile(filepath.Join("../..", path))
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, line := range bytes.Split(data, []byte("\n")) {
			for _, pin := range pins {
				if fmt.Sprintf("%x", sha256.Sum256(line)) != pin {
					continue
				}
				found++
				if !personalPattern.Match(line) || len(personalViolations(path, line)) != 0 {
					t.Fatalf("source-line positive control failed: %s", path)
				}
				if len(personalViolations(path, append(bytes.Clone(line), ' '))) != 1 {
					t.Fatalf("modified source line was exempt: %s", path)
				}
				if len(personalViolations("README.md", line)) != 1 {
					t.Fatalf("source-line exception escaped its path: %s", path)
				}
			}
		}
		if found != len(pins) {
			t.Fatalf("pinned source line missing: %s", path)
		}
	}
}
