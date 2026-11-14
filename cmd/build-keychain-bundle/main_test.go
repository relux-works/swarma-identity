package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Claim: the positional contract accepts a profile and optional output app,
// defaults to .temp/SwarmaKeychain.app, and refuses missing/extra arguments.
func TestArguments(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want options
		bad  bool
	}{
		{[]string{"profile"}, options{"profile", ".temp/SwarmaKeychain.app"}, false},
		{[]string{"profile with spaces", "output with spaces.app"}, options{"profile with spaces", "output with spaces.app"}, false},
		{nil, options{}, true},
		{[]string{"a", "b", "c"}, options{}, true},
	} {
		got, err := arguments(tc.args)
		if (err != nil) != tc.bad || !tc.bad && got != tc.want {
			t.Fatalf("arguments(%q) = %+v, %v", tc.args, got, err)
		}
	}
}

// Claim: unsupported platforms refuse before reading a profile, writing any
// bundle files or running a command; invalid arity retains the usage exit.
func TestNonDarwinRefusal(t *testing.T) {
	for _, platform := range []string{"linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			t.Chdir(t.TempDir())
			var out, diag bytes.Buffer
			never := func(command) error { t.Fatal("non-darwin ran a command"); return nil }
			if code := run([]string{"missing-profile"}, platform, &out, &diag, never); code != 1 || out.Len() != 0 || !strings.Contains(diag.String(), "requires macOS") {
				t.Fatalf("platform refusal: %d %q %q", code, out.String(), diag.String())
			}
			if _, err := os.Lstat(".temp"); !os.IsNotExist(err) {
				t.Fatal("platform refusal created output")
			}
			diag.Reset()
			if code := run(nil, platform, &out, &diag, never); code != 2 || !strings.Contains(diag.String(), "Usage:") {
				t.Fatalf("arity refusal: %d %q", code, diag.String())
			}
		})
	}
}

// Claim: invalid profile/output and existing outputs (including dangling
// symlinks) refuse without executing commands or changing existing files. Early
// input refusals create no app; entitlement collisions leave the same partial
// app as the original recipe. Valid controls proceed in TestBundleContract.
func TestInputRefusals(t *testing.T) {
	for _, variant := range []string{"missing-profile", "profile-directory", "bad-extension", "existing-app", "app-symlink", "existing-entitlements", "entitlements-symlink"} {
		t.Run(variant, func(t *testing.T) {
			dir := t.TempDir()
			profile, bundle := filepath.Join(dir, "profile"), filepath.Join(dir, "Output.app")
			writeFixture(t, profile, "profile bytes")
			entitlements := filepath.Join(dir, "Output.entitlements.plist")
			wantCode, wantMessage := 2, "existing provisioning profile and a new .app"
			sentinel := ""
			switch variant {
			case "missing-profile":
				profile += "-missing"
			case "profile-directory":
				profile = dir
			case "bad-extension":
				bundle += ".zip"
			case "existing-app":
				sentinel = bundle
				writeFixture(t, sentinel, "preserve me")
			case "app-symlink":
				mustSymlink(t, filepath.Join(dir, "missing"), bundle)
			case "existing-entitlements":
				sentinel = entitlements
				writeFixture(t, sentinel, "preserve me")
				wantCode, wantMessage = 1, "Could not create bundle"
			case "entitlements-symlink":
				mustSymlink(t, filepath.Join(dir, "missing"), entitlements)
				wantCode, wantMessage = 1, "Could not create bundle"
			}
			var out, diag bytes.Buffer
			never := func(command) error { t.Fatal("refused input ran a command"); return nil }
			code := run([]string{profile, bundle}, "darwin", &out, &diag, never)
			if code != wantCode || out.Len() != 0 || !strings.Contains(diag.String(), wantMessage) {
				t.Fatalf("refusal: %d %q %q", code, out.String(), diag.String())
			}
			if sentinel != "" && string(readFixture(t, sentinel)) != "preserve me" {
				t.Fatal("refusal overwrote existing output")
			}
			if variant == "app-symlink" || variant == "entitlements-symlink" {
				path := bundle
				if variant == "entitlements-symlink" {
					path = entitlements
				}
				if target, err := os.Readlink(path); err != nil || target != filepath.Join(dir, "missing") {
					t.Fatal("refusal changed a dangling symlink")
				}
			}
			if variant == "existing-entitlements" || variant == "entitlements-symlink" {
				if _, err := os.Stat(filepath.Join(bundle, "Contents/Info.plist")); err != nil {
					t.Fatal("entitlement collision did not preserve partial bundle")
				}
			} else if variant != "existing-app" && variant != "app-symlink" {
				if _, err := os.Lstat(bundle); !os.IsNotExist(err) {
					t.Fatal("preflight refusal created an app")
				}
			}
		})
	}
}

// Claim: default and explicit paths produce the same plist/profile contract
// and ordered go-build/codesign/verify argv as the accepted recipe. Only the
// release build's environment overrides ambient test tags. The executor records
// commands; this proves orchestration and files, not actual Developer ID signing.
func TestBundleContract(t *testing.T) {
	for _, custom := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "custom"}[custom], func(t *testing.T) {
			t.Chdir(t.TempDir())
			t.Setenv("GOFLAGS", "-tags=keychaintest")
			t.Setenv("GOTOOLCHAIN", "auto")
			t.Setenv("CGO_ENABLED", "0")
			t.Setenv("BUNDLE_TEST_CONTROL", "preserved")
			profile, bundle := "profile with spaces", ".temp/SwarmaKeychain.app"
			writeFixture(t, profile, "exact profile bytes")
			args := []string{profile}
			if custom {
				bundle = "custom directory/Custom Bundle.app"
				args = append(args, bundle)
			}
			var calls []command
			var out, diag bytes.Buffer
			execute := func(c command) error {
				calls = append(calls, c)
				if string(readFixture(t, filepath.Join(bundle, "Contents/embedded.provisionprofile"))) != "exact profile bytes" {
					t.Fatal("profile was changed")
				}
				return nil
			}
			if code := run(args, "darwin", &out, &diag, execute); code != 0 || diag.Len() != 0 || out.String() != "Signed bundle: "+bundle+"\n" {
				t.Fatalf("positive control: %d %q %q", code, out.String(), diag.String())
			}
			entitlements := strings.TrimSuffix(bundle, ".app") + ".entitlements.plist"
			want := []command{
				{name: "go", args: []string{"build", "-o", filepath.Join(bundle, "Contents/MacOS/swarma-keychain"), "./cmd/swarma-keychain"}},
				{name: "codesign", args: []string{"--force", "--options", "runtime", "--entitlements", entitlements, "--sign", "Developer ID Application: Relux Works, LLC (262RZ595FP)", bundle}},
				{name: "codesign", args: []string{"--verify", "--strict", bundle}},
			}
			if len(calls) != len(want) {
				t.Fatalf("command count: %d", len(calls))
			}
			for i, c := range calls {
				if c.name != want[i].name || !reflect.DeepEqual(c.args, want[i].args) {
					t.Fatalf("command %d: %s %q", i, c.name, c.args)
				}
				if i != 0 && c.env != nil {
					t.Fatal("codesign changed the environment")
				}
			}
			env := map[string]string{}
			for _, entry := range calls[0].env {
				key, value, _ := strings.Cut(entry, "=")
				if _, duplicate := env[key]; duplicate {
					t.Fatalf("duplicate environment key %s", key)
				}
				env[key] = value
			}
			if env["GOFLAGS"] != "" || env["GOTOOLCHAIN"] != "local" || env["CGO_ENABLED"] != "1" || env["BUNDLE_TEST_CONTROL"] != "preserved" {
				t.Fatal("release build environment overrides or preserved variable differ")
			}
			info := plistValues(t, readFixture(t, filepath.Join(bundle, "Contents/Info.plist")))
			if !reflect.DeepEqual(info, map[string]any{"CFBundleIdentifier": "works.relux.swarma-keychain", "CFBundleExecutable": "swarma-keychain", "CFBundleName": "SwarmaKeychain", "CFBundlePackageType": "APPL", "CFBundleVersion": "1", "LSUIElement": true}) {
				t.Fatalf("Info.plist: %+v", info)
			}
			grants := plistValues(t, readFixture(t, entitlements))
			if !reflect.DeepEqual(grants, map[string]any{"com.apple.application-identifier": "262RZ595FP.works.relux.swarma-keychain", "com.apple.developer.team-identifier": "262RZ595FP", "keychain-access-groups": []string{"262RZ595FP.works.relux.swarma-keychain"}}) {
				t.Fatalf("entitlements: %+v", grants)
			}
		})
	}
}

type commandFailure struct{}

func (commandFailure) Error() string { return "fixture command failed" }
func (commandFailure) ExitCode() int { return 7 }

// Claim: a failure at build, sign or strict verification stops the command
// sequence, preserves its nonzero exit and emits no success message. Files
// already created remain for inspection, as with the original recipe.
func TestCommandFailureStops(t *testing.T) {
	for fail := 0; fail < 3; fail++ {
		t.Run([]string{"build", "sign", "verify"}[fail], func(t *testing.T) {
			dir := t.TempDir()
			profile, bundle := filepath.Join(dir, "profile"), filepath.Join(dir, "Output.app")
			writeFixture(t, profile, "profile bytes")
			calls := 0
			execute := func(command) error {
				calls++
				if calls == fail+1 {
					return commandFailure{}
				}
				return nil
			}
			var out, diag bytes.Buffer
			if code := run([]string{profile, bundle}, "darwin", &out, &diag, execute); code != 7 || calls != fail+1 || out.Len() != 0 || !strings.Contains(diag.String(), "fixture command failed") {
				t.Fatalf("failure did not stop: code=%d calls=%d out=%q diag=%q", code, calls, out.String(), diag.String())
			}
			if _, err := os.Stat(filepath.Join(bundle, "Contents/Info.plist")); err != nil {
				t.Fatal("failure removed diagnostic files")
			}
		})
	}
}

// Claim: an unusable output parent refuses before running an external tool,
// preserves that file, and never reports success. The valid control is above.
func TestUnusableParentRefusal(t *testing.T) {
	dir := t.TempDir()
	profile, parent := filepath.Join(dir, "profile"), filepath.Join(dir, "parent-file")
	writeFixture(t, profile, "profile")
	writeFixture(t, parent, "preserve me")
	var out, diag bytes.Buffer
	code := run([]string{profile, filepath.Join(parent, "Output.app")}, "darwin", &out, &diag, func(command) error { t.Fatal("file failure ran a command"); return nil })
	if code != 2 || out.Len() != 0 || !strings.Contains(diag.String(), "new .app output path") || string(readFixture(t, parent)) != "preserve me" {
		t.Fatalf("file refusal: %d %q %q", code, out.String(), diag.String())
	}
}

func writeFixture(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}
func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func mustSymlink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

type plistNode struct {
	XMLName  xml.Name
	Text     string      `xml:",chardata"`
	Children []plistNode `xml:",any"`
}

func plistValues(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var root plistNode
	if err := xml.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	if root.XMLName.Local != "plist" || len(root.Children) != 1 || root.Children[0].XMLName.Local != "dict" {
		t.Fatal("not a plist dictionary")
	}
	entries := root.Children[0].Children
	if len(entries)%2 != 0 {
		t.Fatal("odd plist dictionary")
	}
	out := map[string]any{}
	for i := 0; i < len(entries); i += 2 {
		if entries[i].XMLName.Local != "key" {
			t.Fatal("missing plist key")
		}
		key, value := entries[i].Text, entries[i+1]
		if _, exists := out[key]; exists {
			t.Fatal("duplicate plist key")
		}
		switch value.XMLName.Local {
		case "string":
			out[key] = value.Text
		case "true":
			out[key] = true
		case "array":
			var values []string
			for _, v := range value.Children {
				if v.XMLName.Local != "string" {
					t.Fatal("non-string grant")
				}
				values = append(values, v.Text)
			}
			out[key] = values
		default:
			t.Fatal("unexpected plist value")
		}
	}
	return out
}

// Claim: command startup failures (including a missing tool) stop before later
// steps, preserve a clear diagnostic, and never print a signing success.
func TestCommandStartRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
		code    int
	}{
		{"start-error", errors.New("fixture start error"), 1},
		{"missing-tool", exec.ErrNotFound, 127},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			profile, bundle := filepath.Join(dir, "profile"), filepath.Join(dir, "Output.app")
			writeFixture(t, profile, "profile")
			var out, diag bytes.Buffer
			calls := 0
			code := run([]string{profile, bundle}, "darwin", &out, &diag, func(command) error { calls++; return tc.failure })
			if code != tc.code || calls != 1 || out.Len() != 0 || !strings.Contains(diag.String(), tc.failure.Error()) {
				t.Fatalf("startup refusal: %d calls=%d %q %q", code, calls, out.String(), diag.String())
			}
		})
	}
}

// Claim: create-only file writes also refuse a collision at the write itself,
// preserving existing bytes and dangling symlinks after a preflight race; a
// new path accepts the same bytes. No external tool is involved in this check.
func TestCreateOnlyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "entitlements.plist")
	if err := writeNew(path, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(path, []byte("second"), 0600); !errors.Is(err, os.ErrExist) || string(readFixture(t, path)) != "first" {
		t.Fatal("create-only write replaced an existing file")
	}
	alias := filepath.Join(dir, "dangling")
	target := filepath.Join(dir, "missing")
	mustSymlink(t, target, alias)
	if err := writeNew(alias, []byte("second"), 0600); !errors.Is(err, os.ErrExist) {
		t.Fatal("create-only write accepted a dangling symlink")
	}
	if got, err := os.Readlink(alias); err != nil || got != target {
		t.Fatal("create-only write changed a dangling symlink")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("create-only write created the symlink target")
	}
}
