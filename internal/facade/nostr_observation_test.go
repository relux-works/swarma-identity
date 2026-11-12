package facade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const nostrObserverPrefix = "nostr-observe:"

// Insert at the exact named function/method entry without replacing its body.
// Ambiguous or missing hooks are setup errors, never passing observations.
func nostrHook(source []byte, name, receiver, prefix string) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "hook.go", source, 0)
	if err != nil {
		return nil, err
	}
	var positions []int
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Body == nil {
			continue
		}
		recv := ""
		if fn.Recv != nil && len(fn.Recv.List) == 1 {
			x := fn.Recv.List[0].Type
			if ptr, ok := x.(*ast.StarExpr); ok {
				x = ptr.X
			}
			if id, ok := x.(*ast.Ident); ok {
				recv = id.Name
			}
		}
		if recv == receiver {
			positions = append(positions, fset.Position(fn.Body.Lbrace).Offset+1)
		}
	}
	if len(positions) != 1 {
		return nil, fmt.Errorf("hook %s.%s matched %d functions, require exactly one", receiver, name, len(positions))
	}
	i := positions[0]
	out := append([]byte{}, source[:i]...)
	out = append(out, []byte("\n"+prefix+"\n")...)
	return append(out, source[i:]...), nil
}

func nostrObserverImport(source []byte, path string) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "plant.go", source, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	for _, spec := range f.Imports {
		if spec.Path.Value == strconv.Quote(path) {
			return source, nil
		}
	}
	f.Decls = append([]ast.Decl{&ast.GenDecl{Tok: token.IMPORT, Specs: []ast.Spec{&ast.ImportSpec{Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(path)}}}}}, f.Decls...)
	var out bytes.Buffer
	err = format.Node(&out, fset, f)
	return out.Bytes(), err
}

// This proves the hook selector distinguishes methods, refuses absent and
// duplicate declarations, and reports malformed source rather than omitting it.
func TestNostrObserverSetup(t *testing.T) {
	for _, tc := range []struct {
		source, receiver string
		valid            bool
	}{
		{"package p; func Hook() {}", "", true},
		{"package p; type T int; func (*T) Hook() {}; func Hook() {}", "T", true},
		{"package p; func Other() {}", "", false},
		{"package p; func Hook() {}; func Hook() {}", "", false},
		{"package p; func Hook(", "", false},
	} {
		out, err := nostrHook([]byte(tc.source), "Hook", tc.receiver, `println("control-marker")`)
		if tc.valid != (err == nil) || (tc.valid && bytes.Count(out, []byte(`println("control-marker")`)) != 1) {
			t.Fatalf("hook selector valid=%t err=%v", tc.valid, err)
		}
	}
	for _, tc := range []struct {
		trace string
		valid bool
	}{
		{"nostr-observe:begin\nnostr-observe:request-open\nnostr-observe:end\n", true},
		{"nostr-observe:begin\nnostr-observe:forbidden-file\nnostr-observe:end\n", true},
		{"nostr-observe:begin\nnostr-observe:request-open\n", false},
		{"nostr-observe:end\n", false},
		{"nostr-observe:begin\nnostr-observe:begin\nnostr-observe:end\n", false},
		{"nostr-observe:begin\nunknown diagnostics\nnostr-observe:end\n", false},
	} {
		if _, err := nostrObservation(tc.trace); tc.valid != (err == nil) {
			t.Fatalf("trace interval valid=%t err=%v", tc.valid, err)
		}
	}
}

type nostrObserver struct {
	root, scratch, signatureSource, modfile string
}

func nostrCopiedModuleFile(name string) bool {
	return (strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")) || name == "go.mod" || name == "go.sum"
}

// Admit exactly the original pinned module's copied production/module files,
// with identical bytes. Additional, missing or modified copies are refused.
func nostrCheckModuleCopy(original, copied string) (map[string]string, error) {
	want := map[string]string{}
	err := filepath.WalkDir(original, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !nostrCopiedModuleFile(entry.Name()) {
			return nil
		}
		rel, err := filepath.Rel(original, path)
		if err != nil {
			return err
		}
		a, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		copyPath := filepath.Join(copied, rel)
		info, err := os.Lstat(copyPath)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("module copy missing/nonregular: %s", rel)
		}
		b, err := os.ReadFile(copyPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(a, b) {
			return fmt.Errorf("module copy byte mismatch: %s", rel)
		}
		h := sha256.Sum256(a)
		want[rel] = hex.EncodeToString(h[:])
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = filepath.WalkDir(copied, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, err := filepath.Rel(copied, path)
		if err != nil {
			return err
		}
		if _, ok := want[rel]; !ok {
			return fmt.Errorf("module copy extra file: %s", rel)
		}
		return nil
	})
	return want, err
}

func newNostrObserver(t *testing.T) *nostrObserver {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".temp"), 0700); err != nil {
		t.Fatalf("observer UNAVAILABLE: scratch root: %v", err)
	}
	scratch, err := os.MkdirTemp(filepath.Join(root, ".temp"), "nostr-observer-")
	if err != nil {
		t.Fatalf("observer UNAVAILABLE: scratch: %v", err)
	}
	o := &nostrObserver{root: root, scratch: scratch}
	var module struct{ Dir string }
	b := o.goCommand(t, "module", "list", "-mod=readonly", "-m", "-json", "github.com/btcsuite/btcd/btcec/v2")
	if json.Unmarshal(b, &module) != nil || module.Dir == "" {
		t.Fatal("observer UNAVAILABLE: verifier source lookup")
	}
	// Go rejects overlays below GOMODCACHE. Copy only the pinned module's
	// production source and use a scratch modfile replacement, then overlay that
	// copy. The real cache and repository dependency files remain untouched.
	copyRoot := filepath.Join(scratch, "verifier")
	err = filepath.WalkDir(module.Dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(module.Dir, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(copyRoot, rel), 0700)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected verifier source link")
		}
		if nostrCopiedModuleFile(entry.Name()) {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(copyRoot, rel), b, 0600)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("observer UNAVAILABLE: isolated verifier copy: %v", err)
	}
	copyHashes, err := nostrCheckModuleCopy(module.Dir, copyRoot)
	if err != nil || len(copyHashes) == 0 {
		t.Fatalf("observer UNAVAILABLE: pinned module copy admission: %v", err)
	}
	// Control the very same checker against a one-byte mutation of the actual
	// isolated pinned module. Restore and re-admit before any child build.
	controlPath := filepath.Join(copyRoot, "schnorr", "signature.go")
	before, err := os.ReadFile(controlPath)
	if err != nil || len(before) == 0 {
		t.Fatal("module copy control setup")
	}
	mutated := append([]byte{}, before...)
	mutated[0] ^= 1
	if err := os.WriteFile(controlPath, mutated, 0600); err != nil {
		t.Fatal(err)
	}
	_, controlErr := nostrCheckModuleCopy(module.Dir, copyRoot)
	if err := os.WriteFile(controlPath, before, 0600); err != nil {
		t.Fatal(err)
	}
	if controlErr == nil || controlErr.Error() != "module copy byte mismatch: "+filepath.Join("schnorr", "signature.go") {
		t.Fatal("one-byte module copy plant missed intended admission refusal")
	}
	if _, err := nostrCheckModuleCopy(module.Dir, copyRoot); err != nil {
		t.Fatalf("restored module copy did not pass admission: %v", err)
	}
	copyReceipt, _ := json.MarshalIndent(map[string]any{"original": module.Dir, "copy": copyRoot, "equal_before_hooks": copyHashes, "negative_control": controlErr.Error(), "mutated_bytes": 1, "restored_admission": "PASS", "modfile_delta": "one appended replace github.com/btcsuite/btcd/btcec/v2 => quoted scratch verifier path; no other changes"}, "", "  ")
	if err := os.WriteFile(filepath.Join(scratch, "module-copy-admission.json"), copyReceipt, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "go.mod" {
			b = append(b, []byte("\nreplace github.com/btcsuite/btcd/btcec/v2 => "+strconv.Quote(copyRoot)+"\n")...)
		}
		if err := os.WriteFile(filepath.Join(scratch, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	o.modfile = filepath.Join(scratch, "go.mod")
	o.signatureSource = filepath.Join(copyRoot, "schnorr", "signature.go")
	t.Logf("observer artifacts: %s; named Go entry points only, no raw-syscall/cgo claim", scratch)
	return o
}

func (o *nostrObserver) goCommand(t *testing.T, label string, args ...string) []byte {
	t.Helper()
	// Both existing-file and dangling-symlink host holds prohibit execution.
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal("observer UNAVAILABLE: execution hold location")
	}
	hold := filepath.Join(userHome, "Library", "Application Support", "host-health", "exec-degraded")
	for _, stat := range []func(string) (os.FileInfo, error){os.Stat, os.Lstat} {
		if _, err := stat(hold); !os.IsNotExist(err) {
			t.Fatal("observer UNAVAILABLE: host execution hold or indeterminate guard")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), args...)
	cmd.Dir = o.root
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOMAXPROCS=2")
	var out, diagnostics bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &diagnostics
	started := time.Now().UTC()
	err = cmd.Start()
	if err != nil {
		t.Fatalf("observer UNAVAILABLE: start Go: %v", err)
	}
	pid := cmd.Process.Pid
	err = cmd.Wait()
	finished := time.Now().UTC()
	for suffix, payload := range map[string][]byte{"stdout": out.Bytes(), "stderr": diagnostics.Bytes()} {
		if e := os.WriteFile(filepath.Join(o.scratch, label+"."+suffix), payload, 0600); e != nil {
			t.Fatal(e)
		}
	}
	receipt, _ := json.MarshalIndent(map[string]any{"argv": cmd.Args, "pid": pid, "started": started, "finished": finished, "exit": cmd.ProcessState.ExitCode(), "toolchain": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH, "explicit_env": map[string]string{"GOTOOLCHAIN": "local", "GOWORK": "off", "GOPROXY": "off", "GOMAXPROCS": "2"}, "inherited_env": "not captured"}, "", "  ")
	if e := os.WriteFile(filepath.Join(o.scratch, label+".json"), receipt, 0600); e != nil {
		t.Fatal(e)
	}
	if err != nil {
		t.Fatalf("observer UNAVAILABLE: Go setup/build exit%d; diagnostics at %s", cmd.ProcessState.ExitCode(), filepath.Join(o.scratch, label+".stderr"))
	}
	return out.Bytes()
}

func (o *nostrObserver) binary(t *testing.T, plant string) string {
	t.Helper()
	dir := filepath.Join(o.scratch, plant)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	sources := map[string][]byte{}
	witnesses := map[string]string{}
	read := func(path string) []byte {
		if b, ok := sources[path]; ok {
			return b
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("observer UNAVAILABLE: hook source: %v", err)
		}
		h := sha256.Sum256(b)
		witnesses[path] = hex.EncodeToString(h[:])
		return b
	}
	hook := func(path, name, receiver, prefix string) {
		b, err := nostrHook(read(path), name, receiver, prefix)
		if err != nil {
			t.Fatalf("observer UNAVAILABLE: %v", err)
		}
		sources[path] = b
	}
	stdlib := func(path string) string { return filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(path)) }
	hook(stdlib("os/file.go"), "OpenFile", "", `
	if name != Getenv("SWARMA_NOSTR_OBSERVER_REQUEST") || (flag != O_RDONLY && flag != O_RDONLY|syscall.O_NONBLOCK) {
		println("nostr-observe:forbidden-file")
		return nil, ErrPermission
	}
	println("nostr-observe:request-open")`)
	hook(stdlib("os/exec.go"), "StartProcess", "", `println("nostr-observe:forbidden-process"); return nil, ErrPermission`)
	hook(stdlib("net/dial.go"), "DialContext", "Dialer", `println("nostr-observe:forbidden-dial"); return nil, &DNSError{Err:"observer denied"}`)
	for _, name := range []string{"LookupHost", "LookupIPAddr", "LookupIP"} {
		hook(stdlib("net/lookup.go"), name, "Resolver", `println("nostr-observe:forbidden-dns"); return nil, &DNSError{Err:"observer denied"}`)
	}
	hook(stdlib("time/time.go"), "Now", "", `println("nostr-observe:forbidden-clock"); return Time{}`)
	hook(o.signatureSource, "ParseSignature", "", `println("nostr-observe:signature-parse")`)
	hook(o.signatureSource, "Verify", "Signature", `println("nostr-observe:signature-verify")`)
	cli := filepath.Join(o.root, "internal", "facade", "cli.go")
	prefix := `println("nostr-observe:begin"); defer println("nostr-observe:end")`
	plants := map[string]struct{ dependency, statement string }{
		"file":       {"", `_, _ = os.ReadFile("observer-forbidden-config")`},
		"file-write": {"", `_, _ = os.OpenFile(os.Getenv("SWARMA_NOSTR_OBSERVER_REQUEST"), os.O_WRONLY, 0)`},
		"dial":       {"net", `_, _ = net.Dial("tcp", "127.0.0.1:1")`},
		"dns":        {"net", `_, _ = net.DefaultResolver.LookupHost(ctx, "observer.invalid")`},
		"process":    {"", `_, _ = os.StartProcess("observer-forbidden-executable", nil, nil)`},
		"clock":      {"time", `_ = time.Now()`},
	}
	if p, ok := plants[plant]; ok {
		if p.dependency != "" {
			b, err := nostrObserverImport(read(cli), p.dependency)
			if err != nil {
				t.Fatal(err)
			}
			sources[cli] = b
		}
		prefix += "\n" + p.statement
	}
	hook(cli, "Run", "", prefix)
	if plant == "eager-signature" {
		hook(filepath.Join(o.root, "internal", "facade", "nostr.go"), "VerifyNostrProfile", "", `
	k, _ := hex.DecodeString(r.Event.Pubkey)
	d, _ := hex.DecodeString(r.Event.ID)
	s, _ := hex.DecodeString(r.Event.Sig)
	_ = verifyNostrSignature(k, d, s)`)
	}
	replacements := map[string]string{}
	for path, b := range sources {
		h := sha256.Sum256([]byte(path))
		copyPath := filepath.Join(dir, hex.EncodeToString(h[:8])+".go")
		if err := os.WriteFile(copyPath, b, 0600); err != nil {
			t.Fatal(err)
		}
		replacements[path] = copyPath
	}
	overlay, _ := json.MarshalIndent(map[string]any{"Replace": replacements}, "", "  ")
	manifest, _ := json.MarshalIndent(witnesses, "", "  ")
	for name, b := range map[string][]byte{"overlay.json": overlay, "sources.json": manifest} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, "swarma-identity")
	o.goCommand(t, plant+"-build", "build", "-mod=readonly", "-modfile", o.modfile, "-p", "1", "-overlay", filepath.Join(dir, "overlay.json"), "-o", binary, "./cmd/swarma-identity")
	t.Cleanup(func() { os.Remove(binary) })
	return binary
}

// Markers outside Run are startup/runtime evidence, not command observations.
// Unknown command stderr, missing delimiters and duplicate markers are errors.
func nostrObservation(stderr string) (map[string]int, error) {
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	counts := map[string]int{}
	active, ended := false, false
	for _, line := range lines {
		if line == nostrObserverPrefix+"begin" {
			if active || ended {
				return nil, fmt.Errorf("duplicate observer interval")
			}
			active = true
			continue
		}
		if line == nostrObserverPrefix+"end" {
			if !active {
				return nil, fmt.Errorf("missing observer begin")
			}
			active, ended = false, true
			continue
		}
		if !strings.HasPrefix(line, nostrObserverPrefix) {
			return nil, fmt.Errorf("unexpected observer diagnostics")
		}
		if active {
			counts[strings.TrimPrefix(line, nostrObserverPrefix)]++
		}
	}
	if active || !ended {
		return nil, fmt.Errorf("incomplete observer interval")
	}
	return counts, nil
}

func (o *nostrObserver) run(t *testing.T, binary, command string, request any) (Envelope, int, []byte, map[string]int) {
	t.Helper()
	path := writeInput(t, request)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "nostr", command, "--request", path, "--json")
	cmd.Env = []string{"SWARMA_NOSTR_OBSERVER_REQUEST=" + path, "GOMAXPROCS=2"}
	var out, diagnostics bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &diagnostics
	started := time.Now().UTC()
	err := cmd.Start()
	if err != nil {
		t.Fatalf("observer execution/setup failure: %v", err)
	}
	pid := cmd.Process.Pid
	err = cmd.Wait()
	code := 0
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok || ctx.Err() != nil {
			t.Fatalf("observer execution/setup failure: %v", err)
		}
		code = exit.ExitCode()
	}
	var e Envelope
	if problem := nostrWireProblem(out.Bytes(), "nostr "+command); problem != "" {
		t.Fatalf("invalid Nostr wire envelope: %s", problem)
	}
	if !outputSafe(out.Bytes()) || json.Unmarshal(out.Bytes(), &e) != nil {
		t.Fatal("observer command did not return a valid closed envelope")
	}
	counts, err := nostrObservation(diagnostics.String())
	if err != nil {
		t.Fatalf("observer trace setup error: %v", err)
	}
	label := filepath.Base(filepath.Dir(binary)) + "-" + command + "-" + strconv.Itoa(pid)
	receipt, _ := json.MarshalIndent(map[string]any{"argv": cmd.Args, "pid": pid, "started": started, "finished": time.Now().UTC(), "exit": code, "counts": counts, "env": map[string]string{"GOMAXPROCS": "2", "SWARMA_NOSTR_OBSERVER_REQUEST": "explicit public request path"}}, "", "  ")
	for suffix, payload := range map[string][]byte{"stdout": out.Bytes(), "stderr": diagnostics.Bytes(), "json": receipt} {
		if err := os.WriteFile(filepath.Join(o.scratch, label+"."+suffix), payload, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("observation %s/%s exit%d counts%v", filepath.Base(filepath.Dir(binary)), command, code, counts)
	return e, code, out.Bytes(), counts
}

func requireNostrObservation(t *testing.T, counts map[string]int, parse, verify int, forbidden string) {
	t.Helper()
	want := map[string]int{"request-open": 1}
	if parse != 0 {
		want["signature-parse"] = parse
	}
	if verify != 0 {
		want["signature-verify"] = verify
	}
	if forbidden != "" {
		want["forbidden-"+forbidden] = 1
	}
	a, _ := json.Marshal(counts)
	b, _ := json.Marshal(want)
	if !bytes.Equal(a, b) {
		t.Fatalf("dependency observation = %s, want %s", a, b)
	}
}

// This same admission predicate is applied to normal traces and instrument
// controls; a discarded error never excuses the recorded forbidden attempt.
func nostrObservationProblem(counts map[string]int, parse, verify int) string {
	for name, count := range counts {
		if count > 0 && strings.HasPrefix(name, "forbidden-") {
			return "forbidden dependency entry: " + name
		}
	}
	if counts["signature-parse"] != parse || counts["signature-verify"] != verify {
		return "unexpected signature parse/verify entry"
	}
	return ""
}

// Named Go dependency entries are observed on complete CLI paths. Every
// ignored-attempt plant preserves a successful envelope yet adds its forbidden
// marker; refusing before the underlying effect keeps these controls offline.
// This is not kernel tracing, raw-syscall/cgo coverage or startup observation.
func TestNostrDependencyObservation(t *testing.T) {
	o := newNostrObserver(t)
	for _, plant := range []string{"normal", "file", "file-write", "dial", "dns", "process", "clock"} {
		t.Run(plant, func(t *testing.T) {
			binary := o.binary(t, plant)
			for _, command := range []string{"profile-prepare", "profile-verify"} {
				t.Run(command, func(t *testing.T) {
					event := publicNostrFixture(t)
					var request any = nostrPrepareInput(event)
					if command == "profile-verify" {
						request = map[string]any{"schema": "swarma-identity/nostr-profile-verify/1", "event": event}
					}
					e, code, _, counts := o.run(t, binary, command, request)
					if code != 0 {
						t.Fatal("ignored-attempt plant changed command success")
					}
					parse, verify := 0, 0
					if command == "profile-prepare" {
						assertNostrPrepared(t, e, event)
					} else {
						assertNostrVerified(t, e, event)
						parse, verify = 1, 1
					}
					forbidden := plant
					if plant == "file-write" {
						forbidden = "file"
					}
					if plant == "normal" {
						forbidden = ""
					}
					problem := nostrObservationProblem(counts, parse, verify)
					if (plant == "normal" && problem != "") || (plant != "normal" && problem != "forbidden dependency entry: forbidden-"+forbidden) {
						t.Fatalf("offline observer missed intended verdict: %q", problem)
					}
					t.Logf("offline observer verdict: %q", problem)
					requireNostrObservation(t, counts, parse, verify, forbidden)
				})
			}
		})
	}
}

// The stale-id refusal precedes signature parsing, even with an overflowing
// encoded signature. A recomputed-id control enters parsing; the original
// signed control enters both parse and verification. An eager masked plant
// retains EVENT_ID_MISMATCH while its extra signature entry is observed.
func TestNostrSignatureOrderObservation(t *testing.T) {
	o := newNostrObserver(t)
	for _, plant := range []string{"normal", "eager-signature"} {
		t.Run(plant, func(t *testing.T) {
			binary := o.binary(t, plant)
			for _, mode := range []string{"valid", "stale-id", "recomputed-id"} {
				if plant != "normal" && mode != "stale-id" {
					continue
				}
				t.Run(mode, func(t *testing.T) {
					event := publicNostrFixture(t)
					if mode != "valid" {
						event["content"] = `{"name":"ordering-control"}`
						event["sig"] = strings.Repeat("f", 128)
						if mode == "recomputed-id" {
							event["id"] = simpleNostrReference(t, event)
						}
					}
					e, code, raw, counts := o.run(t, binary, "profile-verify", map[string]any{"schema": "swarma-identity/nostr-profile-verify/1", "event": event})
					parse, verify := 0, 0
					switch mode {
					case "valid":
						if code != 0 {
							t.Fatal("signed order positive refused")
						}
						assertNostrVerified(t, e, event)
						parse, verify = 1, 1
					case "stale-id":
						assertNostrRefusal(t, e, code, "EVENT_ID_MISMATCH", 3, raw)
						if plant == "eager-signature" {
							parse = 1
							if counts["signature-parse"] == 0 {
								t.Fatal("eager-signature plant was not observed")
							}
							if nostrObservationProblem(counts, 0, 0) != "unexpected signature parse/verify entry" {
								t.Fatal("order observer did not reject eager-signature plant")
							}
							t.Log("order observer rejected eager-signature entry behind unchanged id refusal")
						}
					case "recomputed-id":
						assertNostrRefusal(t, e, code, "INVALID_SIGNATURE", 3, raw)
						parse = 1
					}
					requireNostrObservation(t, counts, parse, verify, "")
				})
			}
		})
	}
}
