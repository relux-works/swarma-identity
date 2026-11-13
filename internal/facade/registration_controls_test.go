package facade

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Each isolated plant removes a required guard and must reach the named real
// test assertion after an unmodified passing control. Setup/build/crash failures
// cannot masquerade as detection. Production source stays unchanged.
func TestRegistrationControls(t *testing.T) {
	o, _ := controlScratch(t, "registration-controls-")
	cases := []struct{ name, file, before, after, pkg, test, diagnostic string }{
		{"frame", "internal/registration/restore.go", "|| !bytes.Equal(expected.frame, retained.ReviewFrame)", "|| false", "./internal/facade", "^TestRegistrationRetainedSubstitution$/^frame$", "restored frame mismatch admitted"},
		{"owner", "internal/facade/registration_files_unix.go", "st.Uid == uint32(os.Geteuid()) && st.Nlink == 1", "st.Nlink == 1", "./internal/facade", "^TestRegistrationOwnerPredicate$", "foreign uid admitted"},
		{"interruption", "internal/facade/registration_files_unix.go", "if ctx.Err() != nil || !validDir() {", "if !validDir() {", "./internal/facade", "^TestRegistrationInterruptedCommit$/^3$", "interruption reported success"},
		{"fixture-temp-root", "internal/facade/registration_test.go", "dir, err := filepath.EvalSymlinks(t.TempDir())", "dir, err := func() (string, error) { return t.TempDir(), nil }()", "./internal/facade", "^TestRegistrationResolvedTempFixture$", "fixture retained symlinked temp root"},
		{"request-network", "internal/registration/restore.go", "!reflect.DeepEqual(expected.data, d)", "!reflect.DeepEqual(expected.data.PSBT, d.PSBT)", "./internal/registration", "^TestRestoreRequestBindings$/^network$", "substituted request binding admitted"},
		{"request-schema", "internal/registration/restore.go", "!reflect.DeepEqual(expected.data, d)", "!reflect.DeepEqual(expected.data.PSBT, d.PSBT)", "./internal/registration", "^TestRestoreRequestBindings$/^schema$", "substituted request binding admitted"},
		{"request-plan_manifest_utf8", "internal/registration/restore.go", "!reflect.DeepEqual(expected.data, d)", "!reflect.DeepEqual(expected.data.PSBT, d.PSBT)", "./internal/registration", "^TestRestoreRequestBindings$/^plan_manifest_utf8$", "substituted request binding admitted"},
		{"original-window-reservation", "internal/registration/restore.go", "func (p *Planner) RestoreReservation(in ReservationInput, preparedAt uint64, manifest []byte, transactions [2]PreparedTransaction) (*Plan, error) {\n\tif !p.timeOK(preparedAt)", "func (p *Planner) RestoreReservation(in ReservationInput, preparedAt uint64, manifest []byte, transactions [2]PreparedTransaction) (*Plan, error) {\n\tif false", "./internal/registration", "^TestRestoreOriginalWindows$/^reservation$", "original window violation admitted"},
		{"original-window-reveal", "internal/registration/restore.go", "func (p *Planner) RestoreReveal(reservation *Plan, in RevealInput, preparedAt uint64, manifest []byte, transactions [2]PreparedTransaction) (*Plan, error) {\n\tif !p.timeOK(preparedAt)", "func (p *Planner) RestoreReveal(reservation *Plan, in RevealInput, preparedAt uint64, manifest []byte, transactions [2]PreparedTransaction) (*Plan, error) {\n\tif false", "./internal/registration", "^TestRestoreOriginalWindows$/^reveal$", "original window violation admitted"},
		{"original-window-request", "internal/registration/restore.go", "if !p.timeOK(retained.PreparedAt)", "if false", "./internal/registration", "^TestRestoreOriginalWindows$/^request$", "original window violation admitted"},
		{"stored-request-hash", "internal/facade/registration_restore.go", "regDigest(bundle.files[\"request.json\"]) != state.RequestHash", "false", "./internal/facade", "^TestRegistrationStaleRequestHash$", "wrong refusal exit=0"},
		{"source-directory", "internal/facade/registration_files_unix.go", "st.Mode&07777 == 0700", "st.Mode&07022 == 0", "./internal/facade", "^TestRegistrationSourceDirMode$", "wrong refusal exit=0"},
		{"bundle-kind", "internal/facade/registration_restore.go", "if !goodKind ||", "if (false && !goodKind) ||", "./internal/facade", "^TestRegistrationRequestKind$", "wrong refusal exit=2"},
		{"retained-pin", "internal/facade/registration_restore.go", "!bytes.Equal(files[\"account-pin.json\"], s.pinRaw)", "false", "./internal/facade", "^TestRegistrationRetainedSubstitution$/^account-pin$", "wrong refusal exit=0"},
		{"dispatch-lifetime", "internal/facade/registration.go", "validFor >= 30", "true", "./internal/facade", "^TestRegistrationFreshDispatchWindow$/^lifetime29$", "wrong refusal exit=0"},
		{"dispatch-release", "internal/facade/registration.go", "releaseRemaining >= 30", "true", "./internal/facade", "^TestRegistrationFreshDispatchWindow$/^release29$", "wrong refusal exit=0"},
		{"parent-result", "internal/registration/result.go", "receipt.RequestID != d.RequestID ||", "false ||", "./internal/facade", "^TestRegistrationRetainedParentResults$/^A-id$/^C$", "wrong refusal exit=0"},
		{"files-before-context", "internal/facade/registration_restore.go", "\t// Freeze transport before reconstruction/result checks, preserving file errors.\n\tresult, f := s.freezer.read(parent.Result, 6<<20, parent.ResultHash, \"result\")\n\tif f != nil {\n\t\treturn nil, nil, f\n\t}\n\tstdout, f := s.freezer.read(parent.Stdout, 256, parent.StdoutHash, \"stdout\")\n\tif f != nil {\n\t\treturn nil, nil, f\n\t}\n\toriginal, f := s.originalRequest(parent.Bundle, parent.BundleHash, depth)\n\tif f != nil {\n\t\treturn nil, nil, f\n\t}\n", "\toriginal, f := s.originalRequest(parent.Bundle, parent.BundleHash, depth)\n\tif f != nil {\n\t\treturn nil, nil, f\n\t}\n\t// Freeze transport before reconstruction/result checks, preserving file errors.\n\tresult, f := s.freezer.read(parent.Result, 6<<20, parent.ResultHash, \"result\")\n\tif f != nil {\n\t\treturn nil, nil, f\n\t}\n\tstdout, f := s.freezer.read(parent.Stdout, 256, parent.StdoutHash, \"stdout\")\n\tif f != nil {\n\t\treturn nil, nil, f\n\t}\n", "./internal/facade", "^TestRegistrationPrecedenceFilesFirst$", "wrong refusal exit=3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseline := filepath.Join(o.scratch, tc.name+"-baseline.test")
			o.goCommand(t, tc.name+"-baseline-build", "test", "-mod=readonly", "-p", "1", "-c", "-o", baseline, tc.pkg)
			t.Cleanup(func() { os.Remove(baseline) })
			if code, _ := regControlProcess(t, o, baseline, tc.name+"-positive", tc.test, tc.pkg); code != 0 {
				t.Fatal("unmodified registration control failed")
			}
			path := filepath.Join(o.root, tc.file)
			source, err := os.ReadFile(path)
			if err != nil || bytes.Count(source, []byte(tc.before)) != 1 {
				t.Fatal("registration plant anchor not unique")
			}
			copyPath := filepath.Join(o.scratch, tc.name+".go")
			regTestWrite(t, copyPath, bytes.Replace(source, []byte(tc.before), []byte(tc.after), 1))
			overlayPath := filepath.Join(o.scratch, tc.name+".json")
			overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{path: copyPath}})
			regTestWrite(t, overlayPath, overlay)
			binary := filepath.Join(o.scratch, tc.name+"-negative.test")
			o.goCommand(t, tc.name+"-negative-build", "test", "-mod=readonly", "-p", "1", "-c", "-overlay", overlayPath, "-o", binary, tc.pkg)
			t.Cleanup(func() { os.Remove(binary) })
			code, log := regControlProcess(t, o, binary, tc.name+"-negative", tc.test, tc.pkg)
			if code != 1 || !strings.Contains(log, tc.diagnostic) || !strings.Contains(log, "--- FAIL: Test") || strings.Contains(log, "panic:") {
				t.Fatalf("registration plant missed intended assertion: exit%d (private capture)", code)
			}
			t.Logf("%s: baseline exit0; isolated violation exit1 at %q", tc.name, tc.diagnostic)
		})
	}
}

// A compiled Go test must start in its own package directory for fixture paths.
// Keep the existing facade runner and use the same bounded execution contract
// for registration-library controls, without changing the shared observer.
func regControlProcess(t *testing.T, o *nostrObserver, binary, label, selection, pkg string) (int, string) {
	t.Helper()
	if pkg == "./internal/facade" {
		return o.testProcess(t, binary, label, selection)
	}
	if pkg != "./internal/registration" {
		t.Fatal("unknown registration control package")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run", selection, "-test.v", "-test.parallel", "1")
	cmd.Dir = filepath.Join(o.root, "internal", "registration")
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	started := time.Now().UTC()
	if err := cmd.Start(); err != nil {
		t.Fatalf("registration control setup failed: %v", err)
	}
	err := cmd.Wait()
	code := cmd.ProcessState.ExitCode()
	if ctx.Err() != nil || (err != nil && code != 1) {
		t.Fatalf("registration control execution failed: %v", err)
	}
	regTestWrite(t, filepath.Join(o.scratch, label+".log"), log.Bytes())
	receipt, _ := json.MarshalIndent(map[string]any{"argv": cmd.Args, "cwd": cmd.Dir, "pid": cmd.Process.Pid, "started": started, "finished": time.Now().UTC(), "exit": code, "selected_test": selection}, "", "  ")
	regTestWrite(t, filepath.Join(o.scratch, label+".json"), receipt)
	return code, log.String()
}
