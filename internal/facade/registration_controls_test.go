package facade

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseline := filepath.Join(o.scratch, tc.name+"-baseline.test")
			o.goCommand(t, tc.name+"-baseline-build", "test", "-mod=readonly", "-p", "1", "-c", "-o", baseline, tc.pkg)
			t.Cleanup(func() { os.Remove(baseline) })
			if code, _ := o.testProcess(t, baseline, tc.name+"-positive", tc.test); code != 0 {
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
			code, log := o.testProcess(t, binary, tc.name+"-negative", tc.test)
			if code != 1 || !strings.Contains(log, tc.diagnostic) || !strings.Contains(log, "--- FAIL: Test") || strings.Contains(log, "panic:") {
				t.Fatalf("registration plant missed intended assertion: exit%d (private capture)", code)
			}
			t.Logf("%s: baseline exit0; isolated violation exit1 at %q", tc.name, tc.diagnostic)
		})
	}
}
