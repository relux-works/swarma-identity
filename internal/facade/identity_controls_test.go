package facade

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: each key identity-show negative is detected by its named test. Removing
// one product check in an isolated overlay copy makes exactly that test fail
// at its own assertion, while the unmodified build passes the same selection.
// Limit: four single-check removals, not exhaustive mutation testing. Product
// and dependency files on disk are never changed.
func TestIdentityShowPlantedControls(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".temp"), 0700); err != nil {
		t.Fatalf("control scratch root: %v", err)
	}
	scratch, err := os.MkdirTemp(filepath.Join(root, ".temp"), "identity-controls-")
	if err != nil {
		t.Fatalf("control scratch: %v", err)
	}
	o := &nostrObserver{root: root, scratch: scratch}
	cases := []struct {
		name, file, before, after, test, diagnostic string
	}{
		{
			"no-snapshot-check", "identity.go",
			"if f := c.sameTip(ctx, h.BlockHash); f != nil {",
			"if f := c.sameTip(ctx, h.BlockHash); f != nil && false {",
			"^TestIdentityShowSnapshotChanged$", "moved snapshot admitted",
		},
		{
			"no-landlord-role-check", "identity.go",
			`if lv := classifyV3(lb); lv.role == "landlord" {`,
			`if lv := classifyV3(lb); lv.role != "" {`,
			"^TestIdentityShowLandlordNotV3$", "non-landlord pointer admitted",
		},
		{
			"no-v3-parse-check", "identity.go",
			"if b, d, err := rental.ParseLandlordIdentity(string(value)); err == nil {",
			"if b, d, _ := rental.ParseLandlordIdentity(string(value)); true {",
			"^TestIdentityShowValueNotV3$", "non-v3 projection differs",
		},
		{
			"no-value-size-bound", "node.go",
			" || len(n.ValueHex) > 1040 {",
			" {",
			"^TestIdentityShowMalformedValue$", "malformed provider value admitted",
		},
	}
	baseline := filepath.Join(scratch, "baseline.test")
	o.goCommand(t, "identity-baseline-build", "test", "-mod=readonly", "-p", "1", "-c", "-o", baseline, "./internal/facade")
	t.Cleanup(func() { os.Remove(baseline) })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := o.testProcess(t, baseline, tc.name+"-positive", tc.test); code != 0 {
				t.Fatal("unmodified identity control failed")
			}
			path := filepath.Join(root, "internal", "facade", tc.file)
			source, err := os.ReadFile(path)
			if err != nil || bytes.Count(source, []byte(tc.before)) != 1 {
				t.Fatal("identity plant setup: expected exactly one source anchor")
			}
			copyPath := filepath.Join(scratch, tc.name+".go")
			if err := os.WriteFile(copyPath, bytes.Replace(source, []byte(tc.before), []byte(tc.after), 1), 0600); err != nil {
				t.Fatal(err)
			}
			overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{path: copyPath}})
			overlayPath := filepath.Join(scratch, tc.name+".json")
			if err := os.WriteFile(overlayPath, overlay, 0600); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(scratch, tc.name+".test")
			o.goCommand(t, tc.name+"-build", "test", "-mod=readonly", "-p", "1", "-c", "-overlay", overlayPath, "-o", binary, "./internal/facade")
			t.Cleanup(func() { os.Remove(binary) })
			code, log := o.testProcess(t, binary, tc.name+"-negative", tc.test)
			if code != 1 || !strings.Contains(log, tc.diagnostic) || !strings.Contains(log, "--- FAIL: TestIdentityShow") || strings.Contains(log, "panic:") {
				t.Fatalf("identity plant missed its assertion: exit%d; log under %s", code, scratch)
			}
			t.Logf("control %s: unmodified exit0; plant exit1 at %q", tc.name, tc.diagnostic)
		})
	}
}
