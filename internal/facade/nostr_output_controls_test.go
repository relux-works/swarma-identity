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

// Mutate only the JSON transport in an isolated product-source copy. The real
// envelope, results and exit code are preserved behind the wire-only fault.
func nostrWirePlant(statement string) string {
	return `
	var payload any = e
	if e.OK && strings.HasPrefix(e.Command, "nostr ") {
		b, _ := json.Marshal(e)
		var transport map[string]any
		_ = json.Unmarshal(b, &transport)
		` + statement + `
		payload = transport
	}
	if json.NewEncoder(stdout).Encode(payload) != nil {`
}

// Each isolated output fault must fail its own real assertion. The corresponding
// unmodified test passes first; a build, setup, crash or unrelated failure cannot
// count as detection. These copies never change production/dependency files.
func TestNostrOutputCorruptionControls(t *testing.T) {
	o := newNostrObserver(t)
	cases := []struct {
		name, file, before, after, test, diagnostic string
	}{
		{
			"prepare-field", "nostr.go",
			`return &NostrPreparedProfile{"swarma-identity/nostr-profile-prepared/1", canonical, e}, nil`,
			`e.Pubkey = strings.Repeat("0", 64); return &NostrPreparedProfile{"swarma-identity/nostr-profile-prepared/1", canonical, e}, nil`,
			"^TestNostrProfileSignedPublicFixture$", "Nostr returned fields differ from independent expected values",
		},
		{
			"verify-summary", "nostr.go",
			`true, e.ID, e.Pubkey, e.CreatedAt, e.Kind}, nil`,
			`true, e.ID, e.Pubkey, e.CreatedAt + 1, e.Kind}, nil`,
			"^TestNostrProfileSignedPublicFixture$", "Nostr returned fields differ from independent expected values",
		},
		{
			"failure-extra-key", "types.go", "type Failure struct {", "type Failure struct {\n Extra bool `json:\"extra\"`",
			"^TestNostrProfileTampering$/^content$/^stale-id$", "invalid Nostr wire envelope: failure keys/type",
		},
		{
			"boundary-prepare-field", "nostr.go",
			`return &NostrPreparedProfile{"swarma-identity/nostr-profile-prepared/1", canonical, e}, nil`,
			`if len(r.Content) == 16384 { e.Pubkey = strings.Repeat("0", 64) }; return &NostrPreparedProfile{"swarma-identity/nostr-profile-prepared/1", canonical, e}, nil`,
			"^TestNostrLimits$/^content-bytes$/^over=false$/^prepare$", "Nostr returned fields differ from independent expected values",
		},
		{
			"null-network-success", "cli.go", "if json.NewEncoder(stdout).Encode(e) != nil {",
			nostrWirePlant(`transport["network"] = nil`),
			"^TestNostrNullNetworkSuccess$", "invalid Nostr wire envelope: envelope string type/value",
		},
		{
			"boundary-null-network", "cli.go", "if json.NewEncoder(stdout).Encode(e) != nil {",
			nostrWirePlant(`if e.Command == "nostr profile-prepare" && len(transport["result"].(map[string]any)["event"].(map[string]any)["content"].(string)) == 16384 { transport["network"] = nil }`),
			"^TestNostrLimits$/^content-bytes$/^over=false$/^prepare$", "invalid Nostr wire envelope: envelope string type/value",
		},
		{
			"missing-network", "cli.go", "if json.NewEncoder(stdout).Encode(e) != nil {",
			nostrWirePlant(`delete(transport, "network")`),
			"^TestNostrNullNetworkSuccess$", "invalid Nostr wire envelope: envelope keys/type",
		},
		{
			"number-for-string", "cli.go", "if json.NewEncoder(stdout).Encode(e) != nil {",
			nostrWirePlant(`transport["network"] = 0`),
			"^TestNostrNullNetworkSuccess$", "invalid Nostr wire envelope: envelope string type/value",
		},
		{
			"string-for-bool", "cli.go", "if json.NewEncoder(stdout).Encode(e) != nil {",
			nostrWirePlant(`transport["ok"] = "true"`),
			"^TestNostrNullNetworkSuccess$", "invalid Nostr wire envelope: envelope bool type",
		},
		{
			"null-result-number", "cli.go", "if json.NewEncoder(stdout).Encode(e) != nil {",
			nostrWirePlant(`if e.Command == "nostr profile-verify" { transport["result"].(map[string]any)["created_at"] = nil }`),
			"^TestNostrProfileSignedPublicFixture$", "invalid Nostr wire envelope: event integer type",
		},
		{
			"missing-result-member", "cli.go", "if json.NewEncoder(stdout).Encode(e) != nil {",
			nostrWirePlant(`delete(transport["result"].(map[string]any), "schema")`),
			"^TestNostrNullNetworkSuccess$", "invalid Nostr wire envelope:",
		},
		{
			"string-for-result-bool", "cli.go", "if json.NewEncoder(stdout).Encode(e) != nil {",
			nostrWirePlant(`if e.Command == "nostr profile-verify" { transport["result"].(map[string]any)["valid"] = "true" }`),
			"^TestNostrProfileSignedPublicFixture$", "invalid Nostr wire envelope: verified bool type/value",
		},
	}
	baseline := filepath.Join(o.scratch, "baseline.test")
	o.goCommand(t, "baseline-test-build", "test", "-mod=readonly", "-p", "1", "-c", "-o", baseline, "./internal/facade")
	t.Cleanup(func() { os.Remove(baseline) })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := o.testProcess(t, baseline, tc.name+"-positive", tc.test); code != 0 {
				t.Fatal("unmodified output control failed")
			}
			path := filepath.Join(o.root, "internal", "facade", tc.file)
			source, err := os.ReadFile(path)
			if err != nil || bytes.Count(source, []byte(tc.before)) != 1 {
				t.Fatal("output plant setup: expected exactly one source anchor")
			}
			copyPath := filepath.Join(o.scratch, tc.name+".go")
			if err := os.WriteFile(copyPath, bytes.Replace(source, []byte(tc.before), []byte(tc.after), 1), 0600); err != nil {
				t.Fatal(err)
			}
			overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{path: copyPath}})
			overlayPath := filepath.Join(o.scratch, tc.name+".json")
			if err := os.WriteFile(overlayPath, overlay, 0600); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(o.scratch, tc.name+".test")
			o.goCommand(t, tc.name+"-test-build", "test", "-mod=readonly", "-p", "1", "-c", "-overlay", overlayPath, "-o", binary, "./internal/facade")
			t.Cleanup(func() { os.Remove(binary) })
			code, log := o.testProcess(t, binary, tc.name+"-negative", tc.test)
			if code != 1 || !strings.Contains(log, tc.diagnostic) || !strings.Contains(log, "--- FAIL: TestNostr") || strings.Contains(log, "panic:") {
				t.Fatalf("output plant missed intended assertion: exit%d; log retained in observer artifacts", code)
			}
			t.Logf("control %s: unmodified exit0; isolated fault exit1 at %q", tc.name, tc.diagnostic)
		})
	}
}

func (o *nostrObserver) testProcess(t *testing.T, binary, label, selection string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run", selection, "-test.v", "-test.parallel", "1")
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	cmd.Dir = filepath.Join(o.root, "internal", "facade")
	started := time.Now().UTC()
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatalf("output control setup/exec failed: %v", err)
	}
	pid := cmd.Process.Pid
	err := cmd.Wait()
	code := cmd.ProcessState.ExitCode()
	if ctx.Err() != nil || (err != nil && code != 1) {
		t.Fatalf("output control crashed or execution failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(o.scratch, label+".log"), log.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	receipt, _ := json.MarshalIndent(map[string]any{"argv": cmd.Args, "pid": pid, "started": started, "finished": time.Now().UTC(), "exit": code, "selected_test": selection}, "", "  ")
	if err := os.WriteFile(filepath.Join(o.scratch, label+".json"), receipt, 0600); err != nil {
		t.Fatal(err)
	}
	return code, log.String()
}
