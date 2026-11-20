package facade

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func linkL1Script(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "scripts", "rehearse_link_l1.py")
}

// Claim: the rehearsal rejects non-regtest before opening tools, wallets, or scratch.
func TestLinkL1NetworkGate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-created")
	for _, network := range []string{"main", "test", "unknown"} {
		command := exec.Command("python3", "-B", linkL1Script(t), "--network", network,
			"--core-bin", "unavailable", "--chain-lab", "unavailable",
			"--identity", "unavailable", "--root", root)
		output, err := command.CombinedOutput()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 {
			t.Fatalf("network %s: exit %v, output %s", network, err, output)
		}
		var report struct {
			Status         string `json:"status"`
			RPCCalls       *int   `json:"rpc_calls"`
			WalletsCreated *int   `json:"wallets_created"`
		}
		if err := json.Unmarshal(output, &report); err != nil {
			t.Fatal(err)
		}
		if report.Status != "NETWORK_REFUSED" || report.RPCCalls == nil || *report.RPCCalls != 0 ||
			report.WalletsCreated == nil || *report.WalletsCreated != 0 {
			t.Fatalf("wrong network refusal: %s", output)
		}
		if _, err := os.Stat(root); !os.IsNotExist(err) {
			t.Fatalf("network refusal touched scratch: %v", err)
		}
	}
}

// Claim: real Core confirms both seals, then both human-landlord drafts refuse AGENT_NOT_V3; not a live-grant proof.
func TestLinkL1RegtestContractStop(t *testing.T) {
	if os.Getenv("L1_REGTEST") != "1" {
		t.Skip("requires L1_REGTEST=1, pinned Core 28.0 and the pinned HTTPS chain-lab checkout")
	}
	script := linkL1Script(t)
	repo := filepath.Dir(filepath.Dir(script))
	for _, name := range []string{"HOME", "GOCACHE", "GOMODCACHE", "GOPATH", "GOTMPDIR", "TMPDIR"} {
		value, err := filepath.EvalSymlinks(os.Getenv(name))
		if err != nil || !filepath.IsAbs(value) {
			t.Fatalf("%s must resolve to an absolute task scratch directory", name)
		}
		relative, err := filepath.Rel(filepath.Join(repo, ".temp"), value)
		if err != nil || relative == ".." || filepath.IsAbs(relative) || len(relative) >= 3 && relative[:3] == "../" {
			t.Fatalf("%s is outside task scratch", name)
		}
	}
	if os.Getenv("GOTELEMETRY") != "off" {
		t.Fatal("GOTELEMETRY=off required")
	}
	root := t.TempDir()
	identity := filepath.Join(root, "swarma-identity")
	build := exec.Command("go", "build", "-p", "1", "-o", identity, "./cmd/swarma-identity")
	build.Dir = repo
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("identity build: %v\n%s", err, output)
	}
	command := exec.Command("python3", "-B", script, "--network", "regtest",
		"--core-bin", os.Getenv("L1_CORE_BIN"), "--chain-lab", os.Getenv("L1_CHAIN_LAB"),
		"--identity", identity, "--root", filepath.Join(root, "run"))
	output, err := command.CombinedOutput()
	if err := os.WriteFile(filepath.Join(root, "script-output.json"), output, 0600); err != nil {
		t.Fatal(err)
	}
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 3 {
		t.Fatalf("prefix must stop with exit 3: %v\n%s", err, output)
	}
	var report struct {
		Status     string `json:"status"`
		Network    string `json:"network"`
		CoreReaped bool   `json:"core_reaped"`
		Directions map[string]struct {
			Confirmations int    `json:"confirmations"`
			FundingType   string `json:"funding_type"`
			DraftRefusal  string `json:"draft_refusal"`
		} `json:"directions"`
		Commands []struct {
			ExitCode int    `json:"exit_code"`
			Refusal  string `json:"refusal"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "STOP:grant-draft-human-landlord" || report.Network != "regtest" || !report.CoreReaped || len(report.Directions) != 2 {
		t.Fatalf("wrong prefix evidence: %s", output)
	}
	for _, role := range []string{"A", "B"} {
		direction := report.Directions[role]
		if direction.Confirmations < 1 || direction.FundingType != "P2WPKH" || direction.DraftRefusal != "AGENT_NOT_V3" {
			t.Fatalf("role %s lacks supported-prefix evidence: %s", role, output)
		}
	}
	counts := map[string]int{}
	for _, command := range report.Commands {
		if command.Refusal == "" && command.ExitCode != 0 || command.Refusal != "" && command.ExitCode != 3 {
			t.Fatalf("unexpected CLI exit: %s", output)
		}
		counts[command.Refusal]++
	}
	if counts[""] != 2 || counts["NETWORK_PIN"] != 2 || counts["AGENT_NOT_V3"] != 2 || len(report.Commands) != 6 {
		t.Fatalf("missing paired controls: %s", output)
	}
	public := os.Getenv("L1_PUBLIC_RESULT")
	if public != "" {
		if !filepath.IsAbs(public) {
			t.Fatal("L1_PUBLIC_RESULT must be absolute")
		}
		if err := os.WriteFile(public, output, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("prefix script exit=3: confirmed seals and named STOP in both directions; Core reaped")
}
