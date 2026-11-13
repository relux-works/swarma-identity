package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const runMainEnv = "SWARMA_KEYCHAIN_RUN_MAIN"

// TestMain runs main itself when the test binary is re-executed by
// TestMainExitsWithResultCode.
func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		os.Args = append([]string{"swarma-keychain"}, os.Args[1:]...)
		main()
		os.Exit(99) // unreachable when main exits by itself
	}
	os.Exit(m.Run())
}

// Claim: the process ends with RunKeychain's code right after the envelope:
// a refused value build exits 3 and an unknown command exits 2, each with
// exactly one JSON envelope on stdout and nothing on stderr, and never with
// the sentinel 99 that would mean main returned instead of exiting. Limit:
// "no further work" after the write is shown by main's source, not measured;
// this test proves the exit status and that the envelope is the only output.
func TestMainExitsWithResultCode(t *testing.T) {
	dir := t.TempDir()
	descriptor := filepath.Join(dir, "social.json")
	if err := os.WriteFile(descriptor, []byte(`{"names":{"_":"aa"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		code int
		err  string
	}{
		{[]string{"value", "build", "--grant-xonly", "zz", "--social-descriptor", descriptor, "--json"}, 3, "LANDLORD_KEY"},
		{[]string{"nope", "x", "--json"}, 2, "BAD_INPUT"},
	} {
		cmd := exec.Command(os.Args[0], c.args...)
		cmd.Env = append(os.Environ(), runMainEnv+"=1")
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != c.code {
			t.Fatalf("%v: exit %v, want %d", c.args, err, c.code)
		}
		var env struct {
			OK    bool `json:"ok"`
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		dec := json.NewDecoder(&stdout)
		if err := dec.Decode(&env); err != nil || env.OK || env.Error.Code != c.err {
			t.Fatalf("%v: envelope %+v %v", c.args, env, err)
		}
		if dec.More() || stderr.Len() != 0 {
			t.Fatalf("%v: output beyond the one envelope (stderr %q)", c.args, stderr.String())
		}
	}
}
