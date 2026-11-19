package facade

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// A genuinely mainnet-issued grant cannot reach any lifecycle action without
// independent opt-in and exact confirmation; the regtest lifecycle stays usable.
func TestSealMainnetAuthorization(testingContext *testing.T) {
	for _, command := range []string{"plan", "sign", "broadcast", "observe"} {
		testingContext.Run(command, func(testingContext *testing.T) {
			fixture := newSealFixtureNetwork(testingContext, "main")
			if _, _, failure := sealPlan(fixture.request); failure != nil {
				testingContext.Fatal("mainnet-issued reproduction fixture invalid", failure)
			}
			args := []string{"seal", command, "--journal", fixture.path, "--issuer-key", fixture.issuer}
			switch command {
			case "plan":
				args = append(args, "--request", writeInput(testingContext, fixture.request))
			case "sign":
				args = append(args, "--label", kcLabel)
			case "broadcast":
				args = append(args, "--config", fixture.node.read, "--broadcast-config", fixture.node.write)
			case "observe":
				args = append(args, "--config", fixture.node.read)
			}
			cases := []struct {
				name, code string
				options    []string
			}{
				{"network-required", "BAD_INPUT", nil},
				{"no-opt-in", "SEAL_MAINNET_OPT_IN_REQUIRED", []string{"--network", "main"}},
				{"confirmation-without-opt-in", "SEAL_MAINNET_OPT_IN_REQUIRED", []string{"--network", "main", "--confirm-mainnet", "MAINNET"}},
				{"no-confirmation", "SEAL_MAINNET_CONFIRMATION_REQUIRED", []string{"--network", "main", "--allow-mainnet"}},
				{"wrong-confirmation", "SEAL_MAINNET_CONFIRMATION_REQUIRED", []string{"--network", "main", "--allow-mainnet", "--confirm-mainnet", "mainnet"}},
			}
			for _, test := range cases {
				testingContext.Run(test.name, func(testingContext *testing.T) {
					input := append(append([]string{}, args...), test.options...)
					envelope, code := fixture.harness.run(input...)
					mustRefuse(testingContext, envelope, code, test.code)
					if _, err := os.Stat(fixture.path); !os.IsNotExist(err) || fixture.harness.keyRead || len(fixture.node.methods) != 0 {
						testingContext.Fatal("authorization refusal changed state or exercised signing/RPC")
					}
				})
			}
		})
	}
	control := newSealFixture(testingContext)
	control.signed()
	envelope, code := control.broadcast()
	mustOK(testingContext, envelope, code)
	envelope, code = control.observe()
	mustOK(testingContext, envelope, code)
}

// Only the two independent mainnet acknowledgements pass the authorization
// parser. This control performs no mainnet plan, signing or RPC operation.
func TestSealNetworkOptionControls(testingContext *testing.T) {
	for _, options := range []map[string]string{
		{"network": "regtest"},
		{"network": "main", "allow-mainnet": "", "confirm-mainnet": "MAINNET"},
	} {
		if failure := sealNetworkOptions(options); failure != nil {
			testingContext.Fatal("valid network options refused", failure)
		}
	}
	for _, options := range []map[string]string{
		{}, {"network": "unknown"},
		{"network": "regtest", "allow-mainnet": ""},
		{"network": "regtest", "confirm-mainnet": "MAINNET"},
	} {
		if failure := sealNetworkOptions(options); failure == nil || failure.Code != "BAD_INPUT" {
			testingContext.Fatalf("invalid network options admitted: %+v", failure)
		}
	}
}

// An independently supplied operator issuer pin is required on every command;
// mismatches cannot alter journals or reach secrets/RPC, beside a valid display.
func TestSealOperatorIssuerPin(testingContext *testing.T) {
	for _, command := range []string{"plan", "sign", "broadcast", "observe"} {
		testingContext.Run(command, func(testingContext *testing.T) {
			fixture := newSealFixture(testingContext)
			args := []string{"seal", command, "--journal", fixture.path, "--network", "regtest"}
			switch command {
			case "plan":
				args = append(args, "--request", writeInput(testingContext, fixture.request))
			case "sign":
				fixture.planned()
				args = append(args, "--label", kcLabel)
			case "broadcast":
				fixture.signed()
				args = append(args, "--config", fixture.node.read, "--broadcast-config", fixture.node.write)
			case "observe":
				fixture.signed()
				args = append(args, "--config", fixture.node.read)
			}
			before, _ := os.ReadFile(fixture.path)
			fixture.harness.keyRead = false
			for _, issuer := range []string{"", cedarKey} {
				input := append([]string{}, args...)
				want := "BAD_INPUT"
				if issuer != "" {
					input = append(input, "--issuer-key", issuer)
					want = "SEAL_ISSUER_MISMATCH"
				}
				envelope, code := fixture.harness.run(input...)
				mustRefuse(testingContext, envelope, code, want)
				after, err := os.ReadFile(fixture.path)
				if (command == "plan" && !os.IsNotExist(err)) || !bytes.Equal(before, after) || fixture.harness.keyRead || len(fixture.node.methods) != 0 {
					testingContext.Fatal("issuer refusal changed state or exercised signing/RPC")
				}
			}
		})
	}
	control := newSealFixture(testingContext)
	control.signed()
	for _, text := range []string{"Landlord: id/landlord-a", "Agent: id/landlord-a-agent", "Issuer key: " + control.issuer, "Seal pays P2PKH(even-y issuer key)."} {
		if !strings.Contains(control.harness.preKey, text) {
			testingContext.Fatalf("issuer display omitted %q before secret read", text)
		}
	}
}

// The reviewer reproduction and malformed/missing depth variants refuse before
// acceptance or attempt writes; the check covers every input, not just the first.
func TestSealFundingParentConfirmations(testingContext *testing.T) {
	for _, mode := range []string{"unconfirmed-parent", "missing-confirmations", "invalid-confirmations", "negative-confirmations", "second-unconfirmed-parent"} {
		testingContext.Run(mode, func(testingContext *testing.T) {
			fixture := newSealFixture(testingContext)
			if mode == "second-unconfirmed-parent" {
				rebindSealFunding(testingContext, fixture, sealTwoFundingInputs(testingContext, fixture.request.Funding, false))
			}
			fixture.signed()
			before, _ := os.ReadFile(fixture.path)
			fixture.node.mode = mode
			envelope, code := fixture.broadcast()
			mustRefuse(testingContext, envelope, code, "SEAL_FUNDING_UNCONFIRMED")
			after, _ := os.ReadFile(fixture.path)
			journal := fixture.journal()
			if !bytes.Equal(before, after) || fixture.node.sends != 0 || journal.State != "signed" || journal.Attempted {
				testingContext.Fatal("unconfirmed funding consumed acceptance or broadcast intent")
			}
			for _, method := range fixture.node.methods {
				if method == "decoderawtransaction" || method == "testmempoolaccept" || method == "sendrawtransaction" {
					testingContext.Fatal("unconfirmed funding reached transaction acceptance", method)
				}
			}
			fixture.node.mode = ""
			envelope, code = fixture.broadcast()
			mustOK(testingContext, envelope, code)
			if fixture.node.sends != 1 || fixture.journal().State != "broadcast" {
				testingContext.Fatal("confirmed funding positive control failed")
			}
		})
	}
}

// Explicit credentials with the wrong RPC role refuse before any request or
// journal write; the unchanged credentials then pass the same broadcast flow.
func TestSealPreflightCredentialRoles(testingContext *testing.T) {
	for _, role := range []string{"read", "broadcast"} {
		testingContext.Run(role, func(testingContext *testing.T) {
			fixture := newSealFixture(testingContext)
			fixture.signed()
			readBytes, err := os.ReadFile(fixture.node.read)
			if err != nil {
				testingContext.Fatal(err)
			}
			writeBytes, err := os.ReadFile(fixture.node.write)
			if err != nil {
				testingContext.Fatal(err)
			}
			var readConfig, writeConfig Config
			if json.Unmarshal(readBytes, &readConfig) != nil || json.Unmarshal(writeBytes, &writeConfig) != nil {
				testingContext.Fatal("credential fixture config invalid")
			}
			originalRead, originalWrite := fixture.node.read, fixture.node.write
			want := "SEAL_READ_AUTH"
			if role == "read" {
				readConfig.Node.AuthFile = writeConfig.Node.AuthFile
				fixture.node.read = writeInput(testingContext, readConfig)
			} else {
				writeConfig.Node.AuthFile = readConfig.Node.AuthFile
				fixture.node.write = writeInput(testingContext, writeConfig)
				want = "SEAL_BROADCAST_AUTH"
			}
			before, _ := os.ReadFile(fixture.path)
			envelope, code := fixture.broadcast()
			mustRefuse(testingContext, envelope, code, want)
			after, _ := os.ReadFile(fixture.path)
			if !bytes.Equal(before, after) || len(fixture.node.methods) != 0 || fixture.node.sends != 0 || fixture.journal().Attempted {
				testingContext.Fatal("credential role refusal contacted RPC or changed journal")
			}
			fixture.node.read, fixture.node.write = originalRead, originalWrite
			envelope, code = fixture.broadcast()
			mustOK(testingContext, envelope, code)
		})
	}
}
