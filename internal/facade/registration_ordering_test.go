package facade

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"

	reg "github.com/relux-works/swarma-identity/internal/registration"
)

// Real construction and size validation consume deterministic simulated time.
// Either boundary leaving 29s must refuse without a payload; 30s/31s neighbors
// emit the once-built bytes and original IDs/timestamps. No wall-clock wait or
// CLI clock override is used; the ordinary CLI fixes all dependencies itself.
func TestRegistrationEmissionOrdering(t *testing.T) {
	for _, stage := range []string{"construction", "size"} {
		t.Run(stage, func(t *testing.T) {
			for _, remaining := range []uint64{29, 30, 31} {
				t.Run(fmt.Sprintf("remaining%d", remaining), func(t *testing.T) {
					e := newRegTestEnv(t, "two-stage", true)
					reservation, en, exit := e.run(t, "reserve", "reservation", e.reserve)
					regTestSuccess(t, en, exit)
					s := regTestSession(t, e)
					raw := regTestJSON(t, regRequest{regPrefix + "request/1", reservation, regTestBundleHash(t, reservation), "A", 600})
					instant := time.Now()
					var built *reg.SigningRequest
					var ids reg.RequestIDs
					var preparedAt uint64
					builds, sizes, captures := 0, 0, 0
					ops := regPrepareOps{
						build: func(plan *reg.Plan, slot, unsigned string, generated reg.RequestIDs, now uint64) (*reg.SigningRequest, error) {
							builds++
							ids, preparedAt = generated, now
							request, err := s.planner.PrepareRequest(plan, slot, unsigned, generated, now)
							if err != nil {
								t.Fatalf("real construction failed: %v", err)
							}
							built = request
							if stage == "construction" {
								instant = time.Unix(int64(ids.ExpiresAt-remaining), 0)
							}
							return request, err
						},
						size: func(raw []byte) *Failure {
							sizes++
							if built == nil || !bytes.Equal(raw, built.Bytes()) {
								t.Fatal("size did not inspect once-constructed bytes")
							}
							f := regEmissionSize(raw)
							if f != nil {
								t.Fatalf("real size check failed: %+v", f)
							}
							if stage == "size" {
								instant = time.Unix(int64(ids.ExpiresAt-remaining), 0)
							}
							return f
						},
						now: func() time.Time { captures++; return instant },
					}
					payload, f := s.prepareWith(raw, ops)
					if remaining < 30 {
						if f == nil || f.Code != "REGISTRATION_POLICY_REFUSED" || f.Exit != 3 || payload != nil {
							t.Fatal("expired request emitted after later work")
						}
					} else {
						if f != nil || payload == nil {
							t.Fatal("valid neighboring final margin refused")
						}
						var state regRequestState
						if !regState(payload["request-state.json"], &state, "request-state") || state.PreparedAt != preparedAt || state.ExpiresAt != ids.ExpiresAt || state.RequestID != ids.RequestID || state.SittingID != ids.SittingID || !bytes.Equal(payload["request.json"], built.Bytes()) || !bytes.Equal(payload["review-frame.bin"], built.ReviewFrame()) {
							t.Fatal("final recapture regenerated retained request state")
						}
					}
					if builds != 1 || sizes != 1 || captures != 1 {
						t.Fatal("construction, size or final capture was not executed exactly once")
					}
				})
			}
		})
	}
}

// This supplements behavior with a structural invariant: the trusted-time
// refusal is immediately before returned output, after every payload write.
// It is not a behavioral ordering witness.
func TestRegistrationEmissionFinalStatement(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "registration.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "prepareWith" {
			continue
		}
		statements := fn.Body.List
		if len(statements) < 2 {
			t.Fatal("missing final emission statements")
		}
		last, ok := statements[len(statements)-1].(*ast.ReturnStmt)
		if !ok || len(last.Results) != 2 {
			t.Fatal("emission does not end in payload return")
		}
		payload, ok := last.Results[0].(*ast.Ident)
		failure, nilOK := last.Results[1].(*ast.Ident)
		if !ok || !nilOK || payload.Name != "payload" || failure.Name != "nil" {
			t.Fatal("unexpected final emission return")
		}
		guard, ok := statements[len(statements)-2].(*ast.IfStmt)
		if !ok {
			t.Fatal("final emission recapture is not adjacent to return")
		}
		unary, ok := guard.Cond.(*ast.UnaryExpr)
		if !ok || unary.Op != token.NOT {
			t.Fatal("missing final emission refusal condition")
		}
		call, ok := unary.X.(*ast.CallExpr)
		if !ok {
			t.Fatal("missing final emission margin call")
		}
		name, ok := call.Fun.(*ast.Ident)
		if !ok || name.Name != "regEmissionMargin" || len(call.Args) != 3 {
			t.Fatal("wrong final emission guard")
		}
		capture, ok := call.Args[2].(*ast.CallExpr)
		if !ok {
			t.Fatal("final emission time is not recaptured")
		}
		selector, ok := capture.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "now" || len(capture.Args) != 0 {
			t.Fatal("wrong final emission clock")
		}
		return
	}
	t.Fatal("missing fresh preparation method")
}
