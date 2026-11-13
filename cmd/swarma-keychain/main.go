// swarma-keychain is the Mac-only grant-key tool (G1-K): keychain keygen,
// keychain sign and value build. It is the only binary that links the
// signer; swarma-identity never holds a private key. Outside darwin cgo
// builds the keychain commands refuse with UNSUPPORTED_CAPABILITY.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/swarma-identity/internal/facade"
	"github.com/relux-works/swarma-identity/internal/keysign"
)

// main exits the process as soon as RunKeychain returns. RunKeychain's last
// action is the single write of the JSON envelope to stdout (run in
// internal/facade/cli.go; os.Stdout is unbuffered, so nothing is left to
// flush). The process then ends without further work: no deferred calls, no
// signal teardown, no collection, and memory the signer used is returned to
// the OS with the process. The signer's scratch is already wiped and
// unreferenced when the output is written; docs/KEYCHAIN.md "Residual
// memory" states why the exit matters for the library temporaries.
func main() {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	os.Exit(facade.RunKeychain(ctx, os.Args[1:], os.Stdout, os.Stderr, keysign.New()))
}
