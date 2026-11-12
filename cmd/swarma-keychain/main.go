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

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := facade.RunKeychain(ctx, os.Args[1:], os.Stdout, os.Stderr, keysign.New())
	stop()
	os.Exit(code)
}
