package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/swarma-identity/internal/facade"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := facade.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
