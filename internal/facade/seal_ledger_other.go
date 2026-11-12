//go:build !linux && !darwin

package facade

import "errors"

// errNoExchange: this platform has no atomic exchange this CLI uses, so a
// final sign refuses to record a seal (fail closed) instead of falling back
// to a plain rename.
var errNoExchange = errors.New("atomic rename exchange unavailable")

func exchangeAt(dir int, a, b string) error { return errNoExchange }

func renameNewAt(dir int, from, to string) error { return errNoExchange }
