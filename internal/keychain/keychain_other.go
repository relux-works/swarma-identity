//go:build !darwin || !cgo

package keychain

// TestMode reports whether this build carries the keychaintest store.
const TestMode = false

// Default has no Keychain outside darwin cgo builds.
func Default() (Store, error) { return nil, ErrUnsupported }
