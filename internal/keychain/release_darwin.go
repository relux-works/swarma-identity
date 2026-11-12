//go:build darwin && cgo && !keychaintest

package keychain

// TestMode reports whether this build carries the keychaintest store.
const TestMode = false

// Default is the release store: the data protection keychain, items bound to
// the currently enrolled biometry of this device, read once per signature.
func Default() (Store, error) { return darwinStore{}, nil }
