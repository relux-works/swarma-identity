// Package keychain stores one secp256k1 grant secret per label as a Mac
// Keychain generic-password item and reads it back only under a fresh
// per-call user authentication. The secret never leaves this package except
// into the caller's buffer for one signature; nothing here prints, logs or
// writes it anywhere else.
//
// Release builds on darwin use the data protection keychain with a
// biometryCurrentSet, this-device-only access control. The build tag
// keychaintest replaces that with a throwaway file keychain and no access
// control, for hosted CI only; release builds never carry it.
package keychain

import (
	"errors"
	"regexp"
)

// Service is the kSecAttrService of every grant-key item; the label is the
// account. No other item is ever read or written.
const Service = "works.relux.swarma-identity.grant-key"

var (
	ErrUnsupported = errors.New("KEYCHAIN_UNSUPPORTED") // not a darwin cgo build
	ErrNotFound    = errors.New("KEY_NOT_FOUND")        // no item under the label
	ErrExists      = errors.New("KEY_EXISTS")           // an item already uses the label
	ErrCanceled    = errors.New("AUTH_CANCELED")        // the user canceled the prompt
	ErrAuth        = errors.New("AUTH_FAILED")          // authentication did not succeed
	ErrBiometry    = errors.New("BIOMETRY_UNAVAILABLE") // no enrolled, usable biometry
	ErrEntitlement = errors.New("KEYCHAIN_ENTITLEMENT") // errSecMissingEntitlement (-34018)
	ErrItem        = errors.New("KEY_ITEM_INVALID")     // the item has an unexpected shape
	ErrStore       = errors.New("KEYCHAIN_ERROR")       // any other Security status
	ErrTestPath    = errors.New("KEYCHAIN_TEST_PATH")   // keychaintest: unusable test keychain
)

// Store is the custody seam. Public reads only the stored compressed public
// key and never prompts. Secret reads the 32-byte secret into dst under a new
// authentication each call; reason is shown in the system prompt.
type Store interface {
	Preflight() error
	Public(label string) ([]byte, error)
	Create(label string, secret *[32]byte, public []byte) error
	Secret(label, reason string, dst *[32]byte) error
}

var labelRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidLabel admits 1..63 bytes of [a-z0-9._-] starting with [a-z0-9].
func ValidLabel(label string) bool { return labelRE.MatchString(label) }
