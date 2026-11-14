// Package keypolicy defines public grant-key access choices without linking a
// signer or Keychain implementation into the public-data CLI.
package keypolicy

import "errors"

type Policy string

const (
	CurrentSet Policy = "biometry-current-set"
	Any        Policy = "biometry-any"
	OrPasscode Policy = "biometry-or-passcode"
	Default           = CurrentSet
)

var (
	ErrUnknown  = errors.New("UNKNOWN_ACCESS_POLICY")
	ErrMismatch = errors.New("ACCESS_POLICY_MISMATCH")
)

// SecurityFlags maps to the public SecAccessControlCreateFlags values. The
// Darwin bridge checks these against the SDK constants at compile time. All
// three use WhenPasscodeSetThisDeviceOnly; flags never select accessibility.
func (p Policy) SecurityFlags() (uint64, error) {
	switch p {
	case CurrentSet:
		return 1 << 3, nil // kSecAccessControlBiometryCurrentSet
	case Any:
		return 1 << 1, nil // kSecAccessControlBiometryAny
	case OrPasscode:
		return 1 << 0, nil // kSecAccessControlUserPresence (biometry OR passcode)
	default:
		return 0, ErrUnknown
	}
}

// FromFlags decodes the one-byte policy recorded with the item. No unknown or
// missing new policy is allowed to silently become the default.
func FromFlags(flags uint64) (Policy, error) {
	for _, p := range []Policy{CurrentSet, Any, OrPasscode} {
		if f, _ := p.SecurityFlags(); flags == f {
			return p, nil
		}
	}
	return "", ErrUnknown
}
