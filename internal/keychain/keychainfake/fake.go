// Package keychainfake is a TEST-ONLY in-memory keychain.Store. It records
// custody calls in order (Access reads only public policy metadata) so tests can prove that nothing reads a secret
// before the human confirmed. No product binary links it; a test asserts that.
package keychainfake

import (
	"errors"
	"sync"

	"github.com/relux-works/swarma-identity/internal/keychain"
	"github.com/relux-works/swarma-identity/internal/keypolicy"
)

type item struct {
	secret [32]byte
	public []byte
	access keypolicy.Policy
	actual keypolicy.Policy
}

type Store struct {
	mu           sync.Mutex
	items        map[string]item
	publicItems  map[string][]byte
	policies     map[string]keypolicy.Policy
	Events       []string  // "preflight", "exists:<label>", "public:<label>", "create:<label>", "secret:<label>"
	Reasons      []string  // the prompt reason of every secret read
	PreflightErr error     // returned by Preflight when set
	SecretErr    error     // returned by Secret when set
	Swap         *[32]byte // when set, Secret returns these bytes instead (a swapped item)
	// InteractionRequired models the owner's data-protection keychain: every
	// unauthenticated read of a biometry-ACL item, even attributes, is refused.
	InteractionRequired  bool
	HideAccessInspection bool
	PublicAddErr         error // fail the second add, after the protected item was added
	OnEvent              func(string)
}

func New() *Store {
	return &Store{items: map[string]item{}, publicItems: map[string][]byte{}, policies: map[string]keypolicy.Policy{}}
}

func (s *Store) event(e string) {
	s.Events = append(s.Events, e)
	if s.OnEvent != nil {
		s.OnEvent(e)
	}
}

func (s *Store) Preflight(access keypolicy.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := access.SecurityFlags(); err != nil {
		return err
	}
	s.event("preflight")
	return s.PreflightErr
}

func (s *Store) Public(label string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.event("public:" + label)
	pub, ok := s.publicItems[label]
	if !ok {
		return nil, keychain.ErrNotFound
	}
	return append([]byte{}, pub...), nil
}

// protectedPublic models the old attributes-only query, without authentication.
func (s *Store) protectedPublic(label string) ([]byte, error) {
	it, ok := s.items[label]
	if !ok {
		return nil, keychain.ErrNotFound
	}
	if s.InteractionRequired {
		return nil, keychain.ErrInteraction
	}
	return append([]byte{}, it.public...), nil
}

func (s *Store) Exists(label string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.event("exists:" + label)
	if _, ok := s.publicItems[label]; ok {
		return true, nil
	}
	_, err := s.protectedPublic(label)
	if err == nil || errors.Is(err, keychain.ErrInteraction) {
		return true, nil
	}
	if errors.Is(err, keychain.ErrNotFound) {
		return false, nil
	}
	return false, err
}

func (s *Store) Create(label string, secret *[32]byte, public []byte, access keypolicy.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := access.SecurityFlags(); err != nil {
		return err
	}
	s.event("create:" + label)
	if _, ok := s.items[label]; ok {
		return keychain.ErrExists
	}
	s.items[label] = item{*secret, append([]byte{}, public...), access, access}
	err := s.PublicAddErr
	if _, ok := s.publicItems[label]; ok {
		err = keychain.ErrExists
	}
	if err != nil {
		delete(s.items, label)
		return err
	}
	s.publicItems[label] = append([]byte{}, public...)
	s.policies[label] = access
	return nil
}

func (s *Store) Secret(label, reason string, dst *[32]byte, access keypolicy.Policy) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.event("secret:" + label)
	s.Reasons = append(s.Reasons, reason)
	if s.SecretErr != nil {
		return nil, s.SecretErr
	}
	it, ok := s.items[label]
	if !ok {
		return nil, keychain.ErrNotFound
	}
	// Actual policy is independently readable in this fake, unlike native flags.
	if it.access != access || (!s.HideAccessInspection && it.actual != access) {
		return nil, keypolicy.ErrMismatch
	}
	recorded, ok := s.policies[label]
	if !ok {
		recorded = keypolicy.Default
	}
	if recorded != access {
		return nil, keypolicy.ErrMismatch
	}
	*dst = it.secret
	if s.Swap != nil {
		*dst = *s.Swap
	}
	return append([]byte{}, it.public...), nil
}

// Access returns the public companion's recorded policy, with a legacy default.
func (s *Store) Access(label string) (keypolicy.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.publicItems[label]; !ok {
		return "", keychain.ErrPublicNotFound
	}
	access, ok := s.policies[label]
	if !ok {
		access = keypolicy.Default
	}
	if _, err := access.SecurityFlags(); err != nil {
		return "", err
	}
	return access, nil
}

func (s *Store) CanInspectAccess() bool { return !s.HideAccessInspection }

// SetAccess changes only public policy metadata for negative tests.
func (s *Store) SetAccess(label string, access keypolicy.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[label] = access
}

// SetActualAccess changes the simulated ACL without changing either policy record.
func (s *Store) SetActualAccess(label string, access keypolicy.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it := s.items[label]
	it.actual = access
	s.items[label] = it
}

// SetPublic replaces only the non-ACL public item; nil removes it.
func (s *Store) SetPublic(label string, public []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if public == nil {
		delete(s.publicItems, label)
	} else {
		s.publicItems[label] = append([]byte{}, public...)
	}
}

// SetGeneric replaces only the protected item's kSecAttrGeneric metadata.
func (s *Store) SetGeneric(label string, public []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it := s.items[label]
	it.public = append([]byte{}, public...)
	s.items[label] = it
}

// SecretOf returns a copy of a stored secret, for output-scanning tests.
func (s *Store) SecretOf(label string) ([32]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[label]
	return it.secret, ok
}
