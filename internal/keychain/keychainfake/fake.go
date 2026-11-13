// Package keychainfake is a TEST-ONLY in-memory keychain.Store. It records
// every store call in order so tests can prove that nothing reads a secret
// before the human confirmed. No product binary links it; a test asserts that.
package keychainfake

import (
	"errors"
	"sync"

	"github.com/relux-works/swarma-identity/internal/keychain"
)

type item struct {
	secret [32]byte
	public []byte
}

type Store struct {
	mu           sync.Mutex
	items        map[string]item
	publicItems  map[string][]byte
	Events       []string  // "preflight", "exists:<label>", "public:<label>", "create:<label>", "secret:<label>"
	Reasons      []string  // the prompt reason of every secret read
	PreflightErr error     // returned by Preflight when set
	SecretErr    error     // returned by Secret when set
	Swap         *[32]byte // when set, Secret returns these bytes instead (a swapped item)
	// InteractionRequired models the owner's data-protection keychain: every
	// unauthenticated read of a biometry-ACL item, even attributes, is refused.
	InteractionRequired bool
	PublicAddErr        error // fail the second add, after the protected item was added
	OnEvent             func(string)
}

func New() *Store { return &Store{items: map[string]item{}, publicItems: map[string][]byte{}} }

func (s *Store) event(e string) {
	s.Events = append(s.Events, e)
	if s.OnEvent != nil {
		s.OnEvent(e)
	}
}

func (s *Store) Preflight() error {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func (s *Store) Create(label string, secret *[32]byte, public []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.event("create:" + label)
	if _, ok := s.items[label]; ok {
		return keychain.ErrExists
	}
	s.items[label] = item{*secret, append([]byte{}, public...)}
	err := s.PublicAddErr
	if _, ok := s.publicItems[label]; ok {
		err = keychain.ErrExists
	}
	if err != nil {
		delete(s.items, label)
		return err
	}
	s.publicItems[label] = append([]byte{}, public...)
	return nil
}

func (s *Store) Secret(label, reason string, dst *[32]byte) ([]byte, error) {
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
	*dst = it.secret
	if s.Swap != nil {
		*dst = *s.Swap
	}
	return append([]byte{}, it.public...), nil
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
