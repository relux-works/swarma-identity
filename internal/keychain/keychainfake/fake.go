// Package keychainfake is a TEST-ONLY in-memory keychain.Store. It records
// every store call in order so tests can prove that nothing reads a secret
// before the human confirmed. No product binary links it; a test asserts that.
package keychainfake

import (
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
	Events       []string  // "preflight", "public:<label>", "create:<label>", "secret:<label>"
	Reasons      []string  // the prompt reason of every secret read
	PreflightErr error     // returned by Preflight when set
	SecretErr    error     // returned by Secret when set
	Swap         *[32]byte // when set, Secret returns these bytes instead (a swapped item)
	OnEvent      func(string)
}

func New() *Store { return &Store{items: map[string]item{}} }

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
	it, ok := s.items[label]
	if !ok {
		return nil, keychain.ErrNotFound
	}
	return append([]byte{}, it.public...), nil
}

func (s *Store) Create(label string, secret *[32]byte, public []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.event("create:" + label)
	if _, ok := s.items[label]; ok {
		return keychain.ErrExists
	}
	s.items[label] = item{*secret, append([]byte{}, public...)}
	return nil
}

func (s *Store) Secret(label, reason string, dst *[32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.event("secret:" + label)
	s.Reasons = append(s.Reasons, reason)
	if s.SecretErr != nil {
		return s.SecretErr
	}
	it, ok := s.items[label]
	if !ok {
		return keychain.ErrNotFound
	}
	*dst = it.secret
	if s.Swap != nil {
		*dst = *s.Swap
	}
	return nil
}

// SecretOf returns a copy of a stored secret, for output-scanning tests.
func (s *Store) SecretOf(label string) ([32]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[label]
	return it.secret, ok
}
