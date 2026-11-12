//go:build darwin && cgo && keychaintest

package keychain

/*
#cgo CFLAGS: -DSK_TESTMODE
#include <stdlib.h>
int sk_open(const char *path);
int sk_delete(const char *label);
*/
import "C"

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

// TestMode reports whether this build carries the keychaintest store.
const TestMode = true

// TestKeychainEnv names the throwaway file keychain the CI job creates. The
// keychaintest build never falls back to any other keychain.
const TestKeychainEnv = "SWARMA_KEYCHAIN_TEST_PATH"

// Default is the TEST store: a file keychain created by the test job, no
// access control and no biometry. It refuses any path that is not an
// absolute swarma-test-*.keychain-db regular file, so it cannot name the
// login keychain.
func Default() (Store, error) {
	p := os.Getenv(TestKeychainEnv)
	base := filepath.Base(p)
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || !strings.HasPrefix(base, "swarma-test-") || !strings.HasSuffix(base, ".keychain-db") {
		return nil, ErrTestPath
	}
	if st, err := os.Lstat(p); err != nil || !st.Mode().IsRegular() {
		return nil, ErrTestPath
	}
	cp := C.CString(p)
	defer C.free(unsafe.Pointer(cp))
	if C.sk_open(cp) != 0 {
		return nil, ErrTestPath
	}
	return darwinStore{}, nil
}

// Delete removes a test item. Only the keychaintest build has it.
func Delete(label string) error {
	cl := C.CString(label)
	defer C.free(unsafe.Pointer(cl))
	return statusErr(C.sk_delete(cl))
}
