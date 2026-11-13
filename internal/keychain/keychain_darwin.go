//go:build darwin && cgo

package keychain

/*
#cgo CFLAGS: -x objective-c -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security -framework LocalAuthentication -framework Foundation -framework CoreFoundation
#include <stdlib.h>
#include <string.h>
#include <dispatch/dispatch.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>

#define SK_SERVICE "works.relux.swarma-identity.grant-key"
#define SK_PUBLIC_SERVICE SK_SERVICE ".pub"

enum { SK_OK = 0, SK_NOT_FOUND = 1, SK_EXISTS = 2, SK_CANCELED = 3, SK_AUTH = 4, SK_BIOMETRY = 5, SK_ENTITLEMENT = 6, SK_ITEM = 7, SK_STORE = 8, SK_INTERACTION = 9 };

static int sk_map(OSStatus st) {
	switch (st) {
	case errSecSuccess: return SK_OK;
	case errSecItemNotFound: return SK_NOT_FOUND;
	case errSecDuplicateItem: return SK_EXISTS;
	case errSecUserCanceled: return SK_CANCELED;
	case errSecAuthFailed: return SK_AUTH;
	case errSecInteractionNotAllowed: return SK_INTERACTION; // -25308, not absence
	case -34018: return SK_ENTITLEMENT; // errSecMissingEntitlement
	}
	return SK_STORE;
}

// The secret buffer handed to SecItemAdd is wiped when its CFData is freed.
// Each block stores its length in front of the bytes.
static void sk_wipe(volatile unsigned char *p, size_t n) {
	while (n-- > 0) *p++ = 0;
}
static void sk_wipe_free(void *ptr, void *info) {
	unsigned char *block = (unsigned char *)ptr - sizeof(size_t);
	size_t n;
	memcpy(&n, block, sizeof n);
	sk_wipe(block, n + sizeof n);
	free(block);
}
static void *sk_never_alloc(CFIndex size, CFOptionFlags hint, void *info) { return NULL; }
static CFAllocatorRef sk_wiping_allocator(void) {
	static CFAllocatorRef a = NULL;
	static dispatch_once_t once;
	dispatch_once(&once, ^{
		CFAllocatorContext c = {0, NULL, NULL, NULL, NULL, sk_never_alloc, NULL, sk_wipe_free, NULL};
		a = CFAllocatorCreate(kCFAllocatorDefault, &c);
	});
	return a;
}

#ifdef SK_TESTMODE
// TEST BUILD ONLY (tag keychaintest): one throwaway file keychain, no access
// control, no biometry. Release builds compile none of this.
static SecKeychainRef sk_test_kc = NULL;

// sk_test_read_wiped records whether the last secret read's result bytes
// were all zero after sk_release_read wiped them (1) or not observed (0).
static int sk_test_read_wiped = 0;
int sk_last_read_wiped(void) { return sk_test_read_wiped; }

int sk_open(const char *path) {
	SecKeychainRef kc = NULL;
	if (SecKeychainOpen(path, &kc) != errSecSuccess || kc == NULL) return SK_STORE;
	SecKeychainStatus s = 0;
	if (SecKeychainGetStatus(kc, &s) != errSecSuccess || !(s & kSecUnlockStateStatus)) { CFRelease(kc); return SK_STORE; }
	if (sk_test_kc != NULL) CFRelease(sk_test_kc);
	sk_test_kc = kc;
	return SK_OK;
}
#endif

// sk_release_read wipes the bytes of a secret read's result, then releases
// it. The result is this process's own +1 object (the Copy rule), whose bytes
// the framework allocated on this process's heap when it decoded the reply.
// CFDataGetBytePtr is declared const; the wipe writes through a cast because
// the bytes would otherwise be freed with the secret in them. Any CFData
// result is wiped, including kSecValueData in an attributes-plus-data result
// and data of an unexpected length.
static void sk_release_read(CFTypeRef res) {
	if (res == NULL) return;
	if (CFGetTypeID(res) == CFDictionaryGetTypeID()) {
		CFTypeRef data = CFDictionaryGetValue((CFDictionaryRef)res, kSecValueData);
		if (data != NULL) { CFRetain(data); sk_release_read(data); }
	}
	if (CFGetTypeID(res) == CFDataGetTypeID()) {
		volatile unsigned char *p = (volatile unsigned char *)CFDataGetBytePtr((CFDataRef)res);
		size_t n = (size_t)CFDataGetLength((CFDataRef)res);
		if (p != NULL) sk_wipe(p, n);
#ifdef SK_TESTMODE
		int zero = p != NULL && n > 0;
		for (size_t i = 0; zero && i < n; i++) if (p[i] != 0) zero = 0;
		sk_test_read_wiped = zero;
#endif
	}
	CFRelease(res);
}

static CFMutableDictionaryRef sk_query(const char *label, const char *service, int add) {
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
	CFStringRef acct = CFStringCreateWithCString(NULL, label, kCFStringEncodingUTF8);
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(q, kSecAttrService, svc);
	CFDictionarySetValue(q, kSecAttrAccount, acct);
	CFRelease(svc);
	CFRelease(acct);
#ifdef SK_TESTMODE
	if (add) {
		CFDictionarySetValue(q, kSecUseKeychain, sk_test_kc);
	} else {
		const void *v[1] = { sk_test_kc };
		CFArrayRef list = CFArrayCreate(NULL, v, 1, &kCFTypeArrayCallBacks);
		CFDictionarySetValue(q, kSecMatchSearchList, list);
		CFRelease(list);
	}
#else
	CFDictionarySetValue(q, kSecUseDataProtectionKeychain, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecAttrSynchronizable, kCFBooleanFalse);
#endif
	return q;
}

// Deletion does not read a biometry-protected item or require authentication.
static int sk_delete_item(const char *label, const char *service) {
	CFMutableDictionaryRef q = sk_query(label, service, 0);
	OSStatus st = SecItemDelete(q);
	CFRelease(q);
	return sk_map(st);
}

#ifdef SK_TESTMODE
int sk_delete(const char *label) {
	if (sk_test_kc == NULL) return SK_STORE;
	int secret = sk_delete_item(label, SK_SERVICE);
	int public = sk_delete_item(label, SK_PUBLIC_SERVICE);
	if (secret != SK_OK && secret != SK_NOT_FOUND) return secret;
	if (public != SK_OK && public != SK_NOT_FOUND) return public;
	return secret == SK_OK || public == SK_OK ? SK_OK : SK_NOT_FOUND;
}
#endif

static int sk_preflight(void) {
#ifdef SK_TESTMODE
	return sk_test_kc == NULL ? SK_STORE : SK_OK;
#else
	@autoreleasepool {
		LAContext *ctx = [[LAContext alloc] init];
		NSError *e = nil;
		BOOL ok = [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&e];
		[ctx invalidate];
		[ctx release];
		return ok ? SK_OK : SK_BIOMETRY;
	}
#endif
}

// All non-authenticated reads explicitly forbid UI. In particular, a secret
// existence query must preserve -25308 rather than use UISkip (which hides it).
static int sk_read_no_ui(const char *label, const char *service, int data, CFTypeRef *res) {
	@autoreleasepool {
		CFMutableDictionaryRef q = sk_query(label, service, 0);
		if (data) CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
		else CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
		CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
		LAContext *ctx = nil;
#ifndef SK_TESTMODE
		ctx = [[LAContext alloc] init];
		ctx.interactionNotAllowed = YES;
		CFDictionarySetValue(q, kSecUseAuthenticationContext, (const void *)ctx);
#endif
		OSStatus st = SecItemCopyMatching(q, res);
		CFRelease(q);
		if (ctx != nil) { [ctx invalidate]; [ctx release]; }
		return sk_map(st);
	}
}

static int sk_probe_no_ui(const char *label, const char *service) {
	CFTypeRef res = NULL;
	int rc = sk_read_no_ui(label, service, 0, &res);
	if (res != NULL) CFRelease(res); // attributes only; never request secret data
	return rc;
}

static int sk_exists(const char *label) {
	int rc = sk_probe_no_ui(label, SK_PUBLIC_SERVICE);
	if (rc == SK_OK || rc == SK_INTERACTION) return SK_EXISTS;
	if (rc != SK_NOT_FOUND) return rc;
	rc = sk_probe_no_ui(label, SK_SERVICE);
	if (rc == SK_OK || rc == SK_INTERACTION) return SK_EXISTS;
	return rc;
}

// Only the separate, non-ACL public item is read before the signing display.
static int sk_public(const char *label, unsigned char *out) {
	CFTypeRef res = NULL;
	int rc = sk_read_no_ui(label, SK_PUBLIC_SERVICE, 1, &res);
	if (rc != SK_OK) { if (res != NULL) CFRelease(res); return rc; }
	if (res == NULL || CFGetTypeID(res) != CFDataGetTypeID() || CFDataGetLength((CFDataRef)res) != 33) { if (res != NULL) CFRelease(res); return SK_ITEM; }
	memcpy(out, CFDataGetBytePtr((CFDataRef)res), 33);
	CFRelease(res);
	return SK_OK;
}

// sk_create adds the protected secret, then a non-ACL public item. Release:
// both are device-only, non-synchronizable data-protection items.
static int sk_create(const char *label, const unsigned char *secret, const unsigned char *pub, int publen) {
	@autoreleasepool {
		CFMutableDictionaryRef q = sk_query(label, SK_SERVICE, 1);
		CFStringRef lbl = CFStringCreateWithFormat(NULL, NULL, CFSTR("Swarma grant key %s"), label);
		CFDictionarySetValue(q, kSecAttrLabel, lbl);
		CFRelease(lbl);
		CFDataRef pd = CFDataCreate(NULL, pub, publen);
		CFDictionarySetValue(q, kSecAttrGeneric, pd);
		CFRelease(pd);
#ifndef SK_TESTMODE
		CFErrorRef err = NULL;
		SecAccessControlRef ac = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, kSecAccessControlBiometryCurrentSet, &err);
		if (ac == NULL) { if (err != NULL) CFRelease(err); CFRelease(q); return SK_STORE; }
		CFDictionarySetValue(q, kSecAttrAccessControl, ac);
		CFRelease(ac);
#endif
		size_t n = 32;
		unsigned char *block = malloc(sizeof n + n);
		if (block == NULL) { CFRelease(q); return SK_STORE; }
		memcpy(block, &n, sizeof n);
		memcpy(block + sizeof n, secret, n);
		CFDataRef sd = CFDataCreateWithBytesNoCopy(NULL, block + sizeof n, (CFIndex)n, sk_wiping_allocator());
		if (sd == NULL) { sk_wipe_free(block + sizeof n, NULL); CFRelease(q); return SK_STORE; }
		CFDictionarySetValue(q, kSecValueData, sd);
		CFRelease(sd);
		OSStatus st = SecItemAdd(q, NULL);
		CFRelease(q);
		if (st != errSecSuccess) return sk_map(st);

		q = sk_query(label, SK_PUBLIC_SERVICE, 1);
		lbl = CFStringCreateWithFormat(NULL, NULL, CFSTR("Swarma grant public key %s"), label);
		CFDictionarySetValue(q, kSecAttrLabel, lbl);
		CFRelease(lbl);
#ifndef SK_TESTMODE
		CFDictionarySetValue(q, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
#endif
		pd = CFDataCreate(NULL, pub, publen);
		CFDictionarySetValue(q, kSecValueData, pd);
		CFRelease(pd);
		st = SecItemAdd(q, NULL);
		CFRelease(q);
		if (st != errSecSuccess) {
			int rollback = sk_delete_item(label, SK_SERVICE);
			if (rollback != SK_OK && rollback != SK_NOT_FOUND) return SK_STORE;
		}
		return sk_map(st);
	}
}

// sk_secret reads the secret into out32. Release: a new LAContext per call
// with no reuse window, so every read is its own Touch ID evaluation; the
// context is invalidated after the read. The framework's result is wiped
// before it is released on every return path (sk_release_read).
static int sk_secret(const char *label, const char *reason, unsigned char *out32, unsigned char *public33) {
#ifdef SK_TESTMODE
	sk_test_read_wiped = 0;
#endif
	@autoreleasepool {
		CFMutableDictionaryRef q = sk_query(label, SK_SERVICE, 0);
		CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
		CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
		CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
		LAContext *ctx = nil;
#ifndef SK_TESTMODE
		ctx = [[LAContext alloc] init];
		ctx.touchIDAuthenticationAllowableReuseDuration = 0;
		NSString *r = [NSString stringWithUTF8String:reason];
		ctx.localizedReason = r;
		CFDictionarySetValue(q, kSecUseAuthenticationContext, (const void *)ctx);
		CFDictionarySetValue(q, kSecUseOperationPrompt, (CFStringRef)r);
#endif
		CFTypeRef res = NULL;
		OSStatus st = SecItemCopyMatching(q, &res);
		CFRelease(q);
		if (ctx != nil) { [ctx invalidate]; [ctx release]; }
		int rc = sk_map(st);
		if (rc != SK_OK) { sk_release_read(res); return rc; }
		if (res == NULL || CFGetTypeID(res) != CFDictionaryGetTypeID()) { sk_release_read(res); return SK_ITEM; }
		CFTypeRef data = CFDictionaryGetValue((CFDictionaryRef)res, kSecValueData);
		CFTypeRef generic = CFDictionaryGetValue((CFDictionaryRef)res, kSecAttrGeneric);
		if (data == NULL || CFGetTypeID(data) != CFDataGetTypeID() || CFDataGetLength((CFDataRef)data) != 32 ||
			generic == NULL || CFGetTypeID(generic) != CFDataGetTypeID() || CFDataGetLength((CFDataRef)generic) != 33) { sk_release_read(res); return SK_ITEM; }
		memcpy(out32, CFDataGetBytePtr((CFDataRef)data), 32);
		memcpy(public33, CFDataGetBytePtr((CFDataRef)generic), 33);
		sk_release_read(res);
		return SK_OK;
	}
}
*/
import "C"

import "unsafe"

type darwinStore struct{}

func statusErr(rc C.int) error {
	switch rc {
	case C.SK_OK:
		return nil
	case C.SK_NOT_FOUND:
		return ErrNotFound
	case C.SK_EXISTS:
		return ErrExists
	case C.SK_CANCELED:
		return ErrCanceled
	case C.SK_AUTH:
		return ErrAuth
	case C.SK_BIOMETRY:
		return ErrBiometry
	case C.SK_ENTITLEMENT:
		return ErrEntitlement
	case C.SK_ITEM:
		return ErrItem
	case C.SK_INTERACTION:
		return ErrInteraction
	}
	return ErrStore
}

func (darwinStore) Preflight() error { return statusErr(C.sk_preflight()) }

func (darwinStore) Exists(label string) (bool, error) {
	if !ValidLabel(label) {
		return false, ErrItem
	}
	cl := C.CString(label)
	defer C.free(unsafe.Pointer(cl))
	err := statusErr(C.sk_exists(cl))
	switch err {
	case ErrExists:
		return true, nil
	case ErrNotFound:
		return false, nil
	default:
		return false, err
	}
}

func (darwinStore) Public(label string) ([]byte, error) {
	if !ValidLabel(label) {
		return nil, ErrNotFound
	}
	cl := C.CString(label)
	defer C.free(unsafe.Pointer(cl))
	var buf [33]C.uchar
	if err := statusErr(C.sk_public(cl, &buf[0])); err != nil {
		return nil, err
	}
	return C.GoBytes(unsafe.Pointer(&buf[0]), 33), nil
}

func (darwinStore) Create(label string, secret *[32]byte, public []byte) error {
	if !ValidLabel(label) || len(public) != 33 {
		return ErrItem
	}
	cl := C.CString(label)
	defer C.free(unsafe.Pointer(cl))
	return statusErr(C.sk_create(cl, (*C.uchar)(unsafe.Pointer(&secret[0])), (*C.uchar)(unsafe.Pointer(&public[0])), C.int(len(public))))
}

func (darwinStore) Secret(label, reason string, dst *[32]byte) ([]byte, error) {
	if !ValidLabel(label) || reason == "" {
		return nil, ErrItem
	}
	cl := C.CString(label)
	defer C.free(unsafe.Pointer(cl))
	cr := C.CString(reason)
	defer C.free(unsafe.Pointer(cr))
	var public [33]C.uchar
	if err := statusErr(C.sk_secret(cl, cr, (*C.uchar)(unsafe.Pointer(&dst[0])), &public[0])); err != nil {
		return nil, err
	}
	return C.GoBytes(unsafe.Pointer(&public[0]), 33), nil
}
