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

enum { SK_OK = 0, SK_NOT_FOUND = 1, SK_EXISTS = 2, SK_CANCELED = 3, SK_AUTH = 4, SK_BIOMETRY = 5, SK_ENTITLEMENT = 6, SK_ITEM = 7, SK_STORE = 8 };

static int sk_map(OSStatus st) {
	switch (st) {
	case errSecSuccess: return SK_OK;
	case errSecItemNotFound: return SK_NOT_FOUND;
	case errSecDuplicateItem: return SK_EXISTS;
	case errSecUserCanceled: return SK_CANCELED;
	case errSecAuthFailed: return SK_AUTH;
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

static CFMutableDictionaryRef sk_query(const char *label, int add) {
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFStringRef svc = CFStringCreateWithCString(NULL, SK_SERVICE, kCFStringEncodingUTF8);
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

#ifdef SK_TESTMODE
int sk_delete(const char *label) {
	if (sk_test_kc == NULL) return SK_STORE;
	CFMutableDictionaryRef q = sk_query(label, 0);
	OSStatus st = SecItemDelete(q);
	CFRelease(q);
	return sk_map(st);
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

// sk_public returns the stored compressed public key (kSecAttrGeneric). It
// never shows a prompt: the release query carries a context that forbids
// interaction.
static int sk_public(const char *label, unsigned char *out, int cap, int *outlen) {
	@autoreleasepool {
		CFMutableDictionaryRef q = sk_query(label, 0);
		CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
		CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
		LAContext *ctx = nil;
#ifndef SK_TESTMODE
		ctx = [[LAContext alloc] init];
		ctx.interactionNotAllowed = YES;
		CFDictionarySetValue(q, kSecUseAuthenticationContext, (const void *)ctx);
#endif
		CFTypeRef res = NULL;
		OSStatus st = SecItemCopyMatching(q, &res);
		CFRelease(q);
		if (ctx != nil) { [ctx invalidate]; [ctx release]; }
		int rc = sk_map(st);
		if (rc != SK_OK) { if (res != NULL) CFRelease(res); return rc; }
		if (res == NULL || CFGetTypeID(res) != CFDictionaryGetTypeID()) { if (res != NULL) CFRelease(res); return SK_ITEM; }
		CFTypeRef g = CFDictionaryGetValue((CFDictionaryRef)res, kSecAttrGeneric);
		if (g == NULL || CFGetTypeID(g) != CFDataGetTypeID() || CFDataGetLength((CFDataRef)g) > cap) { CFRelease(res); return SK_ITEM; }
		*outlen = (int)CFDataGetLength((CFDataRef)g);
		memcpy(out, CFDataGetBytePtr((CFDataRef)g), *outlen);
		CFRelease(res);
		return SK_OK;
	}
}

// sk_create adds the item. Release: biometryCurrentSet, when-passcode-set,
// this device only, not synchronizable.
static int sk_create(const char *label, const unsigned char *secret, const unsigned char *pub, int publen) {
	@autoreleasepool {
		CFMutableDictionaryRef q = sk_query(label, 1);
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
		return sk_map(st);
	}
}

// sk_secret reads the secret into out32. Release: a new LAContext per call
// with no reuse window, so every read is its own Touch ID evaluation; the
// context is invalidated after the read.
static int sk_secret(const char *label, const char *reason, unsigned char *out32) {
	@autoreleasepool {
		CFMutableDictionaryRef q = sk_query(label, 0);
		CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
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
		if (rc != SK_OK) { if (res != NULL) CFRelease(res); return rc; }
		if (res == NULL || CFGetTypeID(res) != CFDataGetTypeID() || CFDataGetLength((CFDataRef)res) != 32) { if (res != NULL) CFRelease(res); return SK_ITEM; }
		memcpy(out32, CFDataGetBytePtr((CFDataRef)res), 32);
		CFRelease(res);
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
	}
	return ErrStore
}

func (darwinStore) Preflight() error { return statusErr(C.sk_preflight()) }

func (darwinStore) Public(label string) ([]byte, error) {
	if !ValidLabel(label) {
		return nil, ErrNotFound
	}
	cl := C.CString(label)
	defer C.free(unsafe.Pointer(cl))
	var buf [65]C.uchar
	var n C.int
	if err := statusErr(C.sk_public(cl, &buf[0], C.int(len(buf)), &n)); err != nil {
		return nil, err
	}
	return C.GoBytes(unsafe.Pointer(&buf[0]), n), nil
}

func (darwinStore) Create(label string, secret *[32]byte, public []byte) error {
	if !ValidLabel(label) || len(public) == 0 || len(public) > 65 {
		return ErrItem
	}
	cl := C.CString(label)
	defer C.free(unsafe.Pointer(cl))
	return statusErr(C.sk_create(cl, (*C.uchar)(unsafe.Pointer(&secret[0])), (*C.uchar)(unsafe.Pointer(&public[0])), C.int(len(public))))
}

func (darwinStore) Secret(label, reason string, dst *[32]byte) error {
	if !ValidLabel(label) || reason == "" {
		return ErrItem
	}
	cl := C.CString(label)
	defer C.free(unsafe.Pointer(cl))
	cr := C.CString(reason)
	defer C.free(unsafe.Pointer(cr))
	return statusErr(C.sk_secret(cl, cr, (*C.uchar)(unsafe.Pointer(&dst[0]))))
}
