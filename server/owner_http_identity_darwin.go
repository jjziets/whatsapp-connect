//go:build darwin && cgo

package main

/*
#include <stdlib.h>
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// Only the exact current-user login Keychain is eligible for this purpose.
static CFDictionaryRef wcOwnerQuery(CFTypeRef login,CFStringRef service,CFStringRef account){
 if(!login)return NULL;
 CFMutableDictionaryRef q=CFDictionaryCreateMutable(kCFAllocatorDefault,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 if(!q)return NULL;
 CFDictionarySetValue(q,kSecClass,kSecClassGenericPassword);
 CFDictionarySetValue(q,kSecAttrService,service);
 CFDictionarySetValue(q,kSecAttrAccount,account);
 CFDictionarySetValue(q,kSecMatchLimit,kSecMatchLimitOne);
 CFDictionarySetValue(q,kSecReturnData,kCFBooleanTrue);
 CFDictionarySetValue(q,kSecAttrSynchronizable,kCFBooleanFalse);
 const void *values[]={login};
 CFArrayRef list=CFArrayCreate(kCFAllocatorDefault,values,1,&kCFTypeArrayCallBacks);
 if(!list){CFRelease(q);return NULL;}
 CFDictionarySetValue(q,kSecMatchSearchList,list);
 CFRelease(list);
 return q;
}
static int wcOwnerSearchCount(CFDictionaryRef q){
 CFTypeRef list=q?CFDictionaryGetValue(q,kSecMatchSearchList):NULL;
 return !list?0:(CFGetTypeID(list)==CFArrayGetTypeID()?(int)CFArrayGetCount((CFArrayRef)list):-1);
}
static int wcOwnerNoSync(CFDictionaryRef q){return q&&CFDictionaryGetValue(q,kSecAttrSynchronizable)==kCFBooleanFalse;}
static int wcOwnerQueryMatches(CFDictionaryRef q,CFStringRef service,CFStringRef account,CFTypeRef login){
 if(!q||!login)return 0;
 CFTypeRef list=CFDictionaryGetValue(q,kSecMatchSearchList);
 return CFDictionaryGetValue(q,kSecClass)==kSecClassGenericPassword
  &&CFEqual(CFDictionaryGetValue(q,kSecAttrService),service)
  &&CFEqual(CFDictionaryGetValue(q,kSecAttrAccount),account)
  &&CFDictionaryGetValue(q,kSecMatchLimit)==kSecMatchLimitOne
  &&CFDictionaryGetValue(q,kSecReturnData)==kCFBooleanTrue
  &&CFDictionaryGetValue(q,kSecAttrSynchronizable)==kCFBooleanFalse
  &&list&&CFGetTypeID(list)==CFArrayGetTypeID()&&CFArrayGetCount((CFArrayRef)list)==1
  &&CFArrayGetValueAtIndex((CFArrayRef)list,0)==login;
}

static OSStatus wcOwnerOpenKeychain(const char *path,CFTypeRef *result){
 SecKeychainRef keychain=NULL;
 OSStatus status=SecKeychainOpen(path,&keychain);
 *result=(CFTypeRef)keychain;
 return status;
}
*/
import "C"

// Manual C-008/C-009, profile C3: exact libc realpath bytes for this NEW purpose
// only. Archive/master/session/Event/callback derivations are untouched.

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"strings"
	"unicode/utf8"
	"unsafe"
)

func ownerHTTPCanonicalDBPath(path string) (string, error) {
	invalid := func() (string, error) { return "", errors.New("owner HTTP database identity unavailable") }
	if strings.IndexByte(path, 0) >= 0 || !utf8.ValidString(path) {
		return invalid()
	}
	input := C.CString(path)
	defer C.free(unsafe.Pointer(input))
	resolved := C.realpath(input, nil)
	if resolved == nil {
		return invalid()
	}
	defer C.free(unsafe.Pointer(resolved))
	// GoString copies exactly the bytes before the terminating NUL. Do not fold
	// case or normalize Unicode; filesystem spelling is decided by libc.
	canonical := C.GoString(resolved)
	if !utf8.ValidString(canonical) {
		return invalid()
	}
	info, err := os.Stat(canonical)
	if err != nil || !info.Mode().IsRegular() {
		return invalid()
	}
	return canonical, nil
}

type ownerHTTPNativeRef struct{ raw C.CFTypeRef }

func (r ownerHTTPNativeRef) close() {
	if r.raw != 0 {
		C.CFRelease(r.raw)
	}
}
func ownerHTTPNativeString(value string) (ownerHTTPNativeRef, error) {
	if strings.IndexByte(value, 0) >= 0 || !utf8.ValidString(value) {
		return ownerHTTPNativeRef{}, errors.New("owner HTTP credential unavailable")
	}
	raw := C.CString(value)
	defer C.free(unsafe.Pointer(raw))
	ref := C.CFStringCreateWithCString(C.kCFAllocatorDefault, raw, C.kCFStringEncodingUTF8)
	if ref == 0 {
		return ownerHTTPNativeRef{}, errors.New("owner HTTP credential unavailable")
	}
	return ownerHTTPNativeRef{raw: C.CFTypeRef(ref)}, nil
}

type ownerHTTPNativeQuery struct{ raw C.CFDictionaryRef }

func (q ownerHTTPNativeQuery) close() {
	if q.raw != 0 {
		C.CFRelease(C.CFTypeRef(q.raw))
	}
}

// The receiving backend can inspect the actual CFDictionary constructed for
// SecItemCopyMatching, rather than a parallel Go description of its policy.
func (q ownerHTTPNativeQuery) matchesPolicy(account string, login ownerHTTPNativeRef) bool {
	service, err := ownerHTTPNativeString(ownerHTTPKeyService)
	if err != nil {
		return false
	}
	defer service.close()
	acct, err := ownerHTTPNativeString(account)
	if err != nil {
		return false
	}
	defer acct.close()
	return C.wcOwnerQueryMatches(q.raw, C.CFStringRef(service.raw), C.CFStringRef(acct.raw), login.raw) != 0
}

type ownerHTTPNativeBackend struct {
	loginPath    func() (string, error)
	open         func(string) (ownerHTTPNativeRef, error)
	copyMatching func(ownerHTTPNativeQuery) ([]byte, error)
}

func ownerHTTPLoginKeychainPath() (string, error) {
	record, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil || record.HomeDir == "" || !strings.HasPrefix(record.HomeDir, "/") || strings.IndexByte(record.HomeDir, 0) >= 0 || !utf8.ValidString(record.HomeDir) {
		return "", errors.New("owner HTTP credential unavailable")
	}
	return record.HomeDir + "/Library/Keychains/login.keychain-db", nil
}

// The backend substitutes only the native open/copy boundary. Both production
// and focused tests receive the same actual CoreFoundation query dictionary.
func readOwnerHTTPKeyWith(account string, backend ownerHTTPNativeBackend) ([]byte, error) {
	unavailable := func() ([]byte, error) { return nil, errors.New("owner HTTP credential unavailable") }
	path, err := backend.loginPath()
	if err != nil {
		return unavailable()
	}
	login, err := backend.open(path)
	if err != nil || login.raw == 0 {
		return unavailable()
	}
	defer login.close()
	service, err := ownerHTTPNativeString(ownerHTTPKeyService)
	if err != nil {
		return unavailable()
	}
	defer service.close()
	acct, err := ownerHTTPNativeString(account)
	if err != nil {
		return unavailable()
	}
	defer acct.close()
	query := ownerHTTPNativeQuery{raw: C.wcOwnerQuery(login.raw, C.CFStringRef(service.raw), C.CFStringRef(acct.raw))}
	if query.raw == 0 {
		return unavailable()
	}
	defer query.close()
	if !query.matchesPolicy(account, login) {
		return unavailable()
	}
	data, err := backend.copyMatching(query)
	if err != nil {
		return unavailable()
	}
	return data, nil
}
func readOwnerHTTPKey(account string) ([]byte, error) {
	return readOwnerHTTPKeyWith(account, ownerHTTPNativeBackend{
		loginPath: ownerHTTPLoginKeychainPath,
		open: func(path string) (ownerHTTPNativeRef, error) {
			if strings.IndexByte(path, 0) >= 0 || !utf8.ValidString(path) {
				return ownerHTTPNativeRef{}, errors.New("owner HTTP credential unavailable")
			}
			input := C.CString(path)
			defer C.free(unsafe.Pointer(input))
			var ref C.CFTypeRef
			if status := C.wcOwnerOpenKeychain(input, &ref); status != C.errSecSuccess {
				if ref != 0 {
					C.CFRelease(ref)
				}
				return ownerHTTPNativeRef{}, errors.New("owner HTTP credential unavailable")
			}
			return ownerHTTPNativeRef{raw: ref}, nil
		},
		copyMatching: func(query ownerHTTPNativeQuery) ([]byte, error) {
			count, nonsync := query.scope()
			if count != 1 || !nonsync {
				return nil, errors.New("owner HTTP credential unavailable")
			}
			var result C.CFTypeRef
			status := C.SecItemCopyMatching(query.raw, &result)
			if result != 0 {
				defer C.CFRelease(result)
			}
			if status != C.errSecSuccess || result == 0 || C.CFGetTypeID(result) != C.CFDataGetTypeID() {
				return nil, errors.New("owner HTTP credential unavailable")
			}
			data := C.CFDataRef(result)
			if C.CFDataGetLength(data) != 32 {
				return nil, errors.New("owner HTTP credential unavailable")
			}
			return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), 32), nil
		},
	})
}

func (q ownerHTTPNativeQuery) scope() (int, bool) {
	return int(C.wcOwnerSearchCount(q.raw)), C.wcOwnerNoSync(q.raw) != 0
}
