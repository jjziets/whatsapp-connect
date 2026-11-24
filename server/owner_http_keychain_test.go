//go:build darwin && cgo && libsqlite3

package main

import (
	"bytes"
	"errors"
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"
)

// OWNER-HTTP-ADV-001: the actual CFDictionary arrives at the fake native copy
// boundary. No SecKeychainOpen/CopyMatching or real search-list change occurs.
func TestOwnerHTTPNativeLoginQuery(t *testing.T) {
	account := strings.Repeat("a", 64)
	keyA, keyB := bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x42}, 32)
	path := "/Users/OS-current-user/Library/Keychains/login.keychain-db"
	for _, failure := range []string{"", "item-missing", "open-missing", "denied", "locked"} {
		t.Run("login-"+failure, func(t *testing.T) {
			opens, copies := 0, 0
			var login ownerHTTPNativeRef
			backend := ownerHTTPNativeBackend{
				loginPath: func() (string, error) { return path, nil },
				open: func(got string) (ownerHTTPNativeRef, error) {
					opens++
					if got != path {
						t.Fatal("wrong OS-user login path")
					}
					if failure != "" && failure != "item-missing" {
						return ownerHTTPNativeRef{}, errors.New("CANARY_NATIVE_ERROR_" + failure)
					}
					var err error
					login, err = ownerHTTPNativeString("synthetic-login-A")
					return login, err
				},
				copyMatching: func(query ownerHTTPNativeQuery) ([]byte, error) {
					copies++
					count, nonsync := query.scope()
					if count != 1 || !nonsync {
						t.Errorf("actual native CFDictionary scope: keychains=%d nonsynchronizable=%v", count, nonsync)
					}
					if query.matchesPolicy(account, login) {
						if failure == "item-missing" {
							return nil, errors.New("CANARY_NATIVE_ERROR_missing_item")
						}
						return keyA, nil
					}
					return keyB, nil
				},
			}
			got, err := readOwnerHTTPKeyWith(account, backend)
			if failure != "" {
				wantCopies := 0
				if failure == "item-missing" {
					wantCopies = 1
				}
				if err == nil || len(got) != 0 || copies != wantCopies || opens != 1 {
					t.Fatalf("login unavailable fell through to alternate B: err=%v opens=%d copies=%d bytes=%d", err, opens, copies, len(got))
				}
				if strings.Contains(err.Error(), "CANARY") {
					t.Fatal("native error exposed")
				}
			} else if err != nil || !bytes.Equal(got, keyA) || opens != 1 || copies != 1 {
				t.Fatalf("alternate B preceded login A: correct_key=%v err=%v opens=%d copies=%d", bytes.Equal(got, keyA), err, opens, copies)
			}
		})
	}
	// Native path must ignore ambient HOME and match Swift's getuid/pwd home.
	record, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", "/synthetic/attacker-home")
	pathGot, err := ownerHTTPLoginKeychainPath()
	if err != nil || pathGot != record.HomeDir+"/Library/Keychains/login.keychain-db" {
		t.Fatalf("native login selected ambient HOME: %q %v", pathGot, err)
	}
}
