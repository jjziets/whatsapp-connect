//go:build !darwin || !cgo

package main

import "errors"

// Manual C-008/C-009: never substitute a different account derivation.
func ownerHTTPCanonicalDBPath(string) (string, error) {
	return "", errors.New("owner HTTP native identity unsupported on this platform")
}

// Purpose-specific native reader never falls back to another Keychain/store.
func readOwnerHTTPKey(string) ([]byte, error) {
	return nil, errors.New("owner HTTP native credential unsupported on this platform")
}
