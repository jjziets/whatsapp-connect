//go:build darwin && libsqlite3 && keychain_integration

package securestore

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	keychain "github.com/keybase/go-keychain"
)

// Explicit native lane; the item is synthetic, unique, and removed by this test.
func TestNativeKeychainRoundTrip(t *testing.T) {
	service := fmt.Sprintf("com.github.jjziets.whatsapp-connect.test.%d.%d", os.Getpid(), time.Now().UnixNano())
	account := "synthetic-profile"
	keys := NewNativeKeyStore()
	defer func() {
		err := keychain.DeleteGenericPasswordItem(service, account)
		if err != nil && !errors.Is(err, keychain.ErrorItemNotFound) {
			t.Error("synthetic Keychain cleanup failed:", err)
		}
		if _, err := keys.Get(service, account); !errors.Is(err, ErrKeyNotFound) {
			t.Error("synthetic Keychain item remains after cleanup")
		}
	}()
	if _, err := keys.Get(service, account); !errors.Is(err, ErrKeyNotFound) {
		t.Fatal("unique test item unexpectedly exists:", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := keys.Add(service, account, key); err != nil {
		t.Fatal(err)
	}
	got, err := keys.Get(service, account)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("native Keychain round trip failed")
	}
	if err := keys.Add(service, account, key); !errors.Is(err, ErrKeyExists) {
		t.Fatal("duplicate native item was not rejected")
	}
}
