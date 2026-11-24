//go:build darwin

package securestore

import (
	"errors"
	"fmt"

	keychain "github.com/keybase/go-keychain"
)

type nativeKeyStore struct{}

func NewNativeKeyStore() KeyStore { return nativeKeyStore{} }

func (nativeKeyStore) Get(service, account string) ([]byte, error) {
	key, err := keychain.GetGenericPassword(service, account, "", "")
	if errors.Is(err, keychain.ErrorItemNotFound) || (err == nil && len(key) == 0) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("macOS Keychain access failed: %w", err)
	}
	return key, nil
}

func (nativeKeyStore) Add(service, account string, key []byte) error {
	item := keychain.NewGenericPassword(service, account, "WhatsApp Connect encrypted archive", key, "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
	err := keychain.AddItem(item)
	if errors.Is(err, keychain.ErrorDuplicateItem) {
		return ErrKeyExists
	}
	if err != nil {
		return fmt.Errorf("macOS Keychain could not save archive key: %w", err)
	}
	return nil
}
