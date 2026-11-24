//go:build darwin

package eventsecrets

import (
	"context"
	"errors"
	"strings"

	keychain "github.com/keybase/go-keychain"
)

type nativeOps interface {
	AddItem(keychain.Item) error
	QueryItem(keychain.Item) ([]keychain.QueryResult, error)
	DeleteItem(keychain.Item) error
}

type systemOps struct{}

func (systemOps) AddItem(item keychain.Item) error { return keychain.AddItem(item) }
func (systemOps) QueryItem(item keychain.Item) ([]keychain.QueryResult, error) {
	return keychain.QueryItem(item)
}
func (systemOps) DeleteItem(item keychain.Item) error { return keychain.DeleteItem(item) }

type nativeBackend struct{ ops nativeOps }

func newNativeBackend(ops nativeOps) Backend { return &nativeBackend{ops: ops} }

// Native constructs a provider without accessing or mutating Keychain. Individual
// operations require an unlocked Keychain and owner-granted access.
func Native(profileID string) (EventSecretProvider, error) {
	return New(profileID, newNativeBackend(systemOps{}), nil)
}

func (n *nativeBackend) Execute(ctx context.Context, r Request) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if n.ops == nil || r.Service != keychainService || r.Synchronizable {
		return nil, errInvalid
	}
	if r.Operation == "list" {
		// Account is a validated namespace token. Keychain cannot prefix-match
		// accounts, so enumeration itself remains restricted to the fixed service.
		if !(strings.HasSuffix(r.Account, "/") && lowerHex(strings.TrimSuffix(r.Account, "/"), 64)) && !validAccount(r.Account) {
			return nil, errInvalid
		}
	} else if !validAccount(r.Account) {
		return nil, errInvalid
	}
	if r.Operation == "add" {
		item := keychain.NewGenericPassword(keychainService, r.Account, "WhatsApp Connect event callback", append([]byte(nil), r.Data...), "")
		item.SetSynchronizable(keychain.SynchronizableNo)
		item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
		return nil, nativeError(n.ops.AddItem(item))
	}
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(keychainService)
	item.SetSynchronizable(keychain.SynchronizableNo)
	switch r.Operation {
	case "delete":
		item.SetAccount(r.Account)
		return nil, nativeError(n.ops.DeleteItem(item))
	case "get":
		item.SetAccount(r.Account)
		item.SetMatchLimit(keychain.MatchLimitOne)
		item.SetReturnAttributes(true)
		item.SetReturnData(true)
	case "list":
		item.SetMatchLimit(keychain.MatchLimitAll)
		item.SetReturnAttributes(true)
		item.SetReturnData(false)
	default:
		return nil, errInvalid
	}
	rows, err := n.ops.QueryItem(item)
	if err != nil {
		return nil, nativeError(err)
	}
	if r.Operation == "get" && len(rows) == 0 {
		return nil, ErrNotFound
	}
	if r.Operation == "list" && len(rows) > maxMetadataRecords {
		return nil, errors.New("event credential metadata limit exceeded")
	}
	result := make([]Record, 0, len(rows))
	for _, row := range rows {
		record := Record{Service: row.Service, Account: row.Account}
		if r.Operation == "get" {
			record.Data = append([]byte(nil), row.Data...)
		}
		result = append(result, record)
	}
	return result, nil
}

func nativeError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, keychain.ErrorItemNotFound) {
		return ErrNotFound
	}
	if errors.Is(err, keychain.ErrorDuplicateItem) {
		return ErrDuplicate
	}
	return ErrDenied
}
