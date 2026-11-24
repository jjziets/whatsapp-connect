//go:build darwin

package eventsecrets

import (
	"context"
	"errors"
	keychain "github.com/keybase/go-keychain"
	"reflect"
	"testing"
)

// These are the exact go-keychain syscall entrypoints, replaced before any call.
type fakeNativeOps struct {
	added, queried, deleted []keychain.Item
	result                  []keychain.QueryResult
	err                     error
}

func (f *fakeNativeOps) AddItem(i keychain.Item) error { f.added = append(f.added, i); return f.err }
func (f *fakeNativeOps) QueryItem(i keychain.Item) ([]keychain.QueryResult, error) {
	f.queried = append(f.queried, i)
	return f.result, f.err
}
func (f *fakeNativeOps) DeleteItem(i keychain.Item) error {
	f.deleted = append(f.deleted, i)
	return f.err
}

func TestNativeRequestsUseExactKeychainAttributes(t *testing.T) {
	ops := &fakeNativeOps{}
	b := newNativeBackend(ops)
	ctx := context.Background()
	account := profileA + "/" + subscription + "/0102030405060708090a0b0c0d0e0f10"
	key := make([]byte, 32)
	_, e := b.Execute(ctx, Request{Operation: "add", Service: service, Account: account, Data: key, Accessible: "when-unlocked-this-device-only"})
	if e != nil {
		t.Fatal(e)
	}
	expected := keychain.NewGenericPassword(service, account, "WhatsApp Connect event callback", key, "")
	expected.SetSynchronizable(keychain.SynchronizableNo)
	expected.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
	if len(ops.added) != 1 || !reflect.DeepEqual(ops.added[0], expected) {
		t.Fatal("native add attributes differ")
	}
	ops.result = []keychain.QueryResult{{Service: service, Account: account, Data: key}}
	if _, e = b.Execute(ctx, Request{Operation: "get", Service: service, Account: account, ReturnData: true}); e != nil {
		t.Fatal(e)
	}
	q := keychain.NewItem()
	q.SetSecClass(keychain.SecClassGenericPassword)
	q.SetService(service)
	q.SetAccount(account)
	q.SetSynchronizable(keychain.SynchronizableNo)
	q.SetMatchLimit(keychain.MatchLimitOne)
	q.SetReturnAttributes(true)
	q.SetReturnData(true)
	if len(ops.queried) != 1 || !reflect.DeepEqual(ops.queried[0], q) {
		t.Fatal("native exact lookup attributes differ")
	}
	if _, e = b.Execute(ctx, Request{Operation: "delete", Service: service, Account: account}); e != nil {
		t.Fatal(e)
	}
	d := keychain.NewItem()
	d.SetSecClass(keychain.SecClassGenericPassword)
	d.SetService(service)
	d.SetAccount(account)
	d.SetSynchronizable(keychain.SynchronizableNo)
	if len(ops.deleted) != 1 || !reflect.DeepEqual(ops.deleted[0], d) {
		t.Fatal("native delete broadens scope")
	}
	if _, e = b.Execute(ctx, Request{Operation: "list", Service: service, Account: profileA + "/"}); e != nil {
		t.Fatal(e)
	}
	l := keychain.NewItem()
	l.SetSecClass(keychain.SecClassGenericPassword)
	l.SetService(service)
	l.SetSynchronizable(keychain.SynchronizableNo)
	l.SetMatchLimit(keychain.MatchLimitAll)
	l.SetReturnAttributes(true)
	l.SetReturnData(false)
	if len(ops.queried) != 2 || !reflect.DeepEqual(ops.queried[1], l) {
		t.Fatal("native enumeration requested key bytes or broad service")
	}
}

func TestNativeErrorTranslationAndEmptyLookup(t *testing.T) {
	for _, tc := range []struct{ native, errorWant error }{{keychain.ErrorDuplicateItem, ErrDuplicate}, {keychain.ErrorItemNotFound, ErrNotFound}, {keychain.Error(-25293), ErrDenied}} {
		ops := &fakeNativeOps{err: tc.native}
		b := newNativeBackend(ops)
		for _, op := range []string{"get", "add", "delete", "list"} {
			if _, e := b.Execute(context.Background(), Request{Operation: op, Service: service, Account: profileA + "/" + subscription + "/0102030405060708090a0b0c0d0e0f10"}); !errors.Is(e, tc.errorWant) {
				t.Fatalf("%s error translation", op)
			}
		}
	}
	b := newNativeBackend(&fakeNativeOps{})
	if _, e := b.Execute(context.Background(), Request{Operation: "get", Service: service, Account: profileA + "/" + subscription + "/0102030405060708090a0b0c0d0e0f10"}); !errors.Is(e, ErrNotFound) {
		t.Fatal("go-keychain empty success must be missing")
	}
}
