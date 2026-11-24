// Package eventsecrets stores versioned callback credentials separately from
// archive keys. References are safe to persist; credential bytes are not.
package eventsecrets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
)

const keychainService = "com.github.jjziets.whatsapp-connect.events"
const maxMetadataRecords = 4096

var (
	ErrNotFound    = errors.New("event credential not found")
	ErrDuplicate   = errors.New("event credential version already exists")
	ErrDenied      = errors.New("event credential access unavailable")
	ErrUnsupported = errors.New("native event credentials unsupported on this platform")
	errInvalid     = errors.New("invalid event credential request")
	errMalformed   = errors.New("invalid stored event credential")
)

// EventSecretProvider never changes archive keys or overwrites a key version.
type EventSecretProvider interface {
	Get(context.Context, string) ([]byte, error)
	PutVersion(context.Context, string, []byte) (string, error)
	Delete(context.Context, string) error
	ListRefs(context.Context) ([]string, error)
}

// Backend is the injectable OS boundary. Only Native should construct the
// production backend. Callers of New supply a trusted test/backend instance.
type Backend interface {
	Execute(context.Context, Request) ([]Record, error)
}

// Request describes a fixed-namespace OS operation. Account is an exact account
// except for list, where it is the current profile prefix for result filtering.
type Request struct {
	Operation      string
	Service        string
	Account        string
	Data           []byte
	Accessible     string
	Synchronizable bool
	ReturnData     bool
}

type Record struct {
	Service string
	Account string
	Data    []byte
}

type providerStore struct {
	profile  string
	backend  Backend
	random   io.Reader
	randomMu sync.Mutex
}

// New accepts the lowercase SHA256 of the canonical archive path, computed by
// the owner integration. It does not accept arbitrary service/account names.
func New(profileID string, backend Backend, random io.Reader) (EventSecretProvider, error) {
	if !lowerHex(profileID, 64) || backend == nil {
		return nil, errInvalid
	}
	if random == nil {
		random = rand.Reader
	}
	return &providerStore{profile: profileID, backend: backend, random: random}, nil
}

func lowerHex(s string, size int) bool {
	if len(s) != size {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validSubscription(id string) bool {
	return strings.HasPrefix(id, "sub_") && lowerHex(strings.TrimPrefix(id, "sub_"), 64)
}

func validAccount(account string) bool {
	parts := strings.Split(account, "/")
	return len(parts) == 3 && lowerHex(parts[0], 64) && validSubscription(parts[1]) && lowerHex(parts[2], 32)
}

func (p *providerStore) account(ref string) (string, error) {
	if !strings.HasPrefix(ref, "evk1/") {
		return "", errInvalid
	}
	account := strings.TrimPrefix(ref, "evk1/")
	if !validAccount(account) || !strings.HasPrefix(account, p.profile+"/") {
		return "", errInvalid
	}
	return account, nil
}

func (p *providerStore) Get(ctx context.Context, ref string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	account, err := p.account(ref)
	if err != nil {
		return nil, err
	}
	rows, err := p.backend.Execute(ctx, Request{Operation: "get", Service: keychainService, Account: account, ReturnData: true})
	if err != nil {
		return nil, safeError(err)
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	if len(rows) != 1 || rows[0].Service != keychainService || rows[0].Account != account || len(rows[0].Data) < 24 || len(rows[0].Data) > 64 {
		return nil, errMalformed
	}
	return append([]byte(nil), rows[0].Data...), nil
}

func (p *providerStore) PutVersion(ctx context.Context, subID string, key []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !validSubscription(subID) || len(key) < 24 || len(key) > 64 {
		return "", errInvalid
	}
	// Snapshot caller memory before passing another private buffer to the backend.
	keyCopy := append([]byte(nil), key...)
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		var version [16]byte
		p.randomMu.Lock()
		_, err := io.ReadFull(p.random, version[:])
		p.randomMu.Unlock()
		if err != nil {
			return "", errors.New("event credential version generation failed")
		}
		account := p.profile + "/" + subID + "/" + hex.EncodeToString(version[:])
		_, err = p.backend.Execute(ctx, Request{Operation: "add", Service: keychainService, Account: account, Data: append([]byte(nil), keyCopy...), Accessible: "when-unlocked-this-device-only"})
		if errors.Is(err, ErrDuplicate) {
			continue
		}
		if err != nil {
			return "", safeError(err)
		}
		return "evk1/" + account, nil
	}
	return "", ErrDuplicate
}

func (p *providerStore) Delete(ctx context.Context, ref string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	account, err := p.account(ref)
	if err != nil {
		return err
	}
	_, err = p.backend.Execute(ctx, Request{Operation: "delete", Service: keychainService, Account: account})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return safeError(err)
}

// ListRefs requests metadata only. The native Keychain query is service-scoped:
// its allocation occurs before this cap because OS account-prefix queries are
// unavailable. No cleanup or deletion is performed here.
func (p *providerStore) ListRefs(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := p.backend.Execute(ctx, Request{Operation: "list", Service: keychainService, Account: p.profile + "/"})
	if errors.Is(err, ErrNotFound) {
		return []string{}, nil
	}
	if err != nil {
		return nil, safeError(err)
	}
	if len(rows) > maxMetadataRecords {
		return nil, errors.New("event credential metadata limit exceeded")
	}
	seen := make(map[string]bool)
	refs := make([]string, 0)
	for _, row := range rows {
		if row.Service != keychainService || !strings.HasPrefix(row.Account, p.profile+"/") || !validAccount(row.Account) {
			continue
		}
		ref := "evk1/" + row.Account
		if !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	return refs, nil
}

// Never propagate backend diagnostics that might include credentials.
func safeError(err error) error {
	if err == nil {
		return nil
	}
	for _, category := range []error{ErrNotFound, ErrDuplicate, ErrDenied, ErrUnsupported, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, category) {
			return category
		}
	}
	return ErrDenied
}
