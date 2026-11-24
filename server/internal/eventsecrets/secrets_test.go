package eventsecrets

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

const profileA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const profileB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const subscription = "sub_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const service = "com.github.jjziets.whatsapp-connect.events"

// fakeOS models OS duplicate/not-found/denied behavior. It implements no provider
// validation, reference parsing, generation, retry, or namespace decisions.
type fakeOS struct {
	items      map[string][]byte
	calls      []Request
	fail       error
	duplicates int
	listings   []Record
}

func (f *fakeOS) Execute(_ context.Context, r Request) ([]Record, error) {
	f.calls = append(f.calls, r)
	if f.fail != nil {
		return nil, f.fail
	}
	id := r.Service + "|" + r.Account
	switch r.Operation {
	case "add":
		if f.duplicates > 0 {
			f.duplicates--
			return nil, ErrDuplicate
		}
		if _, ok := f.items[id]; ok {
			return nil, ErrDuplicate
		}
		f.items[id] = append([]byte(nil), r.Data...)
		return nil, nil
	case "get":
		v, ok := f.items[id]
		if !ok {
			return nil, ErrNotFound
		}
		return []Record{{Service: r.Service, Account: r.Account, Data: v}}, nil
	case "delete":
		if _, ok := f.items[id]; !ok {
			return nil, ErrNotFound
		}
		delete(f.items, id)
		return nil, nil
	case "list":
		if f.listings != nil {
			return f.listings, nil
		}
		var out []Record
		for k := range f.items {
			p := strings.SplitN(k, "|", 2)
			if p[0] == r.Service {
				out = append(out, Record{Service: p[0], Account: p[1]})
			}
		}
		return out, nil
	}
	return nil, errors.New("invalid OS operation")
}
func provider(t *testing.T, f *fakeOS, random io.Reader) EventSecretProvider {
	t.Helper()
	p, e := New(profileA, f, random)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func newOS() *fakeOS { return &fakeOS{items: map[string][]byte{}} }
func entropy() *bytes.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}, 10))
}

func TestVersionLifecyclePolicyAndDefensiveCopies(t *testing.T) {
	f := newOS()
	p := provider(t, f, entropy())
	ctx := context.Background()
	key := bytes.Repeat([]byte{42}, 32)
	ref, e := p.PutVersion(ctx, subscription, key)
	if e != nil {
		t.Fatal(e)
	}
	if ref == "" || strings.Contains(ref, string(key)) {
		t.Fatal("nonopaque reference")
	}
	r := f.calls[0]
	if r.Operation != "add" || r.Service != service || r.Account != profileA+"/"+subscription+"/0102030405060708090a0b0c0d0e0f10" || r.Accessible != "when-unlocked-this-device-only" || r.Synchronizable || !bytes.Equal(r.Data, key) {
		t.Fatal("wrong native storage request")
	}
	key[0] = 0
	got, e := p.Get(ctx, ref)
	if e != nil || got[0] != 42 {
		t.Fatal("input alias or lookup failure")
	}
	got[0] = 0
	again, e := p.Get(ctx, ref)
	if e != nil || again[0] != 42 {
		t.Fatal("output aliases OS storage")
	}
	refs, e := p.ListRefs(ctx)
	if e != nil || len(refs) != 1 || refs[0] != ref {
		t.Fatal("metadata listing")
	}
	r = f.calls[len(f.calls)-1]
	if r.Operation != "list" || r.Service != service || r.Account != profileA+"/" || r.ReturnData {
		t.Fatal("listing requested credentials or foreign namespace")
	}
	if e = p.Delete(ctx, ref); e != nil {
		t.Fatal(e)
	}
	if e = p.Delete(ctx, ref); e != nil {
		t.Fatal("missing delete must be idempotent")
	}
	if _, e = p.Get(ctx, ref); !errors.Is(e, ErrNotFound) {
		t.Fatal("deleted key readable")
	}
}

func TestInvalidInputsNeverReachOS(t *testing.T) {
	f := newOS()
	p := provider(t, f, entropy())
	ctx := context.Background()
	for _, n := range []int{0, 23, 65} {
		if _, e := p.PutVersion(ctx, subscription, make([]byte, n)); e == nil {
			t.Fatalf("length %d accepted", n)
		}
	}
	for _, id := range []string{"", "../master", "sub_bad", subscription + "/extra"} {
		if _, e := p.PutVersion(ctx, id, make([]byte, 32)); e == nil {
			t.Fatal("bad subscription")
		}
	}
	for _, ref := range []string{"", "archive:" + profileA, "com.github.jjziets.whatsapp-connect.archive/" + profileA, profileB + "/" + subscription + "/0102030405060708090a0b0c0d0e0f10", "evk1/" + profileB + "/" + subscription + "/0102030405060708090a0b0c0d0e0f10", "evk1/" + profileA + "/../master/0102030405060708090a0b0c0d0e0f10"} {
		if _, e := p.Get(ctx, ref); e == nil {
			t.Fatal("bad ref accepted")
		}
		if e := p.Delete(ctx, ref); e == nil {
			t.Fatal("bad delete accepted")
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("invalid input reached OS")
	}
	for _, id := range []string{"", "relative", strings.ToUpper(profileA), profileA + "/"} {
		if _, e := New(id, f, entropy()); e == nil {
			t.Fatal("noncanonical profile accepted")
		}
	}
}

func TestBoundsFreshVersionsCollisionAndEntropyFailure(t *testing.T) {
	for _, n := range []int{24, 64} {
		f := newOS()
		p := provider(t, f, entropy())
		if _, e := p.PutVersion(context.Background(), subscription, make([]byte, n)); e != nil {
			t.Fatal(e)
		}
	}
	f := newOS()
	p := provider(t, f, entropy())
	a, e := p.PutVersion(context.Background(), subscription, make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	b, e := p.PutVersion(context.Background(), subscription, bytes.Repeat([]byte{1}, 32))
	if e != nil || a == b || len(f.items) != 2 {
		t.Fatal("rotation overwrote old version")
	}
	f = newOS()
	f.duplicates = 1
	p = provider(t, f, entropy())
	if _, e = p.PutVersion(context.Background(), subscription, make([]byte, 32)); e != nil || len(f.calls) != 2 || f.calls[0].Account == f.calls[1].Account {
		t.Fatal("duplicate retry must generate new version")
	}
	f = newOS()
	f.duplicates = 100
	p = provider(t, f, entropy())
	if _, e = p.PutVersion(context.Background(), subscription, make([]byte, 32)); e == nil || len(f.calls) != 4 {
		t.Fatal("collision retry bound must be four total adds")
	}
	f = newOS()
	p = provider(t, f, bytes.NewReader(nil))
	if _, e = p.PutVersion(context.Background(), subscription, make([]byte, 32)); e == nil || len(f.calls) != 0 {
		t.Fatal("entropy failure reached OS")
	}
}

func TestLookupAndDeleteFailClosed(t *testing.T) {
	f := newOS()
	p := provider(t, f, entropy())
	ctx := context.Background()
	ref, e := p.PutVersion(ctx, subscription, make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	f.fail = ErrDenied
	before := len(f.calls)
	if _, e = p.Get(ctx, ref); !errors.Is(e, ErrDenied) {
		t.Fatal("denial lost")
	}
	if e = p.Delete(ctx, ref); !errors.Is(e, ErrDenied) {
		t.Fatal("delete denial swallowed")
	}
	if len(f.calls) != before+2 {
		t.Fatal("denied access made replacement calls")
	}
	f.fail = nil
	for k := range f.items {
		f.items[k] = make([]byte, 23)
	}
	before = len(f.calls)
	if _, e = p.Get(ctx, ref); e == nil || len(f.calls) != before+1 {
		t.Fatal("malformed stored key replaced or accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	before = len(f.calls)
	if _, e = p.Get(canceled, ref); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	if len(f.calls) != before {
		t.Fatal("canceled lookup reached OS")
	}
}

func TestListRefsBoundsAndNamespaceSafeCleanup(t *testing.T) {
	f := newOS()
	p := provider(t, f, entropy())
	ctx := context.Background()
	ref, e := p.PutVersion(ctx, subscription, make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	own := f.calls[0].Account
	f.listings = []Record{{Service: service, Account: own}, {Service: service, Account: profileB + "/" + subscription + "/0102030405060708090a0b0c0d0e0f10"}, {Service: "com.github.jjziets.whatsapp-connect.archive", Account: profileA}, {Service: service, Account: profileA + "/../../master"}}
	refs, e := p.ListRefs(ctx)
	if e != nil || len(refs) != 1 || refs[0] != ref {
		t.Fatal("foreign/malformed record leaked")
	}
	for _, r := range refs {
		if e = p.Delete(ctx, r); e != nil {
			t.Fatal(e)
		}
	}
	// The OS cannot prefix-filter accounts: service-scoped metadata enumeration
	// is bounded and provider filters profile before returning cleanup refs.
	f.listings = make([]Record, 4097)
	if _, e = p.ListRefs(ctx); e == nil {
		t.Fatal("unbounded namespace enumeration")
	}
	f.fail = ErrDenied
	if _, e = p.ListRefs(ctx); !errors.Is(e, ErrDenied) {
		t.Fatal("list denial swallowed")
	}
}
