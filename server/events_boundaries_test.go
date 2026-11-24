//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hansen/whatsapp-mcp/internal/eventdelivery"
	"github.com/hansen/whatsapp-mcp/internal/eventsecrets"
	"github.com/hansen/whatsapp-mcp/internal/securestore"
	"github.com/rs/zerolog"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

type evArchiveKeys struct{}

func (evArchiveKeys) Get(string, string) ([]byte, error) { return bytes.Repeat([]byte{0x42}, 32), nil }
func (evArchiveKeys) Add(string, string, []byte) error {
	return errors.New("unexpected replacement archive key")
}
func evOwnedApp(t *testing.T) (*App, func(), string) {
	t.Helper()
	w, path := archiveFixture(t)
	dir := filepath.Dir(path)
	if err := w.drainAndClose(); err != nil {
		t.Fatal(err)
	}
	if path != dbPath(dir) {
		if err := os.Rename(path, dbPath(dir)); err != nil {
			t.Fatal(err)
		}
	}
	app, cleanup, err := openForServeWith(context.Background(), dir, zerolog.Nop(), ServeDependencies{ArchiveKeys: evArchiveKeys{}, Connect: func(context.Context, *WA) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return app, cleanup, dir
}
func evCompose(t *testing.T) (*evHarness, *EventRuntime, *httptest.Server, string) {
	t.Helper()
	app, cleanup, dir := evOwnedApp(t)
	clock := &evClock{t: t0.Add(24 * time.Hour)}
	canonicalPath, err := filepath.EvalSymlinks(dbPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	profileHash := sha256.Sum256([]byte(canonicalPath))
	profile := fmt.Sprintf("%x", profileHash)
	keys := &evKeys{profile: profile, keys: map[string][]byte{}}
	sender := &evSender{store: app.store, receipt: eventdelivery.Receipt{StatusCode: 200}, committed: true}
	h := &evHarness{w: app.wa, keys: keys, sender: sender, clock: clock}
	h.cfg = EventConfig{Store: app.store, WA: app.wa, ProfileID: profile, OwnerID: "composition-owner-" + profile[:8], Owner: true, Enabled: true, Transport: "http", Secrets: keys, Sender: sender, Now: clock.Now, Clipboard: func(token string) error { h.token = token; return nil }}
	var out, stderr bytes.Buffer
	if err := dispatchEventsAccess(context.Background(), []string{"init"}, app, h.cfg, &out, &stderr); err != nil {
		t.Fatal(err)
	}
	if err := dispatchEventsAccess(context.Background(), []string{"copy"}, app, h.cfg, &out, &stderr); err != nil {
		t.Fatal(err)
	}
	runtime, err := composeEventServe(context.Background(), app, cleanup, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.s = runtime.Service
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	httpServer := httptest.NewServer(runtime.Handler)
	t.Cleanup(httpServer.Close)
	return h, runtime, httpServer, dir
}
func evSession(t *testing.T, url, token string) string {
	t.Helper()
	out, id, status := evRPC(t, url, token, "", "initialize", 1, map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "composition-test", "version": "1"}})
	if status != 200 || out["error"] != nil || id == "" {
		t.Fatalf("initialize %v %d", out, status)
	}
	evRPC(t, url, token, id, "notifications/initialized", nil, map[string]any{})
	return id
}
func evAwait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("boundary gate not reached")
	}
}
func evWait(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatal("timed out: " + what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// EDEF-01: the same composition seam as runServe must earn authority from the
// actual profile lock result. This test never supplies a forged lock token.
func TestEventsProductionCompositionCLIAndSessionIsolation(t *testing.T) {
	ctx := context.Background()
	h, _, srv, dir := evCompose(t)
	session := evSession(t, srv.URL, h.token)
	q, _, _ := evRPC(t, srv.URL, h.token, session, "events/subscribe", 2, evReq(alice.String(), ""))
	if q["error"] != nil {
		t.Fatal(q)
	}
	id := q["result"].(map[string]any)["id"].(string)
	evLive(h, alice, alice, "composition-worker", h.clock.Now())
	evWait(t, "production composition worker", func() bool { return len(h.sender.requests()) == 1 })
	for _, method := range []string{"events/list", "events/subscribe", "events/unsubscribe"} {
		_, _, status := evRPC(t, srv.URL, "", session, method, 3, map[string]any{})
		if status != 401 {
			t.Fatalf("custom method %s accepted missing auth", method)
		}
	}
	tools, _, _ := evRPC(t, srv.URL, h.token, session, "tools/list", 4, map[string]any{})
	list := tools["result"].(map[string]any)["tools"].([]any)
	seen := map[string]bool{}
	for _, v := range list {
		m := v.(map[string]any)
		name, _ := m["name"].(string)
		if strings.Contains(name, "message_monitor") {
			seen[name] = true
			ann, _ := m["annotations"].(map[string]any)
			if name != "list_message_monitors" && ann["readOnlyHint"] != false {
				t.Fatalf("mutation tool marked read-only: %v", m)
			}
		}
	}
	for _, name := range []string{"list_message_monitors", "pause_message_monitor", "resume_message_monitor", "stop_message_monitor"} {
		if !seen[name] {
			t.Fatal("missing control " + name)
		}
		args := map[string]any{}
		if name != "list_message_monitors" {
			args["id"] = id
		}
		q, _, _ = evRPC(t, srv.URL, h.token, session, "tools/call", 5, map[string]any{"name": name, "arguments": args})
		if q["error"] != nil || q["result"].(map[string]any)["isError"] == true {
			t.Fatalf("control failed %s: %v", name, q)
		}
	}
	// The second real lock attempt must be read-only and cannot advertise controls.
	reader, readerCleanup, err := openForServeWith(ctx, dir, zerolog.Nop(), ServeDependencies{ArchiveKeys: evArchiveKeys{}, Connect: func(context.Context, *WA) error { t.Fatal("reader attempted connection"); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer readerCleanup()
	if reader.wa != nil {
		t.Fatal("second opener gained owner")
	}
	for _, transport := range []string{"http", "stdio"} {
		app := reader
		if transport == "stdio" {
			app = &App{store: h.w.store, wa: h.w, mode: "connected"}
		}
		cfg := h.cfg
		cfg.Transport = transport
		cfg.Owner = true
		if rt, err := composeEventServe(ctx, app, func() {}, cfg); err == nil {
			_ = rt.Close(ctx)
			t.Fatal("explicit non-authoritative Events mode silently downgraded")
		}
		cfg.Enabled = false // Preserve the original disabled/default legacy assertions.
		rt, err := composeEventServe(ctx, app, func() {}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if rt.Service != nil {
			t.Fatal("non-authoritative mode constructed events")
		}
		legacy := httptest.NewServer(rt.Handler)
		initial, ss, status := evRPC(t, legacy.URL, "", "", "initialize", 91, map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "disabled-events", "version": "1"}})
		if status != 200 || initial["error"] != nil {
			t.Fatal("legacy initialize failed")
		}
		caps := initial["result"].(map[string]any)["capabilities"].(map[string]any)
		if _, present := caps["events"]; present {
			t.Fatal("readonly/stdio advertised top-level events")
		}
		evRPC(t, legacy.URL, "", ss, "notifications/initialized", nil, map[string]any{})
		out, _, _ := evRPC(t, legacy.URL, "", ss, "tools/list", 7, map[string]any{})
		if strings.Contains(fmt.Sprint(out), "message_monitor") {
			t.Fatal("reader/stdio controls leaked")
		}
		legacy.Close()
		_ = rt.Close(ctx)
	}
	other, _, otherSrv, _ := evCompose(t)
	otherSession := evSession(t, otherSrv.URL, other.token)
	for _, cred := range []string{other.token, ""} {
		_, _, status := evRPC(t, srv.URL, cred, session, "events/list", 8, map[string]any{})
		if status != 401 {
			t.Fatal("cross-profile credential accepted")
		}
	}
	q, _, status := evRPC(t, srv.URL, h.token, otherSession, "events/list", 9, map[string]any{})
	if status == 200 && q["error"] == nil {
		t.Fatal("cross-server session accepted")
	}
	q, _, _ = evRPC(t, otherSrv.URL, other.token, otherSession, "tools/call", 10, map[string]any{"name": "stop_message_monitor", "arguments": map[string]any{"id": id}})
	if q["error"] == nil && q["result"].(map[string]any)["isError"] != true {
		t.Fatal("other owner controlled monitor")
	}
	var stdout, stderr bytes.Buffer
	app := &App{store: h.w.store, wa: h.w, mode: "connected"} // actual authority must be obtained again below, never synthesized here
	_ = app
	owner, ownerCleanup, _ := evOwnedApp(t)
	defer ownerCleanup()
	cfg := h.cfg
	cfg.Store = owner.store
	cfg.WA = owner.wa
	cliPath, err := filepath.EvalSymlinks(dbPath(owner.wa.dataDir))
	if err != nil {
		t.Fatal(err)
	}
	cliHash := sha256.Sum256([]byte(cliPath))
	cfg.ProfileID = fmt.Sprintf("%x", cliHash)
	cfg.OwnerID = "cli-owner"
	cliKeys := &evKeys{profile: cfg.ProfileID, keys: map[string][]byte{}}
	cfg.Secrets = cliKeys
	copies := 0
	var copied string
	cfg.Clipboard = func(s string) error { copies++; copied = s; return nil }
	for _, op := range []string{"init", "status", "rotate", "copy", "revoke"} {
		beforeCopies := copies
		if err := dispatchEventsAccess(ctx, []string{op}, owner, cfg, &stdout, &stderr); err != nil {
			t.Fatal(err)
		}
		for _, raw := range cliKeys.written {
			for _, needle := range [][]byte{raw, []byte(base64.RawURLEncoding.EncodeToString(raw)), []byte(base64.StdEncoding.EncodeToString(raw))} {
				if len(needle) > 0 && (bytes.Contains(stdout.Bytes(), needle) || bytes.Contains(stderr.Bytes(), needle)) {
					t.Fatal("CLI disclosed an init/rotate credential")
				}
			}
		}
		if op != "copy" && copies != beforeCopies {
			t.Fatal("implicit clipboard operation")
		}
		if op == "copy" && copies != 1 {
			t.Fatal("explicit copy missing")
		}
		if op == "copy" {
			if strings.Contains(stdout.String()+stderr.String(), copied) {
				t.Fatal("CLI printed access token")
			}
		}
	}
	if strings.Contains(stdout.String()+stderr.String(), "whsec_") {
		t.Fatal("CLI printed callback credential")
	}
}

func evStoredStrings(t *testing.T, h *evHarness) [][]byte {
	t.Helper()
	var names []string
	rows, err := h.w.store.db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'mcp_event_%'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		_ = rows.Scan(&name)
		names = append(names, name)
	}
	rows.Close()
	var out [][]byte
	for _, name := range names {
		rs, err := h.w.store.db.Query(`SELECT * FROM "` + name + `"`)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rs.Columns()
		for rs.Next() {
			v := make([]any, len(cols))
			ptr := make([]any, len(cols))
			for i := range v {
				ptr[i] = &v[i]
			}
			if err := rs.Scan(ptr...); err != nil {
				t.Fatal(err)
			}
			for _, x := range v {
				switch z := x.(type) {
				case string:
					out = append(out, []byte(z))
				case []byte:
					out = append(out, z)
				}
			}
		}
		rs.Close()
	}
	return out
}
func TestEventsCredentialBoundaryAndAccessSwapFailure(t *testing.T) {
	ctx := context.Background()
	h := evSetup(t, 0)
	r := evReq(alice.String(), "")
	r.Delivery.URL = "https://CALLBACK.EXAMPLE:443/hook"
	sub := evSub(t, h, r)
	calls := h.sender.verifyCalls
	if len(calls) == 0 || calls[0] != (evVerifyCall{"https://callback.example/hook", sub.ID, r.Delivery.Secret}) {
		t.Fatal("verified wrong callback/identity/key")
	}
	evLive(h, alice, alice, "before-rotation", h.clock.Now())
	evDispatch(t, h)
	if q := h.sender.requests()[0]; len(q.Secrets) != 1 || q.Secrets[0] != r.Delivery.Secret {
		t.Fatal("wrong active signing key")
	}
	newSecret := "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32))
	r.Delivery.Secret = newSecret
	evSub(t, h, r)
	last := h.sender.verifyCalls[len(h.sender.verifyCalls)-1]
	if last.Secret != newSecret || last.ID != sub.ID || last.URL != "https://callback.example/hook" {
		t.Fatal("rotation verified stale key")
	}
	evLive(h, alice, alice, "during-rotation", h.clock.Now())
	evDispatch(t, h)
	q := h.sender.requests()[1]
	if len(q.Secrets) != 2 || q.Secrets[0] != newSecret || q.Secrets[1] != evReq("", "").Delivery.Secret {
		t.Fatal("wrong dual signing values")
	}
	h.clock.Add(5*time.Minute + time.Millisecond)
	evLive(h, alice, alice, "after-rotation", h.clock.Now())
	evDispatch(t, h)
	q = h.sender.requests()[2]
	if len(q.Secrets) != 1 || q.Secrets[0] != newSecret {
		t.Fatal("rotation retained wrong key")
	}
	for _, missing := range []bool{true, false} {
		t.Run(fmt.Sprint("missing=", missing), func(t *testing.T) {
			x := evSetup(t, 0)
			id := evSub(t, x, evReq(alice.String(), "")).ID
			evLive(x, alice, alice, "blocked-key", x.clock.Now())
			refs, _ := x.keys.ListRefs(ctx)
			saved := map[string][]byte{}
			for _, ref := range refs {
				if strings.Contains(ref, "/"+id+"/") {
					saved[ref] = append([]byte(nil), x.keys.keys[ref]...)
					if missing {
						delete(x.keys.keys, ref)
					}
				}
			}
			n := x.keys.n
			if !missing {
				x.keys.getErr = eventsecrets.ErrDenied
			}
			evDispatch(t, x)
			if len(x.sender.requests()) != 0 || x.keys.n != n || evMon(t, x, id).LastErrorCode == "" {
				t.Fatal("missing/denied key fallback or invisible failure")
			}
			x.keys.getErr = nil
			for ref, b := range saved {
				x.keys.keys[ref] = b
			}
			x.clock.Add(16 * time.Minute)
			evDispatch(t, x)
			if len(x.sender.requests()) != 1 {
				t.Fatal("restored key failed recoverable delivery")
			}
		})
	}
	for _, op := range []string{"init", "rotate"} {
		t.Run("access-db-failure-"+op, func(t *testing.T) {
			x := evSetup(t, 0)
			if op == "init" {
				if _, err := x.s.Access(ctx, "revoke"); err != nil {
					t.Fatal(err)
				}
			}
			oldToken := x.token
			oldRefs, _ := x.keys.ListRefs(ctx)
			for _, sqlop := range []string{"INSERT", "UPDATE"} {
				if _, err := x.w.store.db.Exec(`CREATE TRIGGER reject_access_` + sqlop + ` BEFORE ` + sqlop + ` ON mcp_event_access BEGIN SELECT RAISE(ABORT,'access swap failed'); END`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := x.s.Access(ctx, op); err == nil {
				t.Fatal("failed access activation accepted")
			}
			for _, sqlop := range []string{"INSERT", "UPDATE"} {
				_, _ = x.w.store.db.Exec(`DROP TRIGGER reject_access_` + sqlop)
			}
			refs, _ := x.keys.ListRefs(ctx)
			if len(refs) != len(oldRefs) {
				t.Fatal("access swap leaked/deleted wrong key")
			}
			if op == "rotate" {
				if _, err := x.s.Access(ctx, "copy"); err != nil || x.token != oldToken {
					t.Fatal("failed rotation changed usable access credential")
				}
			}
		})
	}
	rawAccess, _ := base64.RawURLEncoding.DecodeString(h.token)
	known := [][]byte{rawAccess, []byte(base64.StdEncoding.EncodeToString(rawAccess)), bytes.Repeat([]byte{0x31}, 32), []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))), []byte(newSecret), bytes.Repeat([]byte{0x77}, 32), []byte(h.token), []byte(evReq("", "").Delivery.Secret)}
	status, _ := json.Marshal(evMon(t, h, sub.ID))
	logical := append(evStoredStrings(t, h), status)
	for _, value := range logical {
		for _, secret := range known {
			if len(secret) > 0 && bytes.Contains(value, secret) {
				t.Fatal("known credential leaked to logical DB/status")
			}
		}
	}
	h.sender.verifyErr = errors.New(newSecret)
	r.Delivery.Secret = evReq("", "").Delivery.Secret
	if _, err := h.s.Subscribe(ctx, r); err != nil && strings.Contains(err.Error(), newSecret) {
		t.Fatal("error disclosed callback key")
	}
}

func evReopen(t *testing.T, h *evHarness) {
	t.Helper()
	path := filepath.Join(h.w.dataDir, "archive.db")
	if err := h.w.drainAndClose(); err != nil {
		t.Fatal(err)
	}
	db, err := securestore.Open(path, false, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	w, err := newWA(context.Background(), db, NewStore(db), filepath.Dir(path), zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	h.w = w
	h.sender.store = w.store
	h.cfg.Store = w.store
	h.cfg.WA = w
	h.cfg.Hooks = nil
	h.s, err = NewEventService(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.s.Close(context.Background()); _ = w.drainAndClose() })
}
func TestEventsReopenLeaseReceiptFailureAndAgeBounds(t *testing.T) {
	ctx := context.Background()
	t.Run("committed-before-wake", func(t *testing.T) {
		h := evSetup(t, 0)
		evSub(t, h, evReq(alice.String(), ""))
		evLive(h, alice, alice, "lost-wake", h.clock.Now())
		if len(h.sender.requests()) != 0 {
			t.Fatal("fixture already dispatched")
		}
		evReopen(t, h)
		if err := h.s.Start(ctx); err != nil {
			t.Fatal(err)
		}
		evWait(t, "reopened startup scan", func() bool { return len(h.sender.requests()) == 1 })
	})
	t.Run("receiver-success-local-ack-interrupted", func(t *testing.T) {
		h := evSetup(t, 0)
		if err := h.s.Close(ctx); err != nil {
			t.Fatal(err)
		}
		h.cfg.Hooks = &EventHooks{BeforeReceiptCommit: func(context.Context, string) error { return errors.New("simulated acknowledgement interruption") }}
		var err error
		h.s, err = NewEventService(h.cfg)
		if err != nil {
			t.Fatal(err)
		}
		id := evSub(t, h, evReq(alice.String(), "")).ID
		evLive(h, alice, alice, "receipt-lost", h.clock.Now())
		_, err = h.s.DispatchOnce(ctx)
		if err == nil {
			t.Fatal("ack interruption not surfaced")
		}
		first := h.sender.requests()[0]
		evReopen(t, h)
		evDispatch(t, h)
		if len(h.sender.requests()) != 1 {
			t.Fatal("unexpired lease reclaimed")
		}
		h.clock.Add(61 * time.Second)
		evDispatch(t, h)
		sent := h.sender.requests()
		if len(sent) != 2 || sent[1].EventID != first.EventID || !bytes.Equal(sent[1].Body, first.Body) || evMon(t, h, id).Accepted != 1 {
			t.Fatal("expired lease recovery lost immutable event or durable receipt")
		}
	})
	for _, status := range []int{410, 500, 429} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			h := evSetup(t, 0)
			rq := evReq(alice.String(), "")
			rq.TTLMS = json.RawMessage("604800000")
			id := evSub(t, h, rq).ID
			h.sender.receipt = eventdelivery.Receipt{StatusCode: status, RetryAfter: 15 * time.Minute}
			evLive(h, alice, alice, "first", h.clock.Now())
			evLive(h, alice, alice, "second", h.clock.Now())
			evDispatch(t, h)
			if status == 410 {
				evLive(h, alice, alice, "after-gone", h.clock.Now())
				evDispatch(t, h)
				if len(h.sender.requests()) != 1 || evMon(t, h, id).State != "revoked" || evMon(t, h, id).Pending != 0 {
					t.Fatal("410 failed to revoke all queued/future work")
				}
				return
			}
			if status == 429 {
				var due int64
				if err := h.w.store.db.QueryRow(`SELECT next_attempt_at FROM mcp_event_deliveries WHERE attempt_count>0 LIMIT 1`).Scan(&due); err != nil {
					t.Fatal(err)
				}
				delta := time.UnixMilli(due).Sub(h.clock.Now())
				if delta < 15*time.Minute || delta > 15*time.Minute+time.Millisecond {
					t.Fatal("Retry-After due time not bounded")
				}
			}
			h.clock.Add(24 * time.Hour)
			n := len(h.sender.requests())
			evDispatch(t, h)
			mon := evMon(t, h, id)
			if len(h.sender.requests()) != n || mon.Pending != 0 || mon.Failed == 0 || mon.LastErrorCode == "" {
				t.Fatal("24h exhausted rows with low attempts were sent/hidden")
			}
		})
	}
}

type evScheduler struct {
	evClock
	timers []evTimer
}
type evTimer struct {
	at time.Time
	ch chan time.Time
}

func (c *evScheduler) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.t
	} else {
		c.timers = append(c.timers, evTimer{c.t.Add(d), ch})
	}
	return ch
}
func (c *evScheduler) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	remaining := c.timers[:0]
	for _, timer := range c.timers {
		if !timer.at.After(c.t) {
			timer.ch <- c.t
		} else {
			remaining = append(remaining, timer)
		}
	}
	c.timers = remaining
	c.mu.Unlock()
}
func TestEventsObservableBurstConcurrencyRateAndPrune(t *testing.T) {
	ctx := context.Background()
	h := evSetup(t, 0)
	_ = h.s.Close(ctx)
	clock := &evScheduler{evClock: evClock{t: h.clock.Now()}}
	h.cfg.Now = clock.Now
	h.cfg.After = clock.After
	var err error
	h.s, err = NewEventService(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		rq := evReq(alice.String(), "")
		rq.Delivery.URL = fmt.Sprintf("https://callback.example/%d", i)
		evSub(t, h, rq)
	}
	var mu sync.Mutex
	var active, maxGlobal int
	per := map[string]int{}
	starts := map[string][]time.Time{}
	release := make(chan struct{}, 80)
	t.Cleanup(func() { close(release) })
	h.sender.enter = func(q eventdelivery.Request) func() {
		mu.Lock()
		active++
		if active > maxGlobal {
			maxGlobal = active
		}
		per[q.SubscriptionID]++
		if active > 4 || per[q.SubscriptionID] > 1 {
			t.Error("observable worker concurrency exceeded")
		}
		starts[q.SubscriptionID] = append(starts[q.SubscriptionID], clock.Now())
		mu.Unlock()
		<-release
		return func() { mu.Lock(); active--; per[q.SubscriptionID]--; mu.Unlock() }
	}
	for i := 0; i < 12; i++ {
		evLive(h, alice, alice, fmt.Sprint("burst", i), clock.Now())
	}
	if err := h.s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	evWait(t, "four concurrent starts", func() bool { mu.Lock(); defer mu.Unlock(); return active == 4 })
	for i := 0; i < 20; i++ {
		release <- struct{}{}
	}
	evWait(t, "initial global burst", func() bool {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, v := range starts {
			n += len(v)
		}
		return n >= 20
	})
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	initial := 0
	for _, v := range starts {
		initial += len(v)
		if len(v) > 10 {
			t.Error("per-sub initial burst exceeded10")
		}
	}
	mu.Unlock()
	if initial != 20 {
		t.Fatalf("global burst got %d want20", initial)
	}
	for tick := 0; tick < 4; tick++ {
		clock.Advance(time.Second)
		for i := 0; i < 20; i++ {
			release <- struct{}{}
		}
		time.Sleep(30 * time.Millisecond)
	}
	evWait(t, "all queued burst work", func() bool { return len(h.sender.requests()) == 60 })
	mu.Lock()
	if maxGlobal != 4 {
		t.Error("worker serialized eligible independent subscriptions")
	}
	startTime := clock.Now().Add(-4 * time.Second)
	for second := 0; second <= 4; second++ {
		boundary := startTime.Add(time.Duration(second) * time.Second)
		global := 0
		for _, ts := range starts {
			count := 0
			for _, at := range ts {
				if !at.After(boundary) {
					count++
				}
			}
			if count > 10+5*second {
				t.Errorf("per-sub token bucket cumulative count %d exceeds %d", count, 10+5*second)
			}
			global += count
		}
		if global > 20+20*second {
			t.Errorf("global token bucket cumulative count %d exceeds %d", global, 20+20*second)
		}
	}
	mu.Unlock()
	t.Run("seven-day-metadata-and-inflight-ref", func(t *testing.T) {
		x := evSetup(t, 0)
		rq := evReq(alice.String(), "")
		rq.TTLMS = json.RawMessage("604800000")
		evSub(t, x, rq)
		evLive(x, alice, alice, "retained", x.clock.Now())
		evDispatch(t, x)
		x.clock.Add(7*24*time.Hour - time.Millisecond)
		if err := x.s.Prune(ctx); err != nil {
			t.Fatal(err)
		}
		if evCount(t, x, "mcp_event_outbox") != 1 {
			t.Fatal("audit pruned before7d")
		}
		x.clock.Add(2 * time.Millisecond)
		if err := x.s.Prune(ctx); err != nil {
			t.Fatal(err)
		}
		if evCount(t, x, "mcp_event_outbox") != 0 {
			t.Fatal("audit retained beyond7d")
		}
		y := evSetup(t, 0)
		evSub(t, y, evReq(alice.String(), ""))
		evLive(y, alice, alice, "blocked-prune", y.clock.Now())
		entered := make(chan struct{})
		unblock := make(chan struct{})
		y.sender.beforeSend = func() { close(entered); <-unblock }
		done := make(chan error, 1)
		go func() { _, err := y.s.DispatchOnce(ctx); done <- err }()
		evAwait(t, entered)
		refs, _ := y.keys.ListRefs(ctx)
		y.clock.Add(8 * 24 * time.Hour)
		if err := y.s.Prune(ctx); err != nil {
			t.Fatal(err)
		}
		during, _ := y.keys.ListRefs(ctx)
		if len(during) != len(refs) {
			t.Fatal("prune deleted active auth/inflight signing reference")
		}
		close(unblock)
		<-done
		if err := y.s.Prune(ctx); err != nil {
			t.Fatal(err)
		}
		after, _ := y.keys.ListRefs(ctx)
		if len(after) != 1 {
			t.Fatal("completed inflight reference not collected or auth lost")
		}
	})
}

func TestEventsHTTPVerificationAdmissionRaceAndStop(t *testing.T) {
	ctx := context.Background()
	for _, action := range []string{"close", "revoke", "logout"} {
		t.Run(action, func(t *testing.T) {
			h, rt, srv, _ := evCompose(t)
			session := evSession(t, srv.URL, h.token)
			rq := evReq(alice.String(), "")
			id := evSub(t, h, rq).ID
			entered := make(chan struct{})
			release := make(chan struct{})
			h.sender.verifyHook = func(context.Context, string, string, string) error { close(entered); <-release; return nil }
			rq.Delivery.Secret = "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x66}, 32))
			response := make(chan map[string]any, 1)
			go func() { q, _, _ := evRPC(t, srv.URL, h.token, session, "events/subscribe", 70, rq); response <- q }()
			evAwait(t, entered)
			closed := make(chan error, 1)
			switch action {
			case "close":
				go func() { closed <- rt.Close(ctx) }()
				time.Sleep(20 * time.Millisecond)
				select {
				case <-closed:
					t.Fatal("cleanup overtook admitted HTTP verify")
				default:
				}
				q, _, status := evRPC(t, srv.URL, h.token, session, "events/list", 71, map[string]any{})
				if status == 200 && q["error"] == nil {
					t.Fatal("close admitted new operations")
				}
			case "revoke":
				if _, err := h.s.Access(ctx, "revoke"); err != nil {
					t.Fatal(err)
				}
			case "logout":
				h.w.handleEvent(&events.LoggedOut{})
			}
			close(release)
			var q map[string]any
			select {
			case q = <-response:
			case <-time.After(2 * time.Second):
				t.Fatal("admitted HTTP operation failed to finish")
			}
			if action == "close" {
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("HTTP operation did not drain before DB cleanup")
				}
				if err := h.w.store.db.Ping(); err == nil {
					t.Fatal("production cleanup did not close archive after HTTP drain")
				}
			} else {
				if q["error"] == nil {
					t.Fatal("admitted refresh committed after grant revoked")
				}
				if mon := evMon(t, h, id); mon.State == "active" || mon.Pending != 0 {
					t.Fatal("revoked refresh reactivated")
				}
			}
		})
	}
	h := evSetup(t, 0)
	id := evSub(t, h, evReq(alice.String(), "")).ID
	evLive(h, alice, alice, "already-admitted", h.clock.Now())
	evLive(h, alice, alice, "not-admitted", h.clock.Now())
	entered := make(chan struct{})
	release := make(chan struct{})
	h.sender.beforeSend = func() { close(entered); <-release }
	done := make(chan error, 1)
	go func() { _, err := h.s.DispatchOnce(ctx); done <- err }()
	evAwait(t, entered)
	if err := h.s.Control(ctx, id, "stop"); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	evDispatch(t, h)
	if len(h.sender.requests()) != 1 {
		t.Fatal("stop allowed more than already admitted callback")
	}
}

func TestEventsRealMonotonicIngressLatency30(t *testing.T) {
	h := evSetup(t, 0)
	_ = h.s.Close(context.Background())
	h.cfg.Now = time.Now
	h.cfg.After = time.After
	var err error
	h.s, err = NewEventService(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	evSub(t, h, evReq(alice.String(), ""))
	readerDB, err := securestore.Open(filepath.Join(h.w.dataDir, "archive.db"), true, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer readerDB.Close()
	reader := NewStore(readerDB)
	var mu sync.Mutex
	ingress := map[string]time.Time{}
	var latencies []time.Duration
	h.sender.enter = func(q eventdelivery.Request) func() {
		entry := time.Now()
		var b struct {
			Data struct {
				Chat string `json:"chat_jid"`
				ID   string `json:"message_id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(q.Body, &b); err != nil {
			t.Error(err)
			return nil
		}
		if _, err := reader.Message(context.Background(), b.Data.Chat, b.Data.ID); err != nil {
			t.Errorf("separate encrypted reader cannot see committed source: %v", err)
		}
		mu.Lock()
		start, ok := ingress[b.Data.ID]
		if !ok {
			t.Error("unobserved source")
		}
		latencies = append(latencies, entry.Sub(start))
		mu.Unlock()
		return nil
	}
	if err := h.s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	schedule := time.Now()
	for i := 0; i < 30; i++ {
		target := schedule.Add(time.Duration(i) * 200 * time.Millisecond)
		if delay := time.Until(target); delay > 0 {
			time.Sleep(delay)
		}
		id := fmt.Sprint("latency", i)
		mu.Lock()
		ingress[id] = time.Now()
		mu.Unlock()
		evLive(h, alice, alice, id, time.Now())
	}
	evWait(t, "30 asynchronous measured starts", func() bool { mu.Lock(); defer mu.Unlock(); return len(latencies) == 30 })
	mu.Lock()
	defer mu.Unlock()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p95 := latencies[28]
	t.Logf("conservative_ingress_to_fake_Send n=30 workload=5/s p50=%s p95=%s max=%s; separate encrypted reader committed; excludes real network/Dot/push", latencies[14], p95, latencies[29])
	if p95 <= 0 || p95 > time.Second {
		t.Fatalf("real-monotonic ingress upper-bound p95 %s exceeds1s or invalid", p95)
	}
}

func TestEventsSelectedPeopleFilterTruthTable(t *testing.T) {
	h := evSetup(t, 0)
	if err := h.w.Client.Store.LIDs.PutLIDMapping(context.Background(), bobLID, bob); err != nil {
		t.Fatal(err)
	}
	r := evReq("", "")
	r.Arguments = json.RawMessage(fmt.Sprintf(`{"sender_jids":[%q,%q]}`, alice.String(), bobLID.String()))
	evSub(t, h, r)
	for i, x := range []struct{ chat, sender types.JID }{{group, bob}, {alice, alice}, {group, alice}, {bob, bob}, {group, types.NewJID("491533333333", types.DefaultUserServer)}} {
		evLive(h, x.chat, x.sender, fmt.Sprint("truth", i), h.clock.Now())
	}
	if n := evCount(t, h, "mcp_event_outbox"); n != 4 {
		t.Fatalf("sender-only OR across chats/preaccepted alias: %d want4", n)
	}
}

var _ io.Writer = (*bytes.Buffer)(nil)
