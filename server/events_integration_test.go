//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hansen/whatsapp-mcp/internal/eventdelivery"
	"github.com/hansen/whatsapp-mcp/internal/eventsecrets"
	"github.com/hansen/whatsapp-mcp/internal/securestore"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

type evClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *evClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *evClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type evKeys struct {
	mu      sync.Mutex
	profile string
	n       int
	keys    map[string][]byte
	failPut bool
	getErr  error
	written [][]byte
}

func (k *evKeys) Get(_ context.Context, ref string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.getErr != nil {
		return nil, k.getErr
	}
	b, ok := k.keys[ref]
	if !ok {
		return nil, eventsecrets.ErrNotFound
	}
	return append([]byte(nil), b...), nil
}
func (k *evKeys) PutVersion(_ context.Context, sub string, b []byte) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failPut {
		return "", eventsecrets.ErrDenied
	}
	k.written = append(k.written, append([]byte(nil), b...))
	k.n++
	ref := fmt.Sprintf("evk1/%s/%s/%032x", k.profile, sub, k.n)
	k.keys[ref] = append([]byte(nil), b...)
	return ref, nil
}
func (k *evKeys) Delete(_ context.Context, ref string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.keys, ref)
	return nil
}
func (k *evKeys) ListRefs(context.Context) ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []string
	for ref := range k.keys {
		out = append(out, ref)
	}
	return out, nil
}

type evVerifyCall struct{ URL, ID, Secret string }
type evSender struct {
	verifyCalls []evVerifyCall
	verifyHook  func(context.Context, string, string, string) error
	enter       func(eventdelivery.Request) func()
	mu          sync.Mutex
	sent        []eventdelivery.Request
	verifyErr   error
	receipt     eventdelivery.Receipt
	sendErr     error
	store       *Store
	beforeSend  func()
	committed   bool
}

func (s *evSender) Verify(ctx context.Context, url, id, secret string) error {
	s.mu.Lock()
	s.verifyCalls = append(s.verifyCalls, evVerifyCall{url, id, secret})
	hook, err := s.verifyHook, s.verifyErr
	s.mu.Unlock()
	if hook != nil {
		return hook(ctx, url, id, secret)
	}
	return err
}
func (s *evSender) Send(ctx context.Context, q eventdelivery.Request) (eventdelivery.Receipt, error) {
	s.mu.Lock()
	entry := s.enter
	s.mu.Unlock()
	if entry != nil {
		exit := entry(q)
		if exit != nil {
			defer exit()
		}
	}
	var body struct {
		Data struct {
			Chat string `json:"chat_jid"`
			ID   string `json:"message_id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(q.Body, &body)
	_, err := s.store.Message(ctx, body.Data.Chat, body.Data.ID)
	s.mu.Lock()
	s.committed = s.committed && err == nil
	q.Body = append([]byte(nil), q.Body...)
	q.Secrets = append([]string(nil), q.Secrets...)
	s.sent = append(s.sent, q)
	hook := s.beforeSend
	receipt, sendErr := s.receipt, s.sendErr
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	return receipt, sendErr
}
func (s *evSender) requests() []eventdelivery.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]eventdelivery.Request(nil), s.sent...)
}

type evHarness struct {
	w      *WA
	s      *EventService
	cfg    EventConfig
	keys   *evKeys
	sender *evSender
	clock  *evClock
	token  string
}

func evSetup(t *testing.T, pending int) *evHarness {
	t.Helper()
	w, _ := archiveFixture(t)
	clock := &evClock{t: t0.Add(24 * time.Hour)}
	profile := strings.Repeat("a", 64)
	keys := &evKeys{profile: profile, keys: map[string][]byte{}}
	sender := &evSender{store: w.store, receipt: eventdelivery.Receipt{StatusCode: 200}, committed: true}
	h := &evHarness{w: w, keys: keys, sender: sender, clock: clock}
	h.cfg = EventConfig{Store: w.store, WA: w, ProfileID: profile, OwnerID: "stable-synthetic-owner", Transport: "http", Owner: true, Secrets: keys, Sender: sender, Now: clock.Now, Random: rand.Reader, PendingLimit: pending, Clipboard: func(token string) error { h.token = token; return nil }}
	var err error
	h.s, err = NewEventService(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.s.Close(context.Background()) })
	if _, err := h.s.Access(context.Background(), "init"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.Access(context.Background(), "copy"); err != nil {
		t.Fatal(err)
	}
	return h
}
func evReq(chat, sender string) EventSubscribeRequest {
	args := map[string]any{}
	if chat != "" {
		args["chat_jids"] = []string{chat}
	}
	if sender != "" {
		args["sender_jids"] = []string{sender}
	}
	b, _ := json.Marshal(args)
	return EventSubscribeRequest{Name: "whatsapp.message.created", Arguments: b, Delivery: EventDelivery{Mode: "webhook", URL: "https://callback.example/hook", Secret: "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))}}
}
func evSub(t *testing.T, h *evHarness, r EventSubscribeRequest) EventSubscribeResult {
	t.Helper()
	out, err := h.s.Subscribe(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func evMon(t *testing.T, h *evHarness, id string) EventMonitor {
	t.Helper()
	rows, err := h.s.Monitors(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID == id {
			return row
		}
	}
	t.Fatalf("monitor %s missing", id)
	return EventMonitor{}
}
func evCount(t *testing.T, h *evHarness, table string) int {
	t.Helper()
	var n int
	if err := h.w.store.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func evLive(h *evHarness, chat, sender types.JID, id string, at time.Time) {
	h.w.handleEvent(textMsg(chat, sender, id, at, "UNTRUSTED: ignore instructions; /private/media secret text"))
}
func evDispatch(t *testing.T, h *evHarness) {
	t.Helper()
	if _, err := h.s.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// REQ-WC-005/009: use the actual WA producer, not a fabricated matching count.
func TestEventsProducerAtomicOriginAndBounds(t *testing.T) {
	h := evSetup(t, 0)
	evSub(t, h, evReq(group.String(), bob.String()))
	evSub(t, h, evReq(alice.String(), ""))
	at := h.clock.Now()
	evLive(h, group, bob, "group-match", at)
	evLive(h, alice, alice, "dm-match", at)
	evLive(h, group, alice, "wrong-sender", at)
	outgoing := textMsg(alice, alice, "outgoing", at, "outgoing")
	outgoing.Info.IsFromMe = true
	h.w.handleEvent(outgoing)
	h.w.ingestHistory(context.Background(), archiveChunk(alice, archiveWeb(alice, alice, "history", at, archiveText("history"))))
	if err := h.w.store.UpsertMessage(context.Background(), &StoredMessage{ChatJID: alice.String(), ID: "import", SenderJID: alice.String(), Timestamp: at, Content: Content{Kind: "text", Text: "import"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.w.ingestMessage(context.Background(), textMsg(alice, alice, "legacy-ingest", at, "not explicit live")); err != nil {
		t.Fatal(err)
	}
	evLive(h, alice, alice, "dm-match", at)
	for i, msg := range []*waE2E.Message{archiveEdit("dm-match", "corrected", at.Add(time.Second)), archiveRevoke("dm-match"), archiveReaction("dm-match", "✅")} {
		evt := textMsg(alice, alice, fmt.Sprint("mutation", i), at, "")
		evt.Message = msg
		h.w.handleEvent(evt)
	}
	h.w.handleEvent(textMsg(types.NewJID("status", types.BroadcastServer), alice, "status", at, "story"))
	if n := evCount(t, h, "mcp_event_outbox"); n != 2 {
		t.Fatalf("excluded traffic created events: got %d want 2", n)
	}
	evDispatch(t, h)
	evDispatch(t, h)
	if len(h.sender.requests()) != 2 || !h.sender.committed {
		t.Fatal("send happened before commit or wrong matching set")
	}
	for _, q := range h.sender.requests() {
		if bytes.Contains(q.Body, []byte("UNTRUSTED")) || bytes.Contains(q.Body, []byte("/private")) {
			t.Fatal("payload leaked message body/path/instructions")
		}
		var b map[string]any
		_ = json.Unmarshal(q.Body, &b)
		_, hasCursor := b["cursor"]
		if !hasCursor || len(b) != 5 || len(b["data"].(map[string]any)) != 5 || b["cursor"] != nil || b["type"] != nil || b["eventId"] != q.EventID {
			t.Fatalf("wrong pointer envelope: %s", q.Body)
		}
	}
	t.Run("exact-source-time-boundaries", func(t *testing.T) {
		x := evSetup(t, 0)
		evSub(t, x, evReq(alice.String(), ""))
		for i, d := range []time.Duration{-5*time.Second - time.Millisecond, -5 * time.Second, 5 * time.Minute, 5*time.Minute + time.Millisecond} {
			evLive(x, alice, alice, fmt.Sprint("bound", i), x.clock.Now().Add(d))
		}
		if n := evCount(t, x, "mcp_event_outbox"); n != 2 {
			t.Errorf("source time boundaries: %d want 2", n)
		}
	})
	t.Run("outbox-fault-rolls-back-original", func(t *testing.T) {
		x := evSetup(t, 0)
		evSub(t, x, evReq(alice.String(), ""))
		if _, err := x.w.store.db.Exec(`CREATE TRIGGER reject_event BEFORE INSERT ON mcp_event_outbox BEGIN SELECT RAISE(ABORT,'injected outbox failure'); END`); err != nil {
			t.Fatal(err)
		}
		evLive(x, alice, alice, "must-rollback", x.clock.Now())
		if _, err := x.w.store.Message(context.Background(), alice.String(), "must-rollback"); err == nil {
			t.Fatal("original committed despite failed outbox")
		}
		if len(x.sender.requests()) != 0 {
			t.Fatal("network before failed commit")
		}
		tel, err := x.w.store.IngestTelemetry(context.Background())
		if err != nil || tel.LastErrorCode == "" {
			t.Fatal("ingest failure not visible")
		}
	})
}

// REQ-WC-004/007: actual SDK HTTP initialize/session/custom methods, no RPC stub.
func evRPC(t *testing.T, url, token, session, method string, id any, params any) (map[string]any, string, int) {
	t.Helper()
	q := map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
	if id != nil {
		q["id"] = id
	}
	b, _ := json.Marshal(q)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
		req.Header.Set("MCP-Protocol-Version", "2025-03-26")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]any
	if len(raw) > 0 && resp.StatusCode == 200 {
		if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.HasPrefix(line, "data: ") {
					raw = []byte(strings.TrimPrefix(line, "data: "))
					break
				}
			}
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("invalid SDK wire %s: %v", raw, err)
		}
	}
	return out, resp.Header.Get("Mcp-Session-Id"), resp.StatusCode
}
func TestEventsHTTPWireAuthAndIsolation(t *testing.T) {
	h := evSetup(t, 0)
	server := newMCPServer(&App{store: h.w.store, wa: h.w, mode: "connected"})
	if err := h.s.Register(server); err != nil {
		t.Fatal(err)
	}
	handler, err := h.s.HTTPHandler(server)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	init := map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "events-test", "version": "1"}}
	for _, token := range []string{"", "wrong"} {
		_, _, status := evRPC(t, httpServer.URL, token, "", "initialize", 1, init)
		if status != 401 {
			t.Fatalf("loopback unauthenticated status %d", status)
		}
	}
	out, session, status := evRPC(t, httpServer.URL, h.token, "", "initialize", 1, init)
	if status != 200 || session == "" {
		t.Fatalf("SDK initialize/session: %v %d", out, status)
	}
	result := out["result"].(map[string]any)
	caps := result["capabilities"].(map[string]any)
	if _, ok := caps["events"]; !ok {
		t.Fatal("top-level capabilities.events absent")
	}
	if _, ok := caps["tools"]; !ok {
		t.Fatal("SDK tools state lost")
	}
	evRPC(t, httpServer.URL, h.token, session, "notifications/initialized", nil, map[string]any{})
	for _, method := range []string{"ping", "tools/list", "events/list"} {
		q, _, _ := evRPC(t, httpServer.URL, h.token, session, method, 2, map[string]any{})
		if q["error"] != nil {
			t.Fatalf("%s failed after SDK initialize: %v", method, q)
		}
		if method == "events/list" {
			events := q["result"].(map[string]any)["events"].([]any)
			if len(events) != 1 || events[0].(map[string]any)["name"] != "whatsapp.message.created" {
				t.Fatalf("event catalog %v", events)
			}
		}
	}
	req := evReq(group.String(), bob.String())
	h.sender.verifyErr = errors.New("synthetic callback failure")
	rejected, _, _ := evRPC(t, httpServer.URL, h.token, session, "events/subscribe", 21, req)
	wireError, ok := rejected["error"].(map[string]any)
	if !ok || wireError["code"] != float64(-32015) {
		t.Fatalf("callback failure wire code: %v", rejected)
	}
	reason, ok := wireError["data"].(map[string]any)
	if !ok || reason["reason"] == nil || reason["reason"] == "" {
		t.Fatal("callback failure lacks categorized reason")
	}
	h.sender.verifyErr = nil
	expectedOwnerID := evSub(t, h, req).ID
	wire, _ := json.Marshal(req)
	var params map[string]any
	_ = json.Unmarshal(wire, &params)
	params["_meta"] = map[string]any{"owner_id": "spoofed"}
	q, _, _ := evRPC(t, httpServer.URL, h.token, session, "events/subscribe", 3, params)
	if q["error"] != nil {
		t.Fatal(q)
	}
	id := q["result"].(map[string]any)["id"].(string)
	if id != expectedOwnerID || len(id) != 68 || !strings.HasPrefix(id, "sub_") {
		t.Fatal(id)
	}
	un := EventUnsubscribeRequest{Name: req.Name, Arguments: req.Arguments, Delivery: EventDelivery{Mode: "webhook", URL: req.Delivery.URL}}
	q, _, _ = evRPC(t, httpServer.URL, h.token, session, "events/unsubscribe", 4, un)
	if q["error"] != nil || len(q["result"].(map[string]any)) != 0 {
		t.Fatal(q)
	}
	for _, cfg := range []EventConfig{func() EventConfig { x := h.cfg; x.Owner = false; x.WA = nil; return x }(), func() EventConfig { x := h.cfg; x.Transport = "stdio"; return x }()} {
		s, err := NewEventService(cfg)
		if err == nil {
			defer s.Close(context.Background())
			if err := s.Register(newMCPServer(&App{store: h.w.store, mode: "read-only"})); err == nil {
				t.Fatal("disabled mode advertised or mutated events")
			}
		}
	}
	oldToken := h.token
	if _, err := h.s.Access(context.Background(), "rotate"); err != nil {
		t.Fatal(err)
	}
	_, _, status = evRPC(t, httpServer.URL, oldToken, session, "ping", 5, map[string]any{})
	if status != 401 {
		t.Fatal("rotated credential retained access")
	}
	if _, err := h.s.Access(context.Background(), "copy"); err != nil {
		t.Fatal(err)
	}
	if h.token == oldToken {
		t.Fatal("access rotation did not rotate")
	}
}

func TestEventsFilterIdentityAndCallbackActivation(t *testing.T) {
	h := evSetup(t, 0)
	ctx := context.Background()
	r := evReq(group.String(), bobLID.String())
	a := evSub(t, h, r)
	r.Arguments = json.RawMessage(fmt.Sprintf(`{"sender_jids":[%q,%q],"chat_jids":[%q]}`, bobLID.String(), bobLID.String(), group.String()))
	r.Delivery.URL = "https://CALLBACK.EXAMPLE:443/hook"
	r.TTLMS = json.RawMessage("60000")
	b := evSub(t, h, r)
	if a.ID != b.ID {
		t.Fatal("canonical args/url/TTL changed identity")
	}
	for _, args := range []string{`{}`, `{"chat_jids":["*"]}`, `{"chat_jids":["status@broadcast"]}`, `{"chat_jids":["123@newsletter"]}`, `{"chat_jids":["Alice"]}`, `{"chat_jids":["491511:3@s.whatsapp.net"]}`, `{"chat_jids":[],"sender_jids":[]}`, `{"chat_jids":["123@g.us"],"unknown":1}`} {
		x := r
		x.Arguments = json.RawMessage(args)
		if _, err := h.s.Subscribe(ctx, x); err == nil {
			t.Errorf("invalid exact filter accepted: %s", args)
		}
	}
	ids := make([]string, 33)
	for i := range ids {
		ids[i] = fmt.Sprintf("%d@g.us", i+1)
	}
	raw, _ := json.Marshal(map[string]any{"chat_jids": ids})
	x := r
	x.Arguments = raw
	if _, err := h.s.Subscribe(ctx, x); err == nil {
		t.Error("33 filter IDs accepted")
	}
	for _, ttl := range []string{"0", "-1", "1.1", "9223372036854775808"} {
		x := r
		x.TTLMS = json.RawMessage(ttl)
		if _, err := h.s.Subscribe(ctx, x); err == nil {
			t.Errorf("invalid TTL accepted: %s", ttl)
		}
	}
	x = r
	x.Cursor = json.RawMessage(`"replay"`)
	if _, err := h.s.Subscribe(ctx, x); err == nil {
		t.Error("v1 replay cursor accepted")
	}
	// Accepted mapping after filter creation changes matching, never issued identity.
	if err := h.w.Client.Store.LIDs.PutLIDMapping(ctx, bobLID, bob); err != nil {
		t.Fatal(err)
	}
	evLive(h, group, bob, "post-alias", h.clock.Now())
	if evCount(t, h, "mcp_event_outbox") != 1 {
		t.Fatal("accepted alias failed sender filter matching")
	}
	for _, stage := range []string{"verify", "key-put", "db-swap"} {
		t.Run(stage, func(t *testing.T) {
			prior := evMon(t, h, a.ID)
			refs, _ := h.keys.ListRefs(ctx)
			candidate := r
			candidate.Delivery.Secret = "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32))
			switch stage {
			case "verify":
				h.sender.verifyErr = errors.New("challenge_failed")
			case "key-put":
				h.keys.failPut = true
			case "db-swap":
				if _, err := h.w.store.db.Exec(`CREATE TRIGGER reject_subscription BEFORE UPDATE ON mcp_event_subscriptions BEGIN SELECT RAISE(ABORT,'swap failed'); END`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := h.s.Subscribe(ctx, candidate); err == nil {
				t.Fatal("failed rotation activated")
			}
			h.sender.verifyErr = nil
			h.keys.failPut = false
			if stage == "db-swap" {
				_, _ = h.w.store.db.Exec(`DROP TRIGGER reject_subscription`)
			}
			after := evMon(t, h, a.ID)
			nowRefs, _ := h.keys.ListRefs(ctx)
			if after.Generation != prior.Generation || after.State != prior.State || len(nowRefs) != len(refs) {
				t.Fatal("failed activation changed old generation or leaked staged key")
			}
		})
	}
	for _, ttl := range []json.RawMessage{nil, json.RawMessage("null"), json.RawMessage("9999999999999")} {
		rq := r
		rq.TTLMS = ttl
		out := evSub(t, h, rq)
		d := out.RefreshBefore.Sub(h.clock.Now())
		if d < time.Minute || d > 7*24*time.Hour {
			t.Fatalf("finite TTL contract: %v", d)
		}
	}
	rotated := r
	rotated.TTLMS = nil
	rotated.Delivery.Secret = "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	oldGeneration := evMon(t, h, a.ID).Generation
	evSub(t, h, rotated)
	if evMon(t, h, a.ID).Generation <= oldGeneration {
		t.Fatal("successful rotation did not advance generation")
	}
	evDispatch(t, h)
	sent := h.sender.requests()
	if len(sent) == 0 || len(sent[len(sent)-1].Secrets) != 2 {
		t.Fatal("rotation did not dual-sign pending event")
	}
	h.clock.Add(5*time.Minute + time.Millisecond)
	evLive(h, group, bob, "after-rotation-window", h.clock.Now())
	evDispatch(t, h)
	sent = h.sender.requests()
	if len(sent[len(sent)-1].Secrets) != 1 {
		t.Fatal("old signing key retained past rotation window")
	}

}

func TestEventsLifecycleRefreshStopExpiryAndRevocation(t *testing.T) {
	h := evSetup(t, 0)
	ctx := context.Background()
	r := evReq(alice.String(), "")
	sub := evSub(t, h, r)
	if err := h.s.Control(ctx, sub.ID, "pause"); err != nil {
		t.Fatal(err)
	}
	evLive(h, alice, alice, "paused", h.clock.Now())
	evSub(t, h, r)
	if evMon(t, h, sub.ID).State != "paused" || evCount(t, h, "mcp_event_outbox") != 0 {
		t.Fatal("refresh revived paused monitor")
	}
	if err := h.s.Control(ctx, sub.ID, "resume"); err != nil {
		t.Fatal(err)
	}
	evLive(h, alice, alice, "resumed", h.clock.Now())
	if evCount(t, h, "mcp_event_outbox") != 1 {
		t.Fatal("resume did not start now")
	}
	if err := h.s.Control(ctx, sub.ID, "stop"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.Subscribe(ctx, r); err == nil {
		t.Fatal("native refresh revived locally stopped monitor")
	}
	if err := h.s.Control(ctx, sub.ID, "resume"); err == nil {
		t.Fatal("resume revived terminal stop")
	}
	evDispatch(t, h)
	if len(h.sender.requests()) != 0 {
		t.Fatal("stop left pending send")
	}
	for _, revoke := range []string{"expiry", "logout", "access-revoke"} {
		t.Run(revoke, func(t *testing.T) {
			x := evSetup(t, 0)
			rq := evReq(alice.String(), "")
			rq.TTLMS = json.RawMessage("60000")
			id := evSub(t, x, rq).ID
			evLive(x, alice, alice, "queued", x.clock.Now())
			switch revoke {
			case "expiry":
				x.clock.Add(time.Minute)
			case "logout":
				x.w.handleEvent(&events.LoggedOut{})
			case "access-revoke":
				if _, err := x.s.Access(ctx, "revoke"); err != nil {
					t.Fatal(err)
				}
			}
			evDispatch(t, x)
			evLive(x, alice, alice, "later", x.clock.Now())
			evDispatch(t, x)
			if len(x.sender.requests()) != 0 || evMon(t, x, id).Pending != 0 {
				t.Fatal("revocation/expiry allowed queued/future delivery")
			}
		})
	}
}

func TestEventsDurableRetriesReceiptAndQueueFailure(t *testing.T) {
	ctx := context.Background()
	for _, status := range []int{200, 410, 413, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			h := evSetup(t, 0)
			id := evSub(t, h, evReq(alice.String(), "")).ID
			h.sender.receipt = eventdelivery.Receipt{StatusCode: status, RetryAfter: 15 * time.Minute}
			evLive(h, alice, alice, "retry", h.clock.Now())
			evDispatch(t, h)
			first := h.sender.requests()[0]
			mon := evMon(t, h, id)
			if mon.SummaryCompleted != nil || mon.UserNotified != nil {
				t.Fatal("receipt falsely became Dot summary/push proof")
			}
			if status == 200 {
				if mon.Accepted != 1 || mon.Pending != 0 {
					t.Fatal(mon)
				}
				return
			}
			if status == 410 || status == 413 {
				evDispatch(t, h)
				if len(h.sender.requests()) != 1 || evMon(t, h, id).Pending != 0 {
					t.Fatal("terminal HTTP response retried")
				}
				return
			}
			evDispatch(t, h)
			if len(h.sender.requests()) != 1 {
				t.Fatal("retry delay ignored")
			}
			h.clock.Add(16 * time.Minute)
			if err := h.s.Close(ctx); err != nil {
				t.Fatal(err)
			}
			var err error
			h.s, err = NewEventService(h.cfg)
			if err != nil {
				t.Fatal(err)
			}
			evDispatch(t, h)
			sent := h.sender.requests()
			if len(sent) != 2 || sent[1].EventID != first.EventID || !bytes.Equal(sent[1].Body, first.Body) {
				t.Fatal("restart/retry changed issued ID/body or lost durable work")
			}
			for i := 0; i < 10; i++ {
				h.clock.Add(16 * time.Minute)
				evDispatch(t, h)
			}
			if len(h.sender.requests()) > 10 || evMon(t, h, id).Pending != 0 {
				t.Fatal("retry exhaustion invisible/unbounded")
			}
		})
	}
	h := evSetup(t, 2)
	id := evSub(t, h, evReq(alice.String(), "")).ID
	for i := 0; i < 3; i++ {
		evLive(h, alice, alice, fmt.Sprint("overflow", i), h.clock.Now())
	}
	mon := evMon(t, h, id)
	if mon.State != "failed" || mon.Overflow == 0 || mon.Pending != 0 {
		t.Fatal("overflow reported active or hid gap")
	}
	if n, err := h.w.store.CountMessages(ctx, alice.String()); err != nil || n != 3 {
		t.Fatal("overflow interrupted archive")
	}
	h.clock.Add(8 * 24 * time.Hour)
	if err := h.s.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	refs, _ := h.keys.ListRefs(ctx)
	if len(refs) != 1 {
		t.Fatal("GC failed to retain only active own access credential")
	}
}

func TestEventsAliasPreservesIssuedAuditAndDedupsUnsent(t *testing.T) {
	h := evSetup(t, 0)
	r := evReq("", "")
	r.Arguments = json.RawMessage(fmt.Sprintf(`{"chat_jids":[%q,%q]}`, bobLID.String(), bob.String()))
	evSub(t, h, r)
	at := h.clock.Now()
	evLive(h, bobLID, bobLID, "same-logical", at)
	evDispatch(t, h)
	first := h.sender.requests()[0]
	evLive(h, bob, bob, "same-logical", at)
	if err := h.w.Client.Store.LIDs.PutLIDMapping(context.Background(), bobLID, bob); err != nil {
		t.Fatal(err)
	}
	evDispatch(t, h)
	if len(h.sender.requests()) != 1 {
		t.Fatal("alias merge sent unsent logical duplicate of acknowledged event")
	}
	var body []byte
	if err := h.w.store.db.QueryRow(`SELECT body_bytes FROM mcp_event_outbox WHERE event_id=?`, first.EventID).Scan(&body); err != nil || !bytes.Equal(body, first.Body) {
		t.Fatal("alias merge rewrote/deleted issued body/audit")
	}
	if _, err := h.w.store.Message(context.Background(), bobLID.String(), "same-logical"); err != nil {
		t.Fatal("historical event JID pointer no longer resolves")
	}
}

func TestEventsWorkerLeaseAndDrainComposition(t *testing.T) {
	h := evSetup(t, 0)
	ctx := context.Background()
	evSub(t, h, evReq(alice.String(), ""))
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.sender.beforeSend = func() { entered <- struct{}{}; <-release }
	evLive(h, alice, alice, "inflight", h.clock.Now())
	if err := h.s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("lost postcommit wake/startup scan")
	}
	if n, err := h.s.DispatchOnce(ctx); err == nil && n != 0 {
		t.Fatal("second worker claimed an already leased event")
	}
	done := make(chan error, 1)
	go func() { done <- h.s.Close(ctx) }()
	select {
	case <-done:
		t.Fatal("Close returned while sender still admitted")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("events drain stuck")
	}
	if len(h.sender.requests()) != 1 {
		t.Fatal("more than one admitted send")
	}
	if err := h.w.drainAndClose(); err != nil {
		t.Fatal(err)
	}
	h.w.handleEvent(textMsg(alice, alice, "after-close", h.clock.Now(), "late"))
}

// Supply entropy through the existing boundary; the one peer commit is ordered
// after receipt reads on the baseline, creating a genuine stale snapshot.
type receiptSnapshotEntropy struct {
	calls      int
	peerCommit func()
}

func (r *receiptSnapshotEntropy) Read(p []byte) (int, error) {
	r.calls++
	if r.calls == 1 {
		r.peerCommit()
	}
	for i := range p {
		p[i] = 128
	}
	return len(p), nil
}
func TestEventsReceiptSnapshotPreservesSingleExternalEffect(t *testing.T) {
	h := evSetup(t, 0)
	ctx := context.Background()
	id := evSub(t, h, evReq(alice.String(), "")).ID
	evLive(h, alice, alice, "receipt-snapshot", h.clock.Now())
	// Exercise retry jitter on a delivery already attempted once.
	if _, err := h.w.store.db.Exec("UPDATE mcp_event_deliveries SET attempt_count=1"); err != nil {
		t.Fatal(err)
	}
	var path string
	if err := h.w.store.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) {
		t.Fatal("fixture database path is not absolute")
	}
	other, err := securestore.Open(path, false, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	entropy := &receiptSnapshotEntropy{peerCommit: func() {
		if _, e := other.Exec("INSERT INTO mcp_meta(key,value) VALUES('receipt-peer','committed')"); e != nil {
			t.Fatal(e)
		}
	}}
	h.s.cfg.Random = entropy
	hooks := 0
	h.s.cfg.Hooks = &EventHooks{BeforeReceiptCommit: func(context.Context, string) error { hooks++; return nil }}
	h.sender.receipt = eventdelivery.Receipt{StatusCode: 500}
	puts := h.keys.n
	verifies := len(h.sender.verifyCalls)
	if _, err := h.s.DispatchOnce(ctx); err != nil {
		t.Fatalf("receipt snapshot must recover without resending: %v", err)
	}
	if len(h.sender.requests()) != 1 || hooks != 1 || entropy.calls != 1 || h.keys.n != puts || len(h.sender.verifyCalls) != verifies {
		t.Fatalf("external effect replayed: sends=%d hook=%d entropy=%d", len(h.sender.requests()), hooks, entropy.calls)
	}
	var state, code string
	var attempts int
	if err := h.w.store.db.QueryRow("SELECT state,last_error_code,attempt_count FROM mcp_event_deliveries WHERE subscription_id=?", id).Scan(&state, &code, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || code != "callback_retry" || attempts != 2 {
		t.Fatalf("receipt state=%q code=%q attempts=%d", state, code, attempts)
	}
	if n := evCount(t, h, "mcp_event_outbox"); n != 1 {
		t.Fatalf("outbox duplicated: %d", n)
	}
	if _, err := h.s.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(h.sender.requests()) != 1 {
		t.Fatal("receipt retry bypassed its durable delay")
	}
}
