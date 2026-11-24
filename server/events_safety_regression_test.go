//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hansen/whatsapp-mcp/internal/eventdelivery"
	"github.com/hansen/whatsapp-mcp/internal/eventsecrets"
)

// FA-001: persistent initialized SDK GET must be stopped by server shutdown,
// never by asking the client to disconnect. A deadline may leave admitted work
// draining, but cannot release DB/lock early or prevent a later Close retry.
func TestEventsSafetySDKStreamAndDeadlineDrain(t *testing.T) {
	h, rt, srv, dir := evCompose(t)
	session := evSession(t, srv.URL, h.token)
	getCtx, cancelGET := context.WithCancel(context.Background())
	t.Cleanup(cancelGET)
	req, _ := http.NewRequestWithContext(getCtx, "GET", srv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Mcp-Session-Id", session)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-03-26")
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
		}
	}()
	evWait(t, "initialized SDK GET admitted", func() bool { h.s.mu.Lock(); defer h.s.mu.Unlock(); return h.s.ops > 0 })
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	h.sender.verifyHook = func(context.Context, string, string, string) error { close(entered); <-release; return nil }
	payload, _ := json.Marshal(evReq(alice.String(), ""))
	post, _ := http.NewRequest("POST", srv.URL, bytes.NewReader(append([]byte(`{"jsonrpc":"2.0","id":77,"method":"events/subscribe","params":`), append(payload, byte('}'))...)))
	post.Header.Set("Authorization", "Bearer "+h.token)
	post.Header.Set("Mcp-Session-Id", session)
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("Accept", "application/json,text/event-stream")
	post.Header.Set("MCP-Protocol-Version", "2025-03-26")
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		resp, err := http.DefaultClient.Do(post)
		if err == nil {
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
		}
	}()
	evAwait(t, entered)
	deadline, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	closed := make(chan error, 1)
	go func() { closed <- rt.Close(deadline) }()
	var closeErr error
	returned := false
	select {
	case closeErr = <-closed:
		returned = true
	case <-time.After(250 * time.Millisecond):
		t.Error("Close ignored deadline while admitted HTTP operation/SDK stream remained")
	}
	if returned && !errors.Is(closeErr, context.DeadlineExceeded) {
		t.Errorf("blocked admitted verifier should yield deadline, got %v", closeErr)
	}
	if returned {
		if err := h.w.store.db.Ping(); err != nil {
			t.Error("DB closed before admitted verifier drained")
		}
		if lock, err := acquireLock(dir); err == nil {
			lock.Close()
			t.Error("owner lock released before admitted verifier drained")
		}
	}
	select {
	case <-streamDone:
	case <-time.After(250 * time.Millisecond):
		t.Error("SDK stream required client-initiated cancellation")
		cancelGET() /* failure cleanup only */
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Error("admitted verifier did not finish")
	}
	if !returned {
		cancelGET()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("failed Close could not recover for cleanup")
		}
	}
	retry := make(chan error, 1)
	go func() { retry <- rt.Close(context.Background()) }()
	select {
	case err := <-retry:
		if err != nil {
			t.Errorf("repeat Close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("repeat Close did not finish drain")
	}
	if err := h.w.store.db.Ping(); err == nil {
		t.Error("drained runtime did not close DB")
	}
	if lock, err := acquireLock(dir); err != nil {
		t.Errorf("drained runtime retained owner lock: %v", err)
	} else {
		lock.Close()
	}
}

type safetyGateKeys struct {
	eventsecrets.EventSecretProvider
	ref              string
	entered, release chan struct{}
	once             sync.Once
}

func (k *safetyGateKeys) Get(ctx context.Context, ref string) ([]byte, error) {
	key, err := k.EventSecretProvider.Get(ctx, ref)
	if ref == k.ref {
		k.once.Do(func() { close(k.entered); <-k.release })
	}
	return key, err
}

// FA-002: a legal implementation may reload safely or requeue a stale claim.
// Either way, no obsolete key may reach Send and skipped stale admission must
// not consume a callback attempt or change immutable event identity/body.
func TestEventsSafetyRotationAdmission(t *testing.T) {
	for _, gated := range []bool{false, true} {
		t.Run(fmt.Sprint("gated-native-get=", gated), func(t *testing.T) {
			h := evSetup(t, 10000)
			ctx := context.Background()
			r := evReq(alice.String(), "")
			sub := evSub(t, h, r)
			evLive(h, alice, alice, "rotation-admission", h.clock.Now())
			jobs, err := h.s.claim(ctx)
			if err != nil || len(jobs) != 1 {
				t.Fatalf("claim count=%d err=%v", len(jobs), err)
			}
			j := jobs[0]
			done := make(chan error, 1)
			var gate *safetyGateKeys
			var unblock sync.Once
			if gated {
				gate = &safetyGateKeys{EventSecretProvider: h.keys, ref: j.key, entered: make(chan struct{}), release: make(chan struct{})}
				h.s.cfg.Secrets = gate
				t.Cleanup(func() { unblock.Do(func() { close(gate.release) }) })
				go func() { done <- h.s.runJob(ctx, j) }()
				evAwait(t, gate.entered)
			}
			for _, value := range []byte{0x32, 0x33} {
				r.Delivery.Secret = "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
				evSub(t, h, r)
			}
			if gated {
				unblock.Do(func() { close(gate.release) })
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("gated key read/rotation deadlock")
				}
			} else {
				if err := h.s.runJob(ctx, j); err != nil {
					t.Fatal(err)
				}
			}
			current := r.Delivery.Secret
			grace := "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32))
			check := func() {
				for _, q := range h.sender.requests() {
					if q.EventID != j.event || !bytes.Equal(q.Body, j.body) {
						t.Error("rotation changed issued event/body")
					}
					if len(q.Secrets) != 2 || q.Secrets[0] != current || q.Secrets[1] != grace {
						t.Error("obsolete signing generation reached Send")
					}
				}
			}
			check()
			for i := 0; len(h.sender.requests()) == 0 && i < 3; i++ {
				h.clock.Add(time.Second)
				evDispatch(t, h)
			}
			check()
			if len(h.sender.requests()) != 1 || evMon(t, h, sub.ID).Accepted != 1 {
				t.Error("stale requeue did not eventually deliver one immutable event")
			}
			var attempts int
			if err := h.w.store.db.QueryRow(`SELECT attempt_count FROM mcp_event_deliveries WHERE subscription_id=? AND event_id=?`, sub.ID, j.event).Scan(&attempts); err != nil {
				t.Fatal(err)
			}
			if attempts != 1 {
				t.Errorf("stale admission burned callback attempts: %d", attempts)
			}
		})
	}
}

// FA-003: observe actual B Send while >128 earlier A jobs are queued and A is
// held in flight. Spare worker slots must not be hidden by A's due backlog.
func TestEventsSafetyFairMonitorHeads(t *testing.T) {
	h := evSetup(t, 10000)
	ctx := context.Background()
	a := evSub(t, h, evReq(alice.String(), ""))
	b := evSub(t, h, evReq(bob.String(), ""))
	for i := 0; i < 130; i++ {
		evLive(h, alice, alice, fmt.Sprintf("head-a-%03d", i), h.clock.Now())
	}
	h.clock.Add(time.Millisecond)
	evLive(h, bob, bob, "head-b", h.clock.Now())
	aEntered := make(chan struct{})
	release := make(chan struct{})
	bEntered := make(chan struct{}, 1)
	var once, releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	h.sender.enter = func(q eventdelivery.Request) func() {
		if q.SubscriptionID == a.ID {
			once.Do(func() { close(aEntered) })
			<-release
		}
		if q.SubscriptionID == b.ID {
			select {
			case bEntered <- struct{}{}:
			default:
			}
		}
		return nil
	}
	if err := h.s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	evAwait(t, aEntered)
	select {
	case <-bEntered:
	case <-time.After(time.Second):
		t.Error("busy A hid due B despite three free worker slots")
	}
	releaseOnce.Do(func() { close(release) })
}

// F-FINAL-VERIFIER-001 / REQ-WC-009: actual wire instructions, not only runbook.
func TestEventsSafetyInitializeSourceInstructions(t *testing.T) {
	h, _, srv, _ := evCompose(t)
	out, _, status := evRPC(t, srv.URL, h.token, "", "initialize", 1, map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "source-instructions", "version": "1"}})
	if status != 200 {
		t.Fatal(status)
	}
	text, _ := out["result"].(map[string]any)["instructions"].(string)
	text = strings.ToLower(text)
	for _, needle := range []string{"untrusted", "embedded", "instructions", "autonomous", "reply", "owner"} {
		if !strings.Contains(text, needle) {
			t.Errorf("wire instructions omit %q trust/reply boundary", needle)
		}
	}
}
