//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
)

// Prevent non-cancelable SDK lock queues and DB-close races: one owner operation
// may dispatch; another request is rejected before its durable reservation.
func TestOwnerMessageCancellationBusyAndDrain(t *testing.T) {
	a, f := messageApp(t)
	p := previewMessage(t, a, "cancel-active", alice.String(), "")
	other := previewMessage(t, a, "busy-other", alice.String(), "")
	entered := make(chan struct{})
	f.send = func(c context.Context, _ types.JID, _ *waE2E.Message, _ ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
		close(entered)
		<-c.Done()
		return whatsmeow.SendResponse{}, c.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, s, e := a.sendText(ctx, nil, p)
		if e == nil && s.State != "outcome_unknown" {
			e = errors.New("canceled dispatch did not settle unknown")
		}
		done <- e
	}()
	select {
	case <-entered:
	case e := <-done:
		t.Fatalf("SDK was not entered: %v", e)
	case <-time.After(time.Second):
		t.Fatal("dispatch blocked")
	}
	if _, _, e := a.sendText(context.Background(), nil, other); e == nil {
		t.Fatal("second dispatch queued/accepted")
	}
	s, e := a.store.sendStatus(context.Background(), other.RequestID)
	if e != nil || s.State != "unknown" {
		t.Fatalf("busy request reserved: %+v %v", s, e)
	}
	// Replaying an in-flight request is a status operation, unaffected by busy gate.
	if s := sendMessage(t, a, p); s.State != "dispatching" {
		t.Fatal(s)
	}
	closed := make(chan struct{})
	go func() { a.wa.drainAndClose(); close(closed) }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not cancel/drain bounded dispatch")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("database close failed to drain")
	}
	if f.calls.Load() != 1 {
		t.Fatal("unexpected second SDK invocation")
	}
}

func TestOwnerMessageOwnerHTTPAuthAndRequestCancel(t *testing.T) {
	a, f := messageApp(t)
	p := previewMessage(t, a, "http-cancel", alice.String(), "")
	key := bytes.Repeat([]byte{0x42}, 32)
	token := "Bearer " + base64.RawURLEncoding.EncodeToString(key)
	root, stop := context.WithCancel(context.Background())
	defer stop()
	rt, e := startOwnerHTTP(root, a, "127.0.0.1:0", OwnerHTTPDependencies{ReadKey: func() ([]byte, error) { return key, nil }})
	if e != nil {
		t.Fatal(e)
	}
	defer rt.Close(context.Background())
	tools := c4Do(c4Request(root, rt.URL(), token, c4Version, "tools/list", c4Params("")))
	if tools.status != http.StatusOK || tools.err != nil ||
		!strings.Contains(tools.body, `"prepare_media_forward"`) || !strings.Contains(tools.body, `"forward_media"`) {
		t.Fatalf("the authenticated active owner must have the media tool pair: %+v", tools)
	}
	badMedia := c4Do(c4Request(root, rt.URL(), "", c4Version, "tools/call", c4Params("forward_media")))
	if badMedia.status != http.StatusUnauthorized || f.calls.Load() != 0 {
		t.Fatalf("unauthenticated media request reached the owner handler: %+v", badMedia)
	}
	raw, _ := json.Marshal(p)
	var args map[string]any
	json.Unmarshal(raw, &args)
	params := c4Params("send_text")
	params["arguments"] = args
	bad := c4Do(c4Request(root, rt.URL(), "", c4Version, "tools/call", params))
	if bad.status != http.StatusUnauthorized || f.calls.Load() != 0 {
		t.Fatalf("unauthenticated dispatch %+v", bad)
	}
	entered := make(chan struct{})
	finished := make(chan struct{})
	f.send = func(ctx context.Context, _ types.JID, _ *waE2E.Message, _ ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
		close(entered)
		<-ctx.Done()
		close(finished)
		return whatsmeow.SendResponse{}, ctx.Err()
	}
	request, cancel := context.WithCancel(root)
	defer cancel()
	result := make(chan c4Wire, 1)
	go func() { result <- c4Do(c4Request(request, rt.URL(), token, c4Version, "tools/call", params)) }()
	select {
	case <-entered:
	case got := <-result:
		t.Fatalf("actual HTTP send not entered: %+v", got)
	case <-time.After(time.Second):
		t.Fatal("request stalled")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("HTTP request cancellation detached")
	}
	<-result
	deadline := time.Now().Add(time.Second)
	for {
		s, e := a.store.sendStatus(context.Background(), p.RequestID)
		if e != nil {
			t.Fatal(e)
		}
		if s.State == "outcome_unknown" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("HTTP cancellation unsettled: %+v", s)
		}
		runtime.Gosched()
	}
	if s := sendMessage(t, a, p); s.State != "outcome_unknown" || f.calls.Load() != 1 {
		t.Fatal("HTTP retry resent")
	}
	if _, _, e := a.prepareMessage(root, nil, PrepareMessageArgs{ChatJID: alice.String(), Text: "still alive"}); e != nil {
		t.Fatal("single cancel killed owner")
	}
}

func TestOwnerMessageHistorySharesDispatchAdmission(t *testing.T) {
	a, f := messageApp(t)
	p := previewMessage(t, a, "history-busy", alice.String(), "")
	entered := make(chan struct{})
	release := make(chan struct{})
	f.send = func(ctx context.Context, to types.JID, m *waE2E.Message, e ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
		if len(e) != 1 || !e[0].Peer || to != a.wa.ownJID() {
			t.Error("history peer call no longer matches pinned SendPeerMessage")
		}
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return whatsmeow.SendResponse{}, ctx.Err()
		}
		return whatsmeow.SendResponse{}, nil
	}
	done := make(chan error, 1)
	go func() { done <- a.wa.RequestOlderHistory(context.Background(), alice, 20) }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("history did not use shared SDK boundary: %v", err)
	case <-time.After(time.Second):
		t.Fatal("history stalled")
	}
	if _, _, err := a.sendText(context.Background(), nil, p); err == nil {
		t.Fatal("new message queued behind peer SDK lock")
	}
	s, _ := a.store.sendStatus(context.Background(), p.RequestID)
	if s.State != "unknown" {
		t.Fatal("busy peer reserved message")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Models the pinned SDK's non-cancelable mutex wait. Never close storage under
// an unresolved SDK call, even when the request/shutdown context is canceled.
func TestOwnerMessageUncooperativeSDKRetainsStore(t *testing.T) {
	a, f := messageApp(t)
	p := previewMessage(t, a, "sdk-lock-held", alice.String(), "")
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	f.send = func(context.Context, types.JID, *waE2E.Message, ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
		close(entered)
		<-release
		return whatsmeow.SendResponse{}, context.Canceled
	}
	sent := make(chan struct{})
	go func() { defer close(sent); sendMessage(t, a, p) }()
	<-entered
	closed := make(chan struct{})
	go func() { a.wa.drainAndClose(); close(closed) }()
	deadline := time.Now().Add(time.Second)
	for {
		a.wa.lifecycleMu.Lock()
		closing := a.wa.closing
		a.wa.lifecycleMu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("shutdown not entered")
		}
		runtime.Gosched()
	}
	select {
	case <-closed:
		t.Fatal("closed DB while SDK unresolved")
	default:
	}
	if e := a.store.db.Ping(); e != nil {
		t.Fatal("active SDK lost DB")
	}
	once.Do(func() { close(release) })
	select {
	case <-sent:
	case <-time.After(time.Second):
		t.Fatal("send failed to settle after SDK returned")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("owner failed to finish drain")
	}
}
