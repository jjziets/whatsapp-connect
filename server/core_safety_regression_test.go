//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hansen/whatsapp-mcp/internal/securestore"
)

func TestCoreSafetyConcurrentChatsComplete(t *testing.T) {
	w, _ := archiveFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.store.SetChatName(ctx, alice.String(), false, "Alice"); err != nil {
		t.Fatal(err)
	}
	w.store.namesMu.Lock()
	type result struct {
		chats []*ChatRow
		err   error
	}
	done := make(chan result, 4)
	started := make(chan struct{}, 4)
	for i := 0; i < 4; i++ {
		go func() { started <- struct{}{}; chats, err := w.store.Chats(ctx); done <- result{chats, err} }()
	}
	for i := 0; i < 4; i++ {
		<-started
	}
	// The old implementation reaches four held rows; a repaired prefetch may
	// instead wait on namesMu before acquiring any connection. Both are legal.
	until := time.Now().Add(200 * time.Millisecond)
	for w.store.db.Stats().InUse < 4 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	t.Logf("releasing real namesMu scheduling barrier: %+v", w.store.db.Stats())
	w.store.namesMu.Unlock()
	guard := time.NewTimer(time.Second)
	defer guard.Stop()
	for i := 0; i < 4; i++ {
		select {
		case got := <-done:
			if got.err != nil {
				t.Errorf("concurrent Chats: %v", got.err)
			}
			if len(got.chats) != 1 || got.chats[0].JID != alice.String() || got.chats[0].Name != "Alice" {
				t.Errorf("real concurrent result: %+v", got.chats)
			}
		case <-guard.C:
			t.Errorf("ordinary concurrent Chats exhausted the four-connection pool after namesMu release: %+v", w.store.db.Stats())
			cancel()
			return
		}
	}
}

// A missing interface on the old source is an explicit capability RED rather
// than a compile failure that would hide the independent concurrent-read RED.
type coreHistoryLifecycle interface {
	historyIdleReady(now, started time.Time, idle time.Duration) bool
	drainAndClose() error
}

func TestCoreSafetyActiveHistoryDrainsBeforeClose(t *testing.T) {
	w, path := archiveFixture(t)
	w.store.namesMu.Lock()
	var release sync.Once
	unlock := func() { release.Do(w.store.namesMu.Unlock) }
	defer unlock()
	imported := make(chan struct{})
	go func() {
		w.ingestHistory(context.Background(), archiveChunk(alice, archiveWeb(alice, alice, "SAFE-PENDING", t0, archiveText("received history must survive cleanup"))))
		close(imported)
	}()
	until := time.Now().Add(time.Second)
	present := 0
	for time.Now().Before(until) {
		if err := w.store.db.QueryRow(`SELECT COUNT(*) FROM mcp_chats WHERE jid=?`, alice.String()).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if present == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if present != 1 {
		t.Fatal("actual importer did not commit metadata before scheduling pause")
	}
	lifecycle, ok := any(w).(coreHistoryLifecycle)
	if !ok {
		unlock()
		<-imported
		t.Fatal("missing history lifecycle capability: production idle guard and admitted-work drain are required; original Astra cleanup-loss runtime proof retained separately")
	}
	now := time.Now().Add(time.Hour)
	if lifecycle.historyIdleReady(now, now.Add(-2*time.Hour), time.Second) {
		t.Error("idle policy became ready while actual received history chunk remains active")
	}
	closed := make(chan error, 1)
	go func() { closed <- lifecycle.drainAndClose() }()
	select {
	case err := <-closed:
		t.Fatalf("cleanup closed/returned before admitted history finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := w.store.db.PingContext(context.Background()); err != nil {
		t.Fatalf("archive closed before admitted history could finish: %v", err)
	}
	unlock()
	select {
	case <-imported:
	case <-time.After(time.Second):
		t.Fatal("admitted history did not finish")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup did not complete after importer drained")
	}
	if err := lifecycle.drainAndClose(); err != nil {
		t.Errorf("repeated cleanup must be safe: %v", err)
	}
	if err := w.store.db.PingContext(context.Background()); err == nil {
		t.Error("drained cleanup must close the owning database")
	}
	db, err := securestore.Open(filepath.Clean(path), false, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := NewStore(db)
	message, err := st.Message(context.Background(), alice.String(), "SAFE-PENDING")
	if err != nil {
		t.Fatal(err)
	}
	if message.Text != "received history must survive cleanup" {
		t.Errorf("admitted received message was lost: %+v", message)
	}
	telemetry, err := st.IngestTelemetry(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if telemetry.HistoryReceived != 1 || telemetry.HistoryInserted != 1 || telemetry.HistoryFailed != 0 || telemetry.LastHistoryStatus != "complete" {
		t.Errorf("durable chunk outcomes disagree after drain: %+v", telemetry)
	}
}
