//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hansen/whatsapp-mcp/internal/securestore"
	"github.com/rs/zerolog"
	"go.mau.fi/whatsmeow/proto/waHistorySync"
)

func spReader(t *testing.T, path string) *App {
	t.Helper()
	db, err := securestore.Open(path, true, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &App{store: NewStore(db), mode: "fixture-reader"}
}
func spMeta(t *testing.T, st *Store, key string) map[string]any {
	t.Helper()
	var raw string
	if err := st.db.QueryRow(`SELECT value FROM mcp_meta WHERE key=?`, key).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	return got
}
func spCoverage(t *testing.T, app *App, chat string) map[string]any {
	t.Helper()
	_, out, err := app.getChat(context.Background(), nil, GetChatIn{Chat: chat})
	if err != nil {
		t.Fatal(err)
	}
	return spObject(t, spJSON(t, out), "evidence_coverage")
}

// SP-05/07 and B-REVIEW-03: construction is not ownership. Exercise the exact
// runServe composition, a genuinely separate read-only SQLCipher handle, and
// cleanup before owner-lock reacquisition. No fabricated owner token.
func TestSyncProgressOwnedLifetimeAndReader(t *testing.T) {
	w, path := archiveFixture(t)
	var count int
	if err := w.store.db.QueryRow(`SELECT COUNT(*) FROM mcp_meta WHERE key='sync_progress_v1'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("newWA constructor published without serve ownership")
	}
	if err := w.drainAndClose(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if err := os.Rename(path, dbPath(dir)); err != nil {
		t.Fatal(err)
	}
	app, cleanup, err := openForServeWith(context.Background(), dir, zerolog.Nop(), ServeDependencies{ArchiveKeys: evArchiveKeys{}, Connect: func(context.Context, *WA) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	reader := spReader(t, dbPath(dir))
	observed := spStatus(t, reader)
	spWant(t, observed, "connected", false)
	p := spObject(t, observed, "sync_progress")
	owner := spObject(t, p, "owner")
	spWant(t, owner, "role", "archive_reader")
	spWant(t, owner, "freshness", "fresh")
	spWant(t, spObject(t, p, "media"), "callable_here", false)
	before := spMeta(t, app.store, "sync_progress_v1")
	for i := 0; i < 3; i++ {
		spStatus(t, reader)
	}
	after := spMeta(t, app.store, "sync_progress_v1")
	if before["revision"] != after["revision"] {
		t.Error("archive-reader status wrote a revision")
	}
	cleanup()
	stopped := spObject(t, spObject(t, spStatus(t, reader), "sync_progress"), "owner")
	spWant(t, stopped, "freshness", "stopped")
	spWant(t, stopped, "connected", nil)
	raw := spMeta(t, reader.store, "sync_progress_v1")
	stoppedRevision := raw["revision"]
	lock, err := acquireLock(dir)
	if err != nil {
		t.Fatal("cleanup returned before lock release")
	}
	defer lock.Close()
	// Every snapshot after cleanup must remain stopped; no goroutine may restart
	// a heartbeat after the old DB/owner-lock lifetime has ended.
	if later := spMeta(t, reader.store, "sync_progress_v1"); later["revision"] != stoppedRevision {
		t.Error("publisher wrote after cleanup")
	}
}

// B-REVIEW-01: stale/replaced owner A's currently_processing must not be made
// active by owner B's heartbeat while B processes a different chat. Historical
// timestamps remain useful evidence and must survive the session boundary.
func TestSyncProgressPerChatSessionFreshness(t *testing.T) {
	for _, tc := range []struct {
		name, chatSession string
		age               time.Duration
		want              any
	}{
		{"same-session", "session-B", 0, true}, {"replaced-session", "session-A", 0, nil}, {"stale-session", "session-B", -16 * time.Second, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, w := setup(t)
			now := time.Now().UTC()
			heartbeat := now.Add(tc.age).Format(time.RFC3339Nano)
			historical := now.Add(-time.Hour).Format(time.RFC3339Nano)
			spSeed(t, w, map[string]any{"schema_version": 1, "revision": 22, "session_id": "session-B", "observed_at": heartbeat, "owner": map[string]any{"heartbeat_at": heartbeat, "connected": true, "stopped": false}, "history": map[string]any{"phase": "processing"}, "media": map[string]any{"active_count": 0, "jobs": []any{}}})
			perchat := map[string]any{"schema_version": 1, "session_id": tc.chatSession, "observed_at": heartbeat, "currently_processing": true, "last_observed_history_at": historical, "last_successful_ingest_at": historical}
			raw, _ := json.Marshal(perchat)
			if _, err := w.store.db.Exec(`INSERT INTO mcp_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, "sync_progress_chat_v1:"+group.String(), string(raw)); err != nil {
				t.Fatal(err)
			}
			ingest := spObject(t, spCoverage(t, &App{store: w.store, mode: "reader"}, group.String()), "ingest")
			spWant(t, ingest, "currently_processing", tc.want)
			spWant(t, ingest, "last_observed_history_at", historical)
			spWant(t, ingest, "last_successful_ingest_at", historical)
			unrelated := spObject(t, spCoverage(t, &App{store: w.store, mode: "reader"}, bob.String()), "ingest")
			spWant(t, unrelated, "currently_processing", nil)
			spWant(t, unrelated, "last_observed_history_at", nil)
		})
	}
}

// SP-03/06: checkpoint is an inert observer called only after the actual
// message transaction/counter boundary. Status reads use another encrypted DB
// handle while two real history chunks are paused before terminal summaries.
func TestSyncProgressConcurrentMidIngest(t *testing.T) {
	app, _, dir := evOwnedApp(t)
	w := app.wa
	reader := spReader(t, dbPath(dir))
	control, ok := any(w).(interface {
		setProgressTestClock(func() time.Time, <-chan time.Time)
		flushSyncProgress(context.Context) error
	})
	if !ok {
		t.Fatal("MISSING INERT SEAM: progress clock/flush")
	}
	clockNow := time.Now().UTC().Add(-2 * time.Second)
	var clockMu sync.Mutex
	ticks := make(chan time.Time, 1)
	control.setProgressTestClock(func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clockNow }, ticks)
	hook, ok := any(w).(interface{ setHistoryCheckpoint(func()) })
	if !ok {
		t.Fatal("MISSING INERT SEAM: setHistoryCheckpoint; this is not behavioral RED")
	}
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	reached := make(chan struct{}, 2)
	hook.setHistoryCheckpoint(func() { reached <- struct{}{}; <-release })
	chunk := func(id string) *waHistorySync.HistorySync {
		return archiveChunk(group, archiveWeb(group, alice, id, t0, archiveText("CANARY_PRIVATE_HISTORY")))
	}
	done := make(chan struct{}, 2)
	for _, id := range []string{"SP-CONCURRENT-A", "SP-CONCURRENT-B"} {
		go func(id string) { w.ingestHistory(context.Background(), chunk(id)); done <- struct{}{} }(id)
	}
	spAwait(t, reached)
	spAwait(t, reached)
	// The publisher may coalesce in-flight counts for up to one second.
	// Advance controlled time and drain that eligible tick before asserting
	// cross-process observations; flush is a handshake, not a cadence bypass.
	clockMu.Lock()
	clockNow = clockNow.Add(time.Second)
	at := clockNow
	clockMu.Unlock()
	ticks <- at
	if err := control.flushSyncProgress(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Both checkpoint transactions committed before either terminal summary.
	var archived int
	if err := reader.store.db.QueryRow(`SELECT COUNT(*) FROM mcp_messages WHERE chat_jid=?`, group.String()).Scan(&archived); err != nil || archived != 2 {
		t.Fatalf("mid-ingest actual persisted messages=%d err=%v", archived, err)
	}
	started := time.Now()
	got := spStatus(t, reader)
	if time.Since(started) >= time.Second {
		t.Error("status blocked behind history ingestion")
	}
	processing := spObject(t, spObject(t, spObject(t, got, "sync_progress"), "history"), "processing")
	spWant(t, processing, "active_chunks", float64(2))
	spWant(t, processing, "observed_total_messages", float64(2))
	spWant(t, processing, "processed_messages", float64(2))
	spWant(t, processing, "inserted", float64(2))
	unblock()
	spAwait(t, done)
	spAwait(t, done)
}

// SP-05/06: fake time drives deterministic heartbeat and coalescing; a busy
// real SQLite writer must not cause unbounded publish or make last success
// perpetually fresh. Missing clock/flush APIs are seam evidence, not RED.
func TestSyncProgressClockAndBusyPublication(t *testing.T) {
	app, _, dir := evOwnedApp(t)
	w := app.wa
	reader := spReader(t, dbPath(dir))
	control, ok := any(w).(interface {
		setProgressTestClock(func() time.Time, <-chan time.Time)
		flushSyncProgress(context.Context) error
	})
	if !ok {
		t.Fatal("MISSING INERT SEAM: progress clock/flush; this is not behavioral RED")
	}
	now := time.Now().UTC()
	ticks := make(chan time.Time, 2)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	control.setProgressTestClock(clock, ticks)
	if err := control.flushSyncProgress(context.Background()); err != nil {
		t.Fatal(err)
	}
	old := spMeta(t, reader.store, "sync_progress_v1")["revision"].(float64)
	mu.Lock()
	now = now.Add(5 * time.Second)
	at := now
	mu.Unlock()
	ticks <- at
	if err := control.flushSyncProgress(context.Background()); err != nil {
		t.Fatal(err)
	}
	latest := spMeta(t, reader.store, "sync_progress_v1")["revision"].(float64)
	if latest <= old {
		t.Error("idle heartbeat did not advance revision")
	}
	writer, err := securestore.Open(dbPath(dir), false, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	tx, err := writer.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE mcp_meta SET value=value WHERE key='sync_progress_v1'`); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(5 * time.Second)
	eligible := now
	mu.Unlock()
	ticks <- eligible
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = control.flushSyncProgress(ctx)
	if err == nil {
		t.Error("busy writer publication unexpectedly succeeded")
	}
	if time.Since(start) > time.Second {
		t.Error("busy writer publication exceeded bounded deadline")
	}
	if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
		t.Fatal(err)
	}
}

// SP-10/11: empty known chat != unknown chat, and instructions explicitly
// protect against treating unexamined media or empty archive matches as quiet.
func TestSyncProgressCoverageEmptyAndInstructions(t *testing.T) {
	w, _ := archiveFixture(t)
	if err := w.store.SetChatName(context.Background(), group.String(), true, "Synthetic fixture"); err != nil {
		t.Fatal(err)
	}
	app := &App{store: w.store, mode: "reader"}
	cov := spCoverage(t, app, group.String())
	a := spObject(t, cov, "archive")
	spWant(t, a, "archived_message_count", float64(0))
	spWant(t, a, "oldest_archived_message_at", nil)
	spWant(t, a, "newest_archived_message_at", nil)
	m := spObject(t, cov, "attachments")
	spWant(t, m, "reference_count", float64(0))
	spWant(t, m, "read_status", "unknown")
	if _, _, err := app.getChat(context.Background(), nil, GetChatIn{Chat: "unknown-fixture@g.us"}); err == nil {
		t.Error("unknown chat invented archive coverage")
	}
	lower := strings.ToLower(instructions)
	for _, term := range []string{"evidence_coverage", "unread", "quiet", "archived evidence"} {
		if !strings.Contains(lower, term) {
			t.Errorf("tool instructions omit %q evidence limit", term)
		}
	}
}
