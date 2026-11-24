//go:build libsqlite3

package main

// B-SOURCE-01..03: real archive/provider/alias boundaries; synthetic data only.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hansen/whatsapp-mcp/internal/securestore"
	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/types"
)

func TestSyncProgressRepairLargeTerminalDrain(t *testing.T) {
	t.Run("real-300-chat-chunk-stop-reopen", func(t *testing.T) {
		app, cleanup, dir := evOwnedApp(t)
		w := app.wa
		now := time.Now().UTC().Add(-2 * time.Second)
		w.setProgressTestClock(func() time.Time { return now }, make(chan time.Time))
		chunk := &waHistorySync.HistorySync{}
		for i := 0; i < 300; i++ {
			chat := types.NewJID(fmt.Sprintf("120363900%06d", i), types.GroupServer)
			part := archiveChunk(chat, archiveWeb(chat, alice, fmt.Sprintf("DRAIN-%d", i), t0, archiveText("synthetic terminal evidence")))
			chunk.Conversations = append(chunk.Conversations, part.Conversations[0])
		}
		w.ingestHistory(context.Background(), chunk)
		if err := w.drainAndClose(); err != nil {
			t.Fatal(err)
		}
		cleanup()
		reader := spReader(t, dbPath(dir))
		var messages, terminal int
		if err := reader.store.db.QueryRow(`SELECT COUNT(*) FROM mcp_messages`).Scan(&messages); err != nil {
			t.Fatal(err)
		}
		if messages != 300 {
			t.Fatalf("actual chunk archived %d messages", messages)
		}
		if err := reader.store.db.QueryRow(`SELECT COUNT(*) FROM mcp_meta WHERE key LIKE 'sync_progress_chat_v1:%' AND json_extract(value,'$.currently_processing')=0 AND json_extract(value,'$.last_successful_ingest_at') IS NOT NULL`).Scan(&terminal); err != nil {
			t.Fatal(err)
		}
		if terminal != 300 {
			t.Errorf("stop/reopen lost terminal chat observations: got %d want 300", terminal)
		}
	})
	t.Run("busy-shutdown-is-explicit-and-bounded", func(t *testing.T) {
		app, cleanup, dir := evOwnedApp(t)
		defer cleanup()
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
		start := time.Now()
		err = app.wa.drainAndClose()
		if err == nil {
			t.Error("shutdown silently discarded failed progress publication")
		}
		if time.Since(start) > 3*time.Second {
			t.Error("shutdown exceeded explicit bounded drain policy")
		}
	})
}

// A nil observer before terminal reference persistence is the only new seam.
// The existing actual channel gate is inspected only to steer an interleaving:
// if A released it, let B finish first; if A still holds it, resume A first.
// The assertion is final observable coverage, without a third cache-hit repair.
func TestSyncProgressRepairSameReferenceCompletionOrder(t *testing.T) {
	w, _ := archiveFixture(t)
	m, plain, wire := spMediaRef(t, w, "document", "ORDERED-COMPLETION")
	spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(r *http.Request) (*http.Response, error) { return spResponse(r, wire, int64(len(wire))), nil })})
	seam, ok := any(w).(interface{ setMediaFinishForTest(func()) })
	if !ok {
		t.Fatal("MISSING INERT SEAM: media finish observer; not behavioral RED")
	}
	var writes atomic.Int32
	w.setMediaSaveForTest(func(path string, data []byte) error {
		if writes.Add(1) == 1 {
			return errors.New("synthetic first save failure")
		}
		return os.WriteFile(path, data, 0600)
	})
	paused := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var finishes atomic.Int32
	seam.setMediaFinishForTest(func() {
		if finishes.Add(1) == 1 {
			close(paused)
			<-release
		}
	})
	first := spStartDownload(w, context.Background(), m)
	spAwait(t, paused)
	digest := sha256.Sum256([]byte(m.ChatJID + "\x00" + m.ID))
	gate := w.progress.mediaLocks[int(digest[0])%len(w.progress.mediaLocks)]
	// Observe A's gate before starting B, so B cannot change the steering
	// condition and accidentally mask the old completion-order defect.
	firstReleased := len(gate) == 0
	second := spStartDownload(w, context.Background(), m)
	var b spDownloadResult
	if firstReleased {
		b = spResult(t, second)
		unblock()
	} else {
		unblock()
		b = spResult(t, second)
	}
	a := spResult(t, first)
	if a.err == nil || b.err != nil || !bytes.Equal(b.data, plain) {
		t.Fatalf("fixture operation results: first=%v second=%v", a.err, b.err)
	}
	attachments := spObject(t, spCoverage(t, &App{store: w.store, mode: "reader"}, group.String()), "attachments")
	spWant(t, attachments, "cached_downloaded_count", float64(1))
	spWant(t, attachments, "unavailable_failed_count", float64(0))
	spWant(t, attachments, "not_checked_count", float64(0))
}

func TestSyncProgressRepairVerifiedAliasCoverage(t *testing.T) {
	t.Run("observed-media-history-and-conflict", func(t *testing.T) {
		app, _, dir := evOwnedApp(t)
		w := app.wa
		msg, plain, wire := spEncrypted(t, "document", "ALIAS-REFERENCE")
		w.ingestHistory(context.Background(), archiveChunk(bobLID, archiveWeb(bobLID, bobLID, "ALIAS-REFERENCE", t0, msg)))
		old := archiveMessage(t, w, bobLID, "ALIAS-REFERENCE")
		spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(r *http.Request) (*http.Response, error) { return spResponse(r, wire, int64(len(wire))), nil })})
		if _, got, err := w.DownloadMedia(context.Background(), old); err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("real cached LID evidence %v", err)
		}
		reader := spReader(t, dbPath(dir))
		before := spCoverage(t, reader, bobLID.String())
		prior := spObject(t, before, "ingest")
		if prior["last_observed_history_at"] == nil || prior["last_successful_ingest_at"] == nil {
			t.Fatal("fixture did not create real per-chat history observations")
		}
		// The same reference has an observed failed PN attempt before verification.
		archiveIngest(t, w, bob, bob, "ALIAS-REFERENCE", t0, msg, false)
		pn := archiveMessage(t, w, bob, "ALIAS-REFERENCE")
		spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(r *http.Request) (*http.Response, error) {
			resp := spResponse(r, nil, 0)
			resp.StatusCode = 404
			return resp, nil
		})})
		if _, _, err := w.DownloadMedia(context.Background(), pn); err == nil {
			t.Fatal("synthetic PN unavailable attempt succeeded")
		}
		if err := w.store.AcceptAlias(context.Background(), bobLID, bob); err != nil {
			t.Fatal(err)
		}
		after := spCoverage(t, reader, bob.String())
		ingest := spObject(t, after, "ingest")
		spWant(t, ingest, "last_observed_history_at", prior["last_observed_history_at"])
		spWant(t, ingest, "last_successful_ingest_at", prior["last_successful_ingest_at"])
		media := spObject(t, after, "attachments")
		spWant(t, media, "reference_count", float64(1))
		spWant(t, media, "cached_downloaded_count", float64(1))
		spWant(t, media, "unavailable_failed_count", float64(0))
		spWant(t, media, "not_checked_count", float64(0))
		if err := w.store.AcceptAlias(context.Background(), bobLID, alice); err == nil {
			t.Error("conflicting identity mapping accepted")
		}
		// An unaccepted alias cannot contribute evidence to another chat.
		archiveIngest(t, w, alice, alice, "UNRELATED", t0, archiveText("synthetic unrelated"), false)
		unrelated := spCoverage(t, reader, alice.String())
		spWant(t, spObject(t, unrelated, "ingest"), "last_successful_ingest_at", nil)
		spWant(t, spObject(t, unrelated, "attachments"), "reference_count", float64(0))
	})
	t.Run("inflight-old-key-after-alias", func(t *testing.T) {
		app, _, dir := evOwnedApp(t)
		w := app.wa
		reader := spReader(t, dbPath(dir))
		now := time.Now().UTC().Add(-3 * time.Second)
		var clockMu sync.Mutex
		ticks := make(chan time.Time, 1)
		w.setProgressTestClock(func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }, ticks)
		paused := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		w.setHistoryCheckpoint(func() { close(paused); <-release })
		done := make(chan struct{})
		go func() {
			w.ingestHistory(context.Background(), archiveChunk(bobLID, archiveWeb(bobLID, bobLID, "ALIAS-INFLIGHT", t0, archiveText("synthetic in-flight"))))
			close(done)
		}()
		spAwait(t, paused)
		clockMu.Lock()
		now = now.Add(time.Second)
		at := now
		clockMu.Unlock()
		ticks <- at
		if err := w.flushSyncProgress(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := w.store.AcceptAlias(context.Background(), bobLID, bob); err != nil {
			t.Fatal(err)
		}
		active := spObject(t, spCoverage(t, reader, bob.String()), "ingest")
		spWant(t, active, "currently_processing", true)
		unblock()
		spAwait(t, done)
		finished := spObject(t, spCoverage(t, reader, bob.String()), "ingest")
		spWant(t, finished, "currently_processing", false)
		if finished["last_successful_ingest_at"] == nil {
			t.Error("old-address terminal publisher lost verified canonical evidence")
		}
		// Owner-session freshness remains required after alias read-through.
		global := spMeta(t, w.store, progressKey)
		owner := spObject(t, global, "owner")
		owner["heartbeat_at"] = time.Now().Add(-16 * time.Second).UTC().Format(time.RFC3339Nano)
		global["observed_at"] = owner["heartbeat_at"]
		raw, _ := json.Marshal(global)
		if _, err := w.store.db.Exec(`UPDATE mcp_meta SET value=? WHERE key=?`, string(raw), progressKey); err != nil {
			t.Fatal(err)
		}
		stale := spObject(t, spCoverage(t, reader, bob.String()), "ingest")
		spWant(t, stale, "currently_processing", nil)
	})
}
