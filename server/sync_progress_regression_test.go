//go:build libsqlite3

package main

// Definition-only regression contract. SP identifiers are architecture cases,
// never aliases for approved REQ identifiers. All content and keys are synthetic.
import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"google.golang.org/protobuf/proto"
)

func spJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func spObject(t *testing.T, v map[string]any, key string) map[string]any {
	t.Helper()
	m, ok := v[key].(map[string]any)
	if !ok {
		t.Fatalf("missing object %s in %v", key, v)
	}
	return m
}
func spWant(t *testing.T, m map[string]any, key string, want any) {
	t.Helper()
	got, present := m[key]
	if !present || got != want {
		t.Errorf("%s got=%v present=%v want=%v", key, got, present, want)
	}
}
func spStatus(t *testing.T, app *App) map[string]any {
	t.Helper()
	_, out, err := app.status(context.Background(), nil, StatusIn{})
	if err != nil {
		t.Fatal(err)
	}
	return spJSON(t, out)
}
func spSeed(t *testing.T, w *WA, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.store.db.Exec(`INSERT INTO mcp_meta(key,value) VALUES('sync_progress_v1',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(raw)); err != nil {
		t.Fatal(err)
	}
}

// SP-01/07/09: absent means unknown; old fields retain process-local meanings.
func TestSyncProgressAbsentReader(t *testing.T) {
	_, w := setup(t)
	app := &App{store: w.store, mode: "test"}
	got := spStatus(t, app)
	spWant(t, got, "connected", false)
	spWant(t, got, "sync_progress_state", "unknown")
	p := spObject(t, got, "sync_progress")
	owner := spObject(t, p, "owner")
	spWant(t, owner, "role", "archive_reader")
	spWant(t, owner, "freshness", "unknown")
	spWant(t, owner, "connected", nil)
	media := spObject(t, p, "media")
	spWant(t, media, "callable_here", false)
	spWant(t, media, "availability_code", "no_owner_rpc")
	spWant(t, media, "automatic_bulk_download", false)
	history := spObject(t, p, "history")
	spWant(t, history, "provider_reported_percent", nil)
	if _, present := history["archive_complete"]; present {
		t.Error("history must not expose a phone completeness field")
	}
	// Existing reader rejection must remain until separately reviewed Stage C.
	if app.online() == nil {
		t.Error("reader acquired owner access")
	}
}

// SP-01/05/07/08: persisted metadata is not eternal liveness or a trusted JSON
// passthrough. A second DB handle is added in the lifecycle acceptance lane.
func TestSyncProgressReaderSnapshotTrust(t *testing.T) {
	for _, tc := range []struct {
		name             string
		age              time.Duration
		version          int
		state, freshness string
		connected        any
	}{
		{"fresh", 0, 1, "observed", "fresh", true},
		{"stale", -16 * time.Second, 1, "observed", "stale", nil},
		{"future", time.Hour, 1, "unavailable", "unknown", nil},
		{"unsupported", 0, 2, "unavailable", "unknown", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, w := setup(t)
			now := time.Now().UTC().Add(tc.age).Format(time.RFC3339Nano)
			spSeed(t, w, map[string]any{"schema_version": tc.version, "revision": 7, "observed_at": now,
				"owner":      map[string]any{"heartbeat_at": now, "connected": true, "stopped": false},
				"history":    map[string]any{"phase": "processing", "provider_reported_percent": 25},
				"media":      map[string]any{"active_count": 1, "jobs": []any{map[string]any{"operation_id": "opaque-synthetic", "phase": "downloading", "kind": "image", "error": "CANARY_PRIVATE_ERROR", "url": "CANARY_PRIVATE_URL"}}},
				"session_id": "CANARY_INTERNAL_SESSION", "unexpected": "CANARY_RAW_METADATA"})
			got := spStatus(t, &App{store: w.store, mode: "test"})
			spWant(t, got, "sync_progress_state", tc.state)
			p := spObject(t, got, "sync_progress")
			owner := spObject(t, p, "owner")
			spWant(t, owner, "role", "archive_reader")
			spWant(t, owner, "freshness", tc.freshness)
			spWant(t, owner, "connected", tc.connected)
			raw, _ := json.Marshal(p)
			if strings.Contains(string(raw), "CANARY_") {
				t.Error("private/unrecognized persisted metadata reached diagnostics")
			}
			if tc.freshness == "stale" {
				jobs, _ := spObject(t, p, "media")["jobs"].([]any)
				for _, job := range jobs {
					if job.(map[string]any)["phase"] == "downloading" {
						t.Error("stale transfer still presented active")
					}
				}
			}
		})
	}
	t.Run("malformed", func(t *testing.T) {
		_, w := setup(t)
		if _, err := w.store.db.Exec(`INSERT INTO mcp_meta(key,value) VALUES('sync_progress_v1','{') ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
			t.Fatal(err)
		}
		got := spStatus(t, &App{store: w.store, mode: "test"})
		spWant(t, got, "sync_progress_state", "unavailable")
		spWant(t, spObject(t, spObject(t, got, "sync_progress"), "owner"), "connected", nil)
	})
}

// SP-02: test the real protobuf pointer and ingestion path, not a fixture copy
// of the proposed algorithm. Local chunk completion is not phone completeness.
func TestSyncProgressHistoryProviderPresence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		percent *uint32
		want    any
	}{
		{"absent", nil, nil}, {"zero", proto.Uint32(0), float64(0)},
		{"hundred", proto.Uint32(100), float64(100)}, {"invalid", proto.Uint32(101), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, w := setup(t)
			chunk := archiveChunk(group, archiveWeb(group, alice, "SP-H1", t0, textMsg(group, alice, "unused", t0, "synthetic").Message))
			chunk.SyncType = waHistorySync.HistorySync_ON_DEMAND.Enum()
			chunk.Progress = tc.percent
			chunk.ChunkOrder = proto.Uint32(7)
			w.ingestHistory(context.Background(), chunk)
			got := spStatus(t, &App{store: w.store, wa: w, mode: "test"})
			h := spObject(t, spObject(t, got, "sync_progress"), "history")
			spWant(t, h, "provider_reported_percent", tc.want)
			spWant(t, h, "sync_type", "ON_DEMAND")
			spWant(t, h, "chunk_order", float64(7))
			if _, present := h["archive_complete"]; present {
				t.Error("history must not expose a phone completeness field")
			}
			counts := spObject(t, h, "processing")
			spWant(t, counts, "observed_total_messages", float64(1))
			spWant(t, counts, "processed_messages", float64(1))
			spWant(t, counts, "inserted", float64(1))
			// A later chunk without Progress resets provider scope rather than retaining 100.
			w.ingestHistory(context.Background(), &waHistorySync.HistorySync{SyncType: waHistorySync.HistorySync_RECENT.Enum()})
			h = spObject(t, spObject(t, spStatus(t, &App{store: w.store, wa: w, mode: "test"}), "sync_progress"), "history")
			spWant(t, h, "provider_reported_percent", nil)
			spWant(t, h, "sync_type", "RECENT")
		})
	}
}

// SP-04/08: the existing cache path is observable without any network, keychain
// or phone. Cached plaintext size must never be reported as network bytes.
func TestSyncProgressCachedMediaTerminal(t *testing.T) {
	_, w := setup(t)
	m := &MessageRow{ChatJID: group.String(), ID: "SP-CACHED", Kind: "document", FileName: "CANARY_PRIVATE_FILENAME.pdf"}
	path := filepath.Join(w.dataDir, "media", safeName(m.ChatJID), safeName(m.ID)+extensionFor(m))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("synthetic-pdf"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.DownloadMedia(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	p := spObject(t, spStatus(t, &App{store: w.store, wa: w, mode: "test"}), "sync_progress")
	media := spObject(t, p, "media")
	spWant(t, media, "active_count", float64(0))
	jobs, ok := media["jobs"].([]any)
	if !ok || len(jobs) != 1 {
		t.Fatalf("one completed cached operation required: %v", media)
	}
	job := jobs[0].(map[string]any)
	spWant(t, job, "phase", "complete")
	spWant(t, job, "cache_hit", true)
	spWant(t, job, "cumulative_received_bytes", float64(0))
	spWant(t, job, "completed_plaintext_bytes", float64(len("synthetic-pdf")))
	raw, _ := json.Marshal(p)
	for _, secret := range []string{"CANARY_", group.String(), path} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("status exposed %q", secret)
		}
	}
}

// SP-10/11: coverage uses evidence from only the selected chat. No extraction
// record means unknown even when an attachment is downloadable or cached.
func TestSyncProgressChatEvidenceCoverage(t *testing.T) {
	_, w := setup(t)
	app := &App{store: w.store, mode: "test"}
	for _, chat := range []string{group.String(), bob.String()} {
		t.Run(chat, func(t *testing.T) {
			_, out, err := app.getChat(context.Background(), nil, GetChatIn{Chat: chat})
			if err != nil {
				t.Fatal(err)
			}
			got := spJSON(t, out)
			coverage := spObject(t, got, "evidence_coverage")
			archive := spObject(t, coverage, "archive")
			spWant(t, archive, "archived_message_count", float64(out.MessageCount))
			spWant(t, archive, "oldest_archived_message_at", out.FirstMessage)
			if _, present := archive["complete"]; present {
				t.Error("archive bounds must not expose a completeness field")
			}
			ingest := spObject(t, coverage, "ingest")
			spWant(t, ingest, "currently_processing", nil)
			spWant(t, ingest, "last_observed_history_at", nil)
			media := spObject(t, coverage, "attachments")
			count := float64(0)
			if chat == bob.String() {
				count = 1
			}
			spWant(t, media, "reference_count", count)
			spWant(t, media, "not_checked_count", count)
			spWant(t, media, "read_status", "unknown")
		})
	}
}
