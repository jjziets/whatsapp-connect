//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/hansen/whatsapp-mcp/internal/securestore"
	"github.com/rs/zerolog"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
)

// No Keychain, account connection, preseeded aliases, or network calls. This uses
// the same encrypted engine and actual Whatsmeow SQL store as the existing suite.
func archiveFixture(t *testing.T) (*WA, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "archive.db")
	db, err := securestore.Open(path, false, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	w, err := newWA(context.Background(), db, NewStore(db), dir, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	own := types.NewADJID("491500000000", 0, 7)
	w.Client.Store.ID = &own
	w.Client.Store.Account = &waAdv.ADVSignedDeviceIdentity{Details: []byte{0}, AccountSignature: make([]byte, 64), AccountSignatureKey: make([]byte, 32), DeviceSignature: make([]byte, 64)}
	if err := w.Client.Store.Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	return w, path
}

func archiveWeb(chat, sender types.JID, id string, at time.Time, msg *waE2E.Message) *waWeb.WebMessageInfo {
	return &waWeb.WebMessageInfo{Key: &waCommon.MessageKey{RemoteJID: proto.String(chat.String()), ID: proto.String(id), Participant: proto.String(sender.String())}, MessageTimestamp: proto.Uint64(uint64(at.Unix())), Message: msg}
}
func archiveText(s string) *waE2E.Message { return &waE2E.Message{Conversation: proto.String(s)} }
func archiveEdit(id, text string, at time.Time) *waE2E.Message {
	return &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{Type: waE2E.ProtocolMessage_MESSAGE_EDIT.Enum(), Key: &waCommon.MessageKey{ID: proto.String(id)}, EditedMessage: archiveText(text), TimestampMS: proto.Int64(at.UnixMilli())}}
}
func archiveRevoke(id string) *waE2E.Message {
	return &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{Type: waE2E.ProtocolMessage_REVOKE.Enum(), Key: &waCommon.MessageKey{ID: proto.String(id)}}}
}
func archiveReaction(id, emoji string) *waE2E.Message {
	return &waE2E.Message{ReactionMessage: &waE2E.ReactionMessage{Key: &waCommon.MessageKey{ID: proto.String(id)}, Text: proto.String(emoji)}}
}
func archiveIngest(t *testing.T, w *WA, chat, sender types.JID, id string, at time.Time, msg *waE2E.Message, history bool) {
	t.Helper()
	if pm := msg.GetProtocolMessage(); pm != nil && pm.GetType() == waE2E.ProtocolMessage_MESSAGE_EDIT {
		// Use the dependency's own edit producer, with a deterministic source time.
		msg = w.Client.BuildEdit(chat, pm.GetKey().GetID(), pm.GetEditedMessage())
		msg.GetEditedMessage().GetMessage().GetProtocolMessage().TimestampMS = pm.TimestampMS
	}
	evt, err := w.Client.ParseWebMessage(chat, archiveWeb(chat, sender, id, at, msg))
	if err != nil {
		t.Fatal(err)
	}
	if !history {
		// The live dispatcher uses UnwrapRaw; unlike ParseWebMessage's additional
		// protocol-edit special case, this preserves a ProtocolMessage envelope.
		evt.Info.ID = id
		evt.UnwrapRaw()
	}
	if err := w.ingestMessage(context.Background(), evt); err != nil {
		t.Fatal(err)
	}
}
func archiveMessage(t *testing.T, w *WA, chat types.JID, id string) *MessageRow {
	t.Helper()
	m, err := w.store.Message(context.Background(), chat.String(), id)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// F01: histories may overlap and arrive out of order; mutations must dominate
// replayed originals, and the newest timestamped edit must dominate older edits.
func TestArchiveEditOrdering(t *testing.T) {
	for _, history := range []bool{false, true} {
		route := "live-protocol"
		if history {
			route = "history-ParseWebMessage"
		}
		for _, order := range []string{"original-edit-original", "edit-before-original", "shuffled-multiple-edits", "equal-time-edits"} {
			t.Run(route+"/"+order, func(t *testing.T) {
				w, path := archiveFixture(t)
				original := func() { archiveIngest(t, w, alice, alice, "target", t0, archiveText("original"), history) }
				edit := func(n int) {
					archiveIngest(t, w, alice, alice, "edit-event", t0.Add(time.Duration(n)*time.Minute), archiveEdit("target", []string{"", "first", "second", "newest"}[n], t0.Add(time.Duration(n)*time.Minute)), history)
				}
				want := "first"
				switch order {
				case "original-edit-original":
					original()
					edit(1)
					original()
				case "edit-before-original":
					edit(1)
					if err := w.store.db.Close(); err != nil {
						t.Fatal(err)
					}
					db, err := securestore.Open(path, false, bytes.Repeat([]byte{0x42}, 32))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { db.Close() })
					w, err = newWA(context.Background(), db, NewStore(db), filepath.Dir(path), zerolog.Nop())
					if err != nil {
						t.Fatal(err)
					}
					original()
				case "shuffled-multiple-edits":
					edit(3)
					edit(1)
					original()
					edit(2)
					edit(3)
					original()
					edit(1)
					want = "newest"
				case "equal-time-edits":
					original()
					for _, pair := range [][2]string{{"edit-z", "zeta"}, {"edit-a", "alpha"}, {"edit-z", "zeta"}, {"edit-a", "alpha"}} {
						archiveIngest(t, w, alice, alice, pair[0], t0.Add(time.Minute), archiveEdit("target", pair[1], t0.Add(time.Minute)), history)
					}
					want = "zeta"
				}
				m := archiveMessage(t, w, alice, "target")
				if m.Text != want || !m.Edited {
					t.Errorf("latest edit lost after %s: want text=%q edited=true; got text=%q edited=%v", order, want, m.Text, m.Edited)
				}
				// Positive controls remain valuable even while the edit assertions are RED.
				archiveIngest(t, w, alice, alice, "revoke", t0.Add(4*time.Minute), archiveRevoke("target"), history)
				original()
				edit(3)
				m = archiveMessage(t, w, alice, "target")
				if !m.Deleted || m.Text != "" || m.HasMedia {
					t.Errorf("deleted content resurrected: %+v", m)
				}
				archiveIngest(t, w, bob, bob, "target", t0, archiveText("unrelated chat"), history)
				if other := archiveMessage(t, w, bob, "target"); other.Text != "unrelated chat" || other.Deleted {
					t.Errorf("duplicate ID in unrelated chat conflated: %+v", other)
				}
			})
		}
	}
}

// F03: mapping arrives through Whatsmeow's real SQL-backed LID store after
// archive rows already exist. Reconciliation is asserted through archive reads.
func TestArchiveLateVerifiedLIDMapping(t *testing.T) {
	for _, producer := range []string{"single", "batch"} {
		t.Run(producer, func(t *testing.T) {
			w, _ := archiveFixture(t)
			ctx := context.Background()
			ingest := func(chat, sender types.JID, id string, n int, msg *waE2E.Message) {
				archiveIngest(t, w, chat, sender, id, t0.Add(time.Duration(n)*time.Minute), msg, false)
			}
			ingest(bobLID, bobLID, "same", 0, archiveText("original"))
			ingest(bobLID, bobLID, "edit", 1, archiveEdit("same", "corrected", t0.Add(time.Minute)))
			ingest(bobLID, bobLID, "reaction", 2, archiveReaction("same", "👍"))
			ingest(bobLID, bobLID, "pending-edit", 3, archiveEdit("pending", "pending correction", t0.Add(3*time.Minute)))
			ingest(bobLID, bobLID, "orphan-reaction", 2, archiveReaction("orphan", "✅"))
			ingest(bob, bob, "older-reaction", 1, archiveReaction("same", "old"))
			ingest(bobLID, bobLID, "deleted", 0, archiveText("secret"))
			ingest(bobLID, bobLID, "revoke", 3, archiveRevoke("deleted"))
			// Both preexisting address forms must reconcile without dropping mutations.
			ingest(bob, bob, "same", 0, archiveText("original"))
			ingest(bob, bob, "deleted", 0, archiveText("secret"))
			ingest(group, bobLID, "group-message", 0, archiveText("group sender"))
			ingest(group, bobLID, "group-reaction", 1, archiveReaction("group-message", "✅"))
			ingest(alice, alice, "same", 0, archiveText("unrelated chat"))
			if pn, err := w.Client.Store.LIDs.GetPNForLID(ctx, bobLID); err != nil || !pn.IsEmpty() {
				t.Fatalf("fixture unexpectedly has alias: %v %v", pn, err)
			}
			if producer == "single" {
				w.Client.StoreLIDPNMapping(ctx, bobLID, bob)
			} else if err := w.Client.Store.LIDs.PutManyLIDMappings(ctx, []store.LIDMapping{{LID: bobLID, PN: bob}}); err != nil {
				t.Fatal(err)
			}
			// No later message may be required to reconcile an upstream mapping producer.
			immediate, err := w.store.Chats(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range immediate {
				if c.JID == bobLID.String() {
					t.Errorf("%s mapping producer left split archive before any following message", producer)
				}
			}
			if pn, err := w.Client.Store.LIDs.GetPNForLID(ctx, bobLID); err != nil || pn != bob {
				t.Fatalf("actual mapping store failed: %v %v", pn, err)
			}
			ingest(bobLID, bobLID, "post-mapping", 5, archiveText("new message"))
			ingest(bob, bob, "pending", 0, archiveText("pending original"))
			ingest(bob, bob, "orphan", 0, archiveText("orphan original"))
			ingest(bob, bob, "same", 0, archiveText("original"))
			ingest(bob, bob, "deleted", 0, archiveText("secret"))
			chats, err := w.store.Chats(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range chats {
				if c.JID == bobLID.String() {
					t.Errorf("verified LID conversation remains split: %+v", c)
				}
			}
			m := archiveMessage(t, w, bob, "same")
			if m.Text != "corrected" || !m.Edited || m.SenderJID != bob.String() {
				t.Errorf("canonical message lost mutation/sender: %+v", m)
			}
			if len(m.Reactions) != 1 || m.Reactions[0].Emoji != "👍" || m.Reactions[0].SenderJID != bob.String() {
				t.Errorf("canonical reaction lost: %+v", m.Reactions)
			}
			if deleted := archiveMessage(t, w, bob, "deleted"); !deleted.Deleted || deleted.Text != "" {
				t.Errorf("alias merge resurrected tombstone: %+v", deleted)
			}
			if gm := archiveMessage(t, w, group, "group-message"); gm.SenderJID != bob.String() || len(gm.Reactions) != 1 || gm.Reactions[0].SenderJID != bob.String() {
				t.Errorf("group sender/reaction alias was not reconciled: %+v", gm)
			}
			if pending := archiveMessage(t, w, bob, "pending"); pending.Text != "pending correction" || !pending.Edited {
				t.Errorf("pending edit lost across mapping: %+v", pending)
			}
			if orphan := archiveMessage(t, w, bob, "orphan"); len(orphan.Reactions) != 1 || orphan.Reactions[0].SenderJID != bob.String() {
				t.Errorf("orphan reaction lost across mapping: %+v", orphan)
			}
			if n, err := w.store.CountMessages(ctx, bob.String()); err != nil || n != 5 {
				t.Errorf("want 5 unique canonical messages; got %d: %v", n, err)
			}
			if m := archiveMessage(t, w, alice, "same"); m.Text != "unrelated chat" || m.Deleted {
				t.Errorf("unrelated duplicate ID conflated: %+v", m)
			}
		})
	}
}

// F08: observed empty memberships exist independently of subject and messages.
func TestArchiveUnnamedEmptyGroupInventory(t *testing.T) {
	for _, route := range []string{"joined-group-event", "history-conversation"} {
		t.Run(route, func(t *testing.T) {
			w, _ := archiveFixture(t)
			if route == "joined-group-event" {
				w.handleEvent(&events.JoinedGroup{GroupInfo: types.GroupInfo{JID: group}})
			} else {
				w.ingestHistory(context.Background(), &waHistorySync.HistorySync{Conversations: []*waHistorySync.Conversation{{ID: proto.String(group.String()), Archived: proto.Bool(true), UnreadCount: proto.Uint32(2)}}})
			}
			chats, err := w.store.Chats(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(chats) != 1 || chats[0].JID != group.String() || !chats[0].IsGroup || chats[0].MessageCount != 0 {
				t.Errorf("observed unnamed empty group absent from inventory: %+v", chats)
			}
			if route == "history-conversation" && len(chats) == 1 && (!chats[0].Archived || chats[0].UnreadCount != 2) {
				t.Errorf("empty history chat state lost: %+v", chats[0])
			}
		})
	}
}

func archiveChunk(chat types.JID, msgs ...*waWeb.WebMessageInfo) *waHistorySync.HistorySync {
	conv := &waHistorySync.Conversation{ID: proto.String(chat.String())}
	for _, msg := range msgs {
		conv.Messages = append(conv.Messages, &waHistorySync.HistorySyncMsg{Message: msg})
	}
	return &waHistorySync.HistorySync{Conversations: []*waHistorySync.Conversation{conv}}
}
func archiveTelemetry(t *testing.T, st *Store) map[string]any {
	t.Helper()
	var raw string
	if err := st.db.QueryRowContext(context.Background(), `SELECT value FROM mcp_meta WHERE key = 'prelink_ingest_telemetry_v1'`).Scan(&raw); err != nil {
		t.Errorf("durable ingest outcomes missing: %v", err)
		return nil
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("invalid durable telemetry JSON: %v", err)
	}
	return result
}
func archiveWantCounts(t *testing.T, out map[string]any, want map[string]float64) {
	t.Helper()
	if out == nil {
		return
	}
	for key, value := range want {
		if out[key] != value {
			t.Errorf("telemetry %s: got %v want %v; summary=%v", key, out[key], value, out)
		}
	}
	received, _ := out["history_received"].(float64)
	var sum float64
	for _, key := range []string{"history_inserted", "history_updated", "history_duplicate", "history_ignored", "history_failed"} {
		n, _ := out[key].(float64)
		sum += n
	}
	if sum != received {
		t.Errorf("outcome conservation violated: received=%v sum=%v", received, sum)
	}
}

// F04: distinguish archived content from parsed no-ops/replays; failed history
// must not publish a successful checkpoint, including for an archive-only reader.
func TestArchiveHistoryTruthfulOutcomes(t *testing.T) {
	t.Run("replay-and-unsupported-are-not-new", func(t *testing.T) {
		w, path := archiveFixture(t)
		ctx := context.Background()
		original := archiveWeb(alice, alice, "history-one", t0, archiveText("persisted"))
		w.ingestHistory(ctx, archiveChunk(alice, original))
		w.ingestHistory(ctx, archiveChunk(alice, original, archiveWeb(alice, alice, "unsupported", t0, &waE2E.Message{}), archiveWeb(alice, alice, "noop", t0, &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{Type: waE2E.ProtocolMessage_HISTORY_SYNC_NOTIFICATION.Enum()}})))
		if n := w.historyMessages.Load(); n != 1 {
			t.Errorf("stored counter includes replays/unsupported/no-op: got %d, want 1 new durable message", n)
		}
		if n, err := w.store.CountMessages(ctx, alice.String()); err != nil || n != 1 {
			t.Errorf("durable count: %d %v", n, err)
		}
		if err := w.store.db.Close(); err != nil {
			t.Fatal(err)
		}
		db, err := securestore.Open(path, false, bytes.Repeat([]byte{0x42}, 32))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		archiveWantCounts(t, archiveTelemetry(t, NewStore(db)), map[string]float64{"schema_version": 1, "history_received": 3, "history_inserted": 0, "history_updated": 0, "history_duplicate": 1, "history_ignored": 2, "history_failed": 0})
	})
	t.Run("mixed-chunk-is-partial", func(t *testing.T) {
		w, _ := archiveFixture(t)
		valid := archiveChunk(alice, archiveWeb(alice, alice, "partial-one", t0, archiveText("stored despite partial chunk")))
		bad := archiveWeb(group, types.EmptyJID, "bad-partial", t0, archiveText("missing sender"))
		bad.Key.Participant = nil
		valid.Conversations = append(valid.Conversations, archiveChunk(group, bad).Conversations...)
		w.ingestHistory(context.Background(), valid)
		out := archiveTelemetry(t, w.store)
		if out["last_history_status"] != "partial" {
			t.Errorf("mixed committed/failed chunk not reported partial: %v", out)
		}
		archiveWantCounts(t, out, map[string]float64{"schema_version": 1, "history_received": 2, "history_inserted": 1, "history_updated": 0, "history_duplicate": 0, "history_ignored": 0, "history_failed": 1, "history_parse_failed": 1})
		if m := archiveMessage(t, w, alice, "partial-one"); m.Text != "stored despite partial chunk" {
			t.Errorf("successful part lost: %+v", m)
		}
	})
	for _, failure := range []string{"parse-failure", "write-failure"} {
		t.Run(failure, func(t *testing.T) {
			w, path := archiveFixture(t)
			ctx := context.Background()
			checkpoint := "2026-09-01T00:00:00Z"
			seed, _ := json.Marshal(map[string]any{"schema_version": 1, "last_successful_ingest_at": checkpoint})
			if err := w.store.SetMeta(ctx, "prelink_ingest_telemetry_v1", string(seed)); err != nil {
				t.Fatal(err)
			}
			var chunk *waHistorySync.HistorySync
			if failure == "parse-failure" {
				// A group web message with neither participant field is rejected by the
				// actual pinned Whatsmeow parser, rather than a stand-in parse mock.
				bad := archiveWeb(group, types.EmptyJID, "bad-parse", t0, archiveText("unparseable"))
				bad.Key.Participant = nil
				if _, err := w.Client.ParseWebMessage(group, bad); err == nil {
					t.Fatal("fixture must really fail parser")
				}
				chunk = archiveChunk(group, bad)
			} else {
				// Fault injection only: production ingestion still performs the write.
				if _, err := w.store.db.ExecContext(ctx, `CREATE TRIGGER reject_history BEFORE INSERT ON mcp_messages WHEN NEW.id = 'bad-write' BEGIN SELECT RAISE(FAIL, 'injected history write failure'); END`); err != nil {
					t.Fatal(err)
				}
				chunk = archiveChunk(alice, archiveWeb(alice, alice, "bad-write", t0, archiveText("must not commit")))
			}
			w.ingestHistory(ctx, chunk)
			if n := w.historyMessages.Load(); n != 0 {
				t.Errorf("failed history counted stored: %d", n)
			}
			// Reopen the real encrypted file to prove this is a durable public status
			// outcome; the reader has no in-memory WA telemetry to fall back on.
			if err := w.store.db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := securestore.Open(path, false, bytes.Repeat([]byte{0x42}, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			out := archiveTelemetry(t, NewStore(db))
			if got := out["last_successful_ingest_at"]; got != checkpoint {
				t.Errorf("%s advanced durable successful-ingest checkpoint: got %v want %s", failure, got, checkpoint)
			}
			if out["last_history_status"] != "failed" {
				t.Errorf("failed chunk not durably reported: %v", out)
			}
			if out["last_error_code"] == nil || out["last_error_code"] == "" {
				t.Errorf("failed chunk lacks bounded error code: %v", out)
			}
			parseFailed := float64(0)
			if failure == "parse-failure" {
				parseFailed = 1
			}
			archiveWantCounts(t, out, map[string]float64{"schema_version": 1, "history_received": 1, "history_inserted": 0, "history_updated": 0, "history_duplicate": 0, "history_ignored": 0, "history_failed": 1, "history_parse_failed": parseFailed})
		})
	}
}

func TestArchivePinnedEditProducerShapes(t *testing.T) {
	w, _ := archiveFixture(t)
	raw := w.Client.BuildEdit(alice, "target", archiveText("corrected"))
	raw.GetEditedMessage().GetMessage().GetProtocolMessage().TimestampMS = proto.Int64(t0.Add(time.Minute).UnixMilli())
	web := archiveWeb(alice, alice, "edit-envelope-id", t0.Add(time.Minute), raw)
	history, err := w.Client.ParseWebMessage(alice, web)
	if err != nil {
		t.Fatal(err)
	}
	live := (&events.Message{Info: types.MessageInfo{ID: "edit-envelope-id", Timestamp: t0.Add(time.Minute)}, RawMessage: raw}).UnwrapRaw()
	t.Logf("dependency=go.mau.fi/whatsmeow@v0.0.0-20260925162019-b3832c2bd1d1 raw=%s", raw.String())
	t.Logf("ParseWebMessage: info.ID=%q IsEdit=%v Message=%s RawMessage=%s SourceWebMsg.Key.ID=%q", history.Info.ID, history.IsEdit, history.Message.String(), history.RawMessage.String(), history.SourceWebMsg.GetKey().GetID())
	t.Logf("UnwrapRaw live: info.ID=%q IsEdit=%v Message=%s RawMessage=%s", live.Info.ID, live.IsEdit, live.Message.String(), live.RawMessage.String())
	if history.Info.ID != "target" || history.Message.GetConversation() != "corrected" || history.SourceWebMsg.GetKey().GetID() != "edit-envelope-id" {
		t.Fatal("pinned history edit producer shape changed; reassess translation contract")
	}
	if !live.IsEdit || live.Message.GetProtocolMessage().GetKey().GetID() != "target" {
		t.Fatal("pinned live edit producer shape changed; reassess translation contract")
	}
}

// Frozen verbatim from the prior db.go schema. This fixture must not track future schema edits.
const archivePriorSchema = `
CREATE TABLE IF NOT EXISTS mcp_chats (
	jid             TEXT PRIMARY KEY,
	name            TEXT NOT NULL DEFAULT '',
	is_group        INTEGER NOT NULL DEFAULT 0,
	last_message_at INTEGER NOT NULL DEFAULT 0,
	unread_count    INTEGER NOT NULL DEFAULT 0,
	archived        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mcp_messages (
	chat_jid       TEXT    NOT NULL,
	id             TEXT    NOT NULL,
	sender_jid     TEXT    NOT NULL DEFAULT '',
	from_me        INTEGER NOT NULL DEFAULT 0,
	timestamp      INTEGER NOT NULL,
	kind           TEXT    NOT NULL,
	text           TEXT    NOT NULL DEFAULT '',
	push_name      TEXT    NOT NULL DEFAULT '',
	media_mime     TEXT    NOT NULL DEFAULT '',
	media_filename TEXT    NOT NULL DEFAULT '',
	media_size     INTEGER NOT NULL DEFAULT 0,
	media_seconds  INTEGER NOT NULL DEFAULT 0,
	quoted_id      TEXT    NOT NULL DEFAULT '',
	edited         INTEGER NOT NULL DEFAULT 0,
	deleted        INTEGER NOT NULL DEFAULT 0,
	raw            BLOB,
	PRIMARY KEY (chat_jid, id)
);
CREATE INDEX IF NOT EXISTS mcp_messages_chat_ts ON mcp_messages (chat_jid, timestamp);
CREATE INDEX IF NOT EXISTS mcp_messages_ts ON mcp_messages (timestamp);
CREATE INDEX IF NOT EXISTS mcp_messages_sender ON mcp_messages (sender_jid);

CREATE TABLE IF NOT EXISTS mcp_reactions (
	chat_jid   TEXT    NOT NULL,
	message_id TEXT    NOT NULL,
	sender_jid TEXT    NOT NULL,
	emoji      TEXT    NOT NULL,
	timestamp  INTEGER NOT NULL,
	PRIMARY KEY (chat_jid, message_id, sender_jid)
);

CREATE TABLE IF NOT EXISTS mcp_meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

// Snapshot actual persisted archive tables, including any newly introduced
// mutation/alias table. Operational telemetry may legitimately record the failed
// attempt, so rollback checks exclude only mcp_meta; migration checks include it.
func archiveDurableState(t *testing.T, w *WA, excludeMeta bool) map[string][]string {
	t.Helper()
	ctx := context.Background()
	tables, err := w.store.db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'mcp_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for tables.Next() {
		var name string
		if err := tables.Scan(&name); err != nil {
			t.Fatal(err)
		}
		if !excludeMeta || name != "mcp_meta" {
			names = append(names, name)
		}
	}
	if err := tables.Err(); err != nil {
		t.Fatal(err)
	}
	tables.Close()
	out := map[string][]string{}
	for _, name := range names {
		rows, err := w.store.db.QueryContext(ctx, `SELECT * FROM "`+name+`"`)
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		out[name] = []string{}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(vals)
			if err != nil {
				t.Fatal(err)
			}
			out[name] = append(out[name], string(b))
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		sort.Strings(out[name])
	}
	return out
}

// F03 destructive-merge gate: an already accepted person identity is immutable.
func TestArchiveAliasConflictIsolation(t *testing.T) {
	for _, producer := range []string{"single", "batch"} {
		t.Run(producer, func(t *testing.T) {
			w, _ := archiveFixture(t)
			ctx := context.Background()
			archiveIngest(t, w, bob, bob, "pn-one", t0, archiveText("first person"), false)
			archiveIngest(t, w, alice, alice, "pn-two", t0, archiveText("second person"), false)
			if err := w.Client.Store.LIDs.PutLIDMapping(ctx, bobLID, bob); err != nil {
				t.Fatal(err)
			}
			before := archiveDurableState(t, w, true)
			var err error
			if producer == "single" {
				err = w.Client.Store.LIDs.PutLIDMapping(ctx, bobLID, alice)
			} else {
				err = w.Client.Store.LIDs.PutManyLIDMappings(ctx, []store.LIDMapping{{LID: bobLID, PN: alice}})
			}
			if err == nil {
				t.Errorf("conflicting %s LID mapping was accepted without error", producer)
			}
			if after := archiveDurableState(t, w, true); !reflect.DeepEqual(before, after) {
				t.Errorf("conflicting mapping mutated accepted archive identities: before=%v after=%v", before, after)
			}
			// Even if upstream persisted conflicting evidence, archive canonicalization
			// must continue using the accepted registry, not the mutable upstream value.
			archiveIngest(t, w, bobLID, bobLID, "after-conflict", t0.Add(time.Minute), archiveText("belongs to first person"), false)
			if m, err := w.store.Message(ctx, bob.String(), "after-conflict"); err != nil || m.SenderJID != bob.String() {
				t.Errorf("accepted canonical person changed after conflicting evidence: message=%+v err=%v", m, err)
			}
			if n, err := w.store.CountMessages(ctx, alice.String()); err != nil || n != 1 {
				t.Errorf("distinct PN conversation absorbed conflicting identity: count=%d err=%v", n, err)
			}
		})
	}
}

// F03 destructive-merge gate: fail source-row removal/rename after any copy may
// already have happened. This catches copy+delete and in-place rename designs,
// rather than assuming a specific future reconciliation SQL statement.
func TestArchiveAliasMergeRollbackAndRetry(t *testing.T) {
	w, _ := archiveFixture(t)
	ctx := context.Background()
	archiveIngest(t, w, bobLID, bobLID, "rollback-original", t0, archiveText("original"), false)
	archiveIngest(t, w, bobLID, bobLID, "rollback-edit", t0.Add(time.Minute), archiveEdit("rollback-original", "corrected", t0.Add(time.Minute)), false)
	archiveIngest(t, w, bobLID, bobLID, "rollback-pending-edit", t0.Add(2*time.Minute), archiveEdit("rollback-pending", "pending correction", t0.Add(2*time.Minute)), false)
	archiveIngest(t, w, bobLID, bobLID, "rollback-reaction", t0.Add(time.Minute), archiveReaction("rollback-original", "✅"), false)
	archiveIngest(t, w, bob, bob, "destination-only", t0, archiveText("destination"), false)
	before := archiveDurableState(t, w, true)
	var triggers []string
	for _, table := range []string{"mcp_chats", "mcp_messages"} {
		key := "chat_jid"
		if table == "mcp_chats" {
			key = "jid"
		}
		for _, op := range []string{"UPDATE", "DELETE"} {
			name := fmt.Sprintf("reject_alias_%s_%s", table, op)
			triggers = append(triggers, name)
			q := fmt.Sprintf(`CREATE TRIGGER %s BEFORE %s ON %s WHEN OLD.%s = '%s' BEGIN SELECT RAISE(ABORT, 'injected mid-merge source move failure'); END`, name, op, table, key, bobLID.String())
			if _, err := w.store.db.ExecContext(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Client.Store.LIDs.PutLIDMapping(ctx, bobLID, bob); err == nil {
		t.Error("mid-merge fault was not surfaced by real LIDStore API")
	}
	if after := archiveDurableState(t, w, true); !reflect.DeepEqual(before, after) {
		t.Errorf("failed merge did not roll back source/destination chats, messages, mutations and reactions: before=%v after=%v", before, after)
	}
	if got := w.canonical(ctx, bobLID, types.EmptyJID); got != bobLID {
		t.Errorf("failed merge exposed uncommitted archive alias: got %s want %s", got, bobLID)
	}
	for _, name := range triggers {
		if _, err := w.store.db.ExecContext(ctx, `DROP TRIGGER `+name); err != nil {
			t.Fatal(err)
		}
	}
	// Retrying the exact same pair must retry archive reconciliation even when the
	// upstream mapping already committed and its own cache would otherwise no-op.
	if err := w.Client.Store.LIDs.PutLIDMapping(ctx, bobLID, bob); err != nil {
		t.Fatalf("retry after fault removed failed: %v", err)
	}
	chats, err := w.store.Chats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chats {
		if c.JID == bobLID.String() {
			t.Error("retry left source LID conversation stranded")
		}
	}
	m, err := w.store.Message(ctx, bob.String(), "rollback-original")
	if err != nil {
		t.Errorf("retry lost original/edited row: %v", err)
	} else if m.Text != "corrected" || !m.Edited || len(m.Reactions) != 1 || m.Reactions[0].SenderJID != bob.String() {
		t.Errorf("retry failed to preserve edit/reaction state: %+v", m)
	}
	archiveIngest(t, w, bob, bob, "rollback-pending", t0, archiveText("pending original"), false)
	if m := archiveMessage(t, w, bob, "rollback-pending"); m.Text != "pending correction" || !m.Edited {
		t.Errorf("pending mutation was lost on rollback/retry: %+v", m)
	}
	if m := archiveMessage(t, w, bob, "destination-only"); m.Text != "destination" {
		t.Errorf("destination row lost: %+v", m)
	}
}

// F01/schema gate: load a real populated prior archive before newWA performs
// its migrations; the fixture is independent of the evolving current schema.
func TestArchivePopulatedLegacyMigration(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "prior.db")
	db, err := securestore.Open(path, false, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, archivePriorSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO mcp_chats (jid,name,last_message_at,unread_count,archived) VALUES (?,'Legacy chat',?,2,1)`, alice.String(), t0.Unix()); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		id, text        string
		edited, deleted int
	}{{"legacy-edit", "legacy correction", 1, 0}, {"legacy-deleted", "", 0, 1}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO mcp_messages (chat_jid,id,sender_jid,timestamp,kind,text,edited,deleted) VALUES (?,?,?,?,'text',?,?,?)`, alice.String(), row.id, alice.String(), t0.Unix(), row.text, row.edited, row.deleted); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO mcp_reactions (chat_jid,message_id,sender_jid,emoji,timestamp) VALUES (?, 'legacy-edit', ?, '✅', ?)`, alice.String(), bob.String(), t0.Unix()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = securestore.Open(path, false, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	w, err := newWA(ctx, db, NewStore(db), dir, zerolog.Nop())
	if err != nil {
		t.Fatalf("upgrade prior populated schema: %v", err)
	}
	before := archiveDurableState(t, w, false)
	if err := w.store.Migrate(ctx); err != nil {
		t.Fatalf("idempotent second migration: %v", err)
	}
	if after := archiveDurableState(t, w, false); !reflect.DeepEqual(before, after) {
		t.Errorf("second migration changed persisted archive: before=%v after=%v", before, after)
	}
	for _, id := range []string{"legacy-edit", "legacy-deleted"} {
		archiveIngest(t, w, alice, alice, id, t0, archiveText("replayed original"), true)
	}
	if m := archiveMessage(t, w, alice, "legacy-edit"); m.Text != "legacy correction" || !m.Edited || len(m.Reactions) != 1 {
		t.Errorf("migration/replay destroyed legacy unversioned edit or reaction: %+v", m)
	}
	if m := archiveMessage(t, w, alice, "legacy-deleted"); !m.Deleted || m.Text != "" || m.HasMedia {
		t.Errorf("migration/replay resurrected legacy tombstone: %+v", m)
	}
	if c, err := w.store.Chat(ctx, alice.String()); err != nil || c.Name != "Legacy chat" || !c.Archived || c.UnreadCount != 2 || c.MessageCount != 2 {
		t.Errorf("migration lost legacy chat inventory/state: %+v %v", c, err)
	}
}
