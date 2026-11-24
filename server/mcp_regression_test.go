//go:build libsqlite3

package main

// Pre-link defect definitions F02/F05/F06/F07. Fixtures enter through real
// ingestion and callers use the MCP transport, including future cursor fields.
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hansen/whatsapp-mcp/internal/securestore"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"
)

func regressionClient(t *testing.T, app *App) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := newMCPServer(app).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "prelink-regression", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// F04: the public status contract must expose committed producer telemetry to
// another archive reader, including real parser and actual SQLite failures.
func TestPrelinkStatusDurableHistoryFailure(t *testing.T) {
	for _, failure := range []string{"parse_failure", "write_failure"} {
		t.Run(failure, func(t *testing.T) {
			owner, wa := setup(t)
			ctx := context.Background()
			web := func(id string) *waWeb.WebMessageInfo {
				return &waWeb.WebMessageInfo{Key: &waCommon.MessageKey{RemoteJID: proto.String(group.String()), Participant: proto.String(alice.String()), ID: proto.String(id)}, MessageTimestamp: proto.Uint64(uint64(t0.Unix())), Message: &waE2E.Message{Conversation: proto.String("public telemetry fixture")}}
			}
			chunk := func(msg *waWeb.WebMessageInfo) *waHistorySync.HistorySync {
				return &waHistorySync.HistorySync{SyncType: waHistorySync.HistorySync_ON_DEMAND.Enum(), Conversations: []*waHistorySync.Conversation{{ID: proto.String(group.String()), Messages: []*waHistorySync.HistorySyncMsg{{Message: msg}}}}}
			}
			// Establish the success checkpoint through the real producer, with no
			// hand-seeded telemetry or direct insertion of a fake healthy summary.
			wa.ingestHistory(ctx, chunk(web("status-success")))
			var success map[string]json.RawMessage
			call(t, owner, "whatsapp_status", nil, &success)
			var previous map[string]any
			if err := json.Unmarshal(success["ingest_telemetry"], &previous); err != nil {
				t.Errorf("successful real history producer missing public ingest_telemetry: %v", err)
			}
			checkpoint, _ := previous["last_successful_ingest_at"].(string)
			if checkpoint == "" {
				t.Errorf("real successful import must establish last_successful_ingest_at")
			}
			before, err := wa.store.CountMessages(ctx, group.String())
			if err != nil {
				t.Fatal(err)
			}
			bad := web("status-failure")
			if failure == "parse_failure" {
				bad.Key.Participant = nil
				if _, err := wa.Client.ParseWebMessage(group, bad); err == nil {
					t.Fatal("fixture must fail the actual pinned parser")
				}
			} else {
				if _, err := wa.store.db.ExecContext(ctx, `CREATE TRIGGER reject_public_status_history BEFORE INSERT ON mcp_messages WHEN NEW.id = 'status-failure' BEGIN SELECT RAISE(FAIL, 'injected public status history failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			// Cross a wall-clock second so incorrectly advancing an RFC3339
			// checkpoint during failure cannot pass through equal timestamps.
			time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)) + 10*time.Millisecond)
			wa.ingestHistory(ctx, chunk(bad))
			after, err := wa.store.CountMessages(ctx, group.String())
			if err != nil {
				t.Fatal(err)
			}
			if after != before {
				t.Fatalf("failed message was committed: before=%d after=%d", before, after)
			}
			db, err := securestore.Open(filepath.Join(wa.dataDir, "whatsapp.db"), false, bytes.Repeat([]byte{0x42}, 32))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.Close() })
			reader := regressionClient(t, &App{store: NewStore(db), wa: nil, mode: "archive-reader"})
			var status map[string]json.RawMessage
			call(t, reader, "whatsapp_status", nil, &status)
			var telemetry map[string]any
			if err := json.Unmarshal(status["ingest_telemetry"], &telemetry); err != nil || telemetry == nil {
				t.Fatalf("archive-only status hides durable %s: missing ingest_telemetry object: %v", failure, err)
			}
			if telemetry["last_history_status"] != "failed" {
				t.Errorf("failed chunk must not default healthy: %v", telemetry)
			}
			if telemetry["last_successful_ingest_at"] != checkpoint {
				t.Errorf("failure advanced success checkpoint: got %v want %q", telemetry["last_successful_ingest_at"], checkpoint)
			}
			for _, field := range []string{"last_history_received_at", "last_history_completed_at", "last_error_code", "last_error_at"} {
				if value, ok := telemetry[field].(string); !ok || value == "" {
					t.Errorf("failure missing %s: %v", field, telemetry)
				}
			}
			want := map[string]float64{"schema_version": 1, "history_received": 1, "history_inserted": 0, "history_updated": 0, "history_duplicate": 0, "history_ignored": 0, "history_failed": 1, "history_parse_failed": 0, "history_metadata_failed": 0}
			if failure == "parse_failure" {
				want["history_parse_failed"] = 1
			}
			for field, expected := range want {
				if actual, ok := telemetry[field].(float64); !ok || actual != expected {
					t.Errorf("%s: got %v want %v", field, telemetry[field], expected)
				}
			}
			var durable map[string]any
			var stored string
			if err := db.QueryRowContext(ctx, `SELECT value FROM mcp_meta WHERE key = 'prelink_ingest_telemetry_v1'`).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(stored), &durable); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(telemetry, durable) {
				t.Errorf("public status differs from committed versioned producer object: public=%v stored=%v", telemetry, durable)
			}
		})
	}
}

func regressionCall(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s transport: %v", name, err)
	}
	return r
}

func regressionErrorText(r *mcp.CallToolResult) string {
	var parts []string
	for _, c := range r.Content {
		if text, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, text.Text)
		}
	}
	return strings.Join(parts, " ")
}

func regressionAmbiguous(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any, candidates ...string) {
	t.Helper()
	r := regressionCall(t, cs, name, args)
	text := regressionErrorText(r)
	if !r.IsError || !strings.Contains(strings.ToLower(text), "ambig") {
		t.Errorf("%s must reject ambiguous reference, got is_error=%v content=%q", name, r.IsError, text)
		return
	}
	for _, jid := range candidates {
		if !strings.Contains(text, jid) {
			t.Errorf("ambiguity response omits candidate %s: %s", jid, text)
		}
	}
}

func regressionIDs(ms []*MessageOut) []string {
	ids := make([]string, len(ms))
	for i, m := range ms {
		ids[i] = m.ID
	}
	return ids
}

func regressionTies(t *testing.T, wa *WA, chat types.JID, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := wa.ingestMessage(context.Background(), textMsg(chat, alice, fmt.Sprintf("T%02d", i), t0.Add(24*time.Hour), "dense cursor fixture")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrelinkPaginationTimestampLosesTies(t *testing.T) {
	cs, wa := setup(t)
	chat := types.NewJID("120363000000000102", types.GroupServer)
	regressionTies(t, wa, chat, 9)
	var first, next MessagesOut
	call(t, cs, "list_messages", map[string]any{"chat": chat.String(), "limit": 1}, &first)
	if len(first.Messages) != 1 || !first.HasMore {
		t.Fatalf("fixture first page: %+v", first)
	}
	call(t, cs, "list_messages", map[string]any{"chat": chat.String(), "limit": 1, "before": first.Messages[0].Time}, &next)
	// A cursor repair may keep before as a strict date filter, but must stop
	// instructing clients to use that lossy date filter as a paging continuation.
	if len(next.Messages) == 0 && strings.Contains(first.Hint, "before=") {
		t.Fatalf("actual omission: has_more=true, advertised before=%s returns zero of eight remaining same-second rows", first.Messages[0].Time)
	}
}

func TestPrelinkPaginationOpaqueCursor(t *testing.T) {
	for _, oldest := range []bool{false, true} {
		t.Run(fmt.Sprintf("oldest_first=%v", oldest), func(t *testing.T) {
			cs, wa := setup(t)
			chat := types.NewJID("120363000000000103", types.GroupServer)
			regressionTies(t, wa, chat, 9)
			seen := map[string]bool{}
			cursor := ""
			for page := 0; page < 10; page++ {
				args := map[string]any{"chat": chat.String(), "limit": 1, "oldest_first": oldest}
				if cursor != "" {
					args["cursor"] = cursor
				}
				var raw map[string]json.RawMessage
				call(t, cs, "list_messages", args, &raw)
				var out MessagesOut
				data, err := json.Marshal(raw)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(data, &out); err != nil {
					t.Fatal(err)
				}
				if len(out.Messages) != 1 {
					t.Fatalf("page %d must contain one row: %+v", page, out)
				}
				id := out.Messages[0].ID
				if seen[id] {
					t.Fatalf("cursor repeated message %s on page %d", id, page)
				}
				seen[id] = true
				var next string
				if data := raw["next_cursor"]; len(data) > 0 {
					if err := json.Unmarshal(data, &next); err != nil {
						t.Fatalf("next_cursor must be a string: %s", data)
					}
				}
				if !out.HasMore {
					if next != "" {
						t.Errorf("terminal page carries next_cursor=%q", next)
					}
					break
				}
				if next == "" {
					t.Fatalf("has_more=true requires opaque next_cursor; raw MCP response=%s", data)
				}
				if next == cursor {
					t.Fatalf("cursor did not advance: %q", next)
				}
				if next == out.Messages[0].Time {
					t.Fatalf("cursor is only a timestamp: %q", next)
				}
				cursor = next
			}
			if len(seen) != 9 {
				t.Errorf("same-second traversal lost rows: visited %d/9: %v", len(seen), seen)
			}
		})
	}
}

func TestPrelinkPaginationRejectsInvalidCursor(t *testing.T) {
	cs, wa := setup(t)
	chat := types.NewJID("120363000000000104", types.GroupServer)
	regressionTies(t, wa, chat, 3)
	t.Run("malformed", func(t *testing.T) {
		r := regressionCall(t, cs, "list_messages", map[string]any{"chat": chat.String(), "cursor": "not-a-valid-cursor", "limit": 1})
		if !r.IsError || !strings.Contains(strings.ToLower(regressionErrorText(r)), "cursor") {
			t.Fatalf("malformed cursor must be rejected as a cursor error: %+v", r)
		}
	})
	t.Run("wrong_scope", func(t *testing.T) {
		var raw map[string]json.RawMessage
		call(t, cs, "list_messages", map[string]any{"chat": chat.String(), "limit": 1}, &raw)
		var cursor string
		if err := json.Unmarshal(raw["next_cursor"], &cursor); err != nil || cursor == "" {
			t.Fatalf("cannot validate scope: first page has no next_cursor")
		}
		for _, args := range []map[string]any{
			{"chat": alice.String(), "cursor": cursor, "limit": 1},
			{"chat": chat.String(), "cursor": cursor, "limit": 1, "oldest_first": true},
			{"chat": chat.String(), "cursor": cursor, "limit": 1, "sender": bob.String()},
		} {
			r := regressionCall(t, cs, "list_messages", args)
			if !r.IsError || !strings.Contains(strings.ToLower(regressionErrorText(r)), "cursor") {
				t.Errorf("wrong-scope cursor must fail: args=%v error=%v content=%s", args, r.IsError, regressionErrorText(r))
			}
		}
	})
}

func TestPrelinkSearchCursorAcrossChatsReopenAndNewerInsert(t *testing.T) {
	_, wa := setup(t)
	chats := []types.JID{
		types.NewJID("120363000000000108", types.GroupServer),
		types.NewJID("120363000000000109", types.GroupServer),
	}
	for _, chat := range chats {
		regressionTies(t, wa, chat, 4)
	}
	want := map[string]bool{}
	for _, chat := range chats {
		for i := 0; i < 4; i++ {
			want[chat.String()+"/"+fmt.Sprintf("T%02d", i)] = true
		}
	}
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 9; page++ {
		// Every page starts a separate encrypted handle/Store/App with wa=nil.
		db, err := securestore.Open(filepath.Join(wa.dataDir, "whatsapp.db"), false, bytes.Repeat([]byte{0x42}, 32))
		if err != nil {
			t.Fatal(err)
		}
		cs := regressionClient(t, &App{store: NewStore(db), wa: nil, mode: "archive-reader"})
		args := map[string]any{"query": "dense cursor fixture", "limit": 1}
		if cursor != "" {
			args["cursor"] = cursor
		}
		var raw map[string]json.RawMessage
		call(t, cs, "search_messages", args, &raw)
		cs.Close()
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		var messages []*MessageOut
		if err := json.Unmarshal(raw["messages"], &messages); err != nil {
			t.Fatal(err)
		}
		if len(messages) != 1 {
			t.Fatalf("page %d must have one row: %s", page, raw["messages"])
		}
		key := messages[0].ChatJID + "/" + messages[0].ID
		if !want[key] || seen[key] {
			t.Fatalf("page %d unexpected/repeated key %s", page, key)
		}
		seen[key] = true
		var more bool
		if err := json.Unmarshal(raw["has_more"], &more); err != nil {
			t.Fatal(err)
		}
		var next string
		if len(raw["next_cursor"]) > 0 {
			if err := json.Unmarshal(raw["next_cursor"], &next); err != nil {
				t.Fatal(err)
			}
		}
		if !more {
			if next != "" {
				t.Errorf("terminal search page carries a cursor")
			}
			break
		}
		if next == "" || next == cursor {
			t.Fatalf("search has_more=true requires advancing next_cursor: %v", raw)
		}
		cursor = next
		if page == 0 {
			// Legacy search offset is supported only without a cursor.
			guard := regressionCall(t, regressionClient(t, &App{store: wa.store, wa: nil, mode: "archive-reader"}), "search_messages", map[string]any{"query": "dense cursor fixture", "cursor": cursor, "offset": 1})
			if !guard.IsError || !strings.Contains(strings.ToLower(regressionErrorText(guard)), "cursor") {
				t.Errorf("search offset with cursor must fail: error=%v content=%s", guard.IsError, regressionErrorText(guard))
			}
			// This newly inserted row is before an older-page boundary. A keyset
			// continuation excludes it without shifting or duplicating old rows.
			if err := wa.ingestMessage(context.Background(), textMsg(chats[0], alice, "NEWER", t0.Add(25*time.Hour), "dense cursor fixture")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("cross-chat traversal: seen=%v want=%v", seen, want)
	}
}

func TestPrelinkCursorInvalidatedByAliasMerge(t *testing.T) {
	cs, wa := setup(t)
	lid := types.NewJID("99880000199", types.HiddenUserServer)
	pn := types.NewJID("491544440199", types.DefaultUserServer)
	regressionTies(t, wa, lid, 3)
	var raw map[string]json.RawMessage
	call(t, cs, "list_messages", map[string]any{"chat": lid.String(), "limit": 1}, &raw)
	var cursor string
	if err := json.Unmarshal(raw["next_cursor"], &cursor); err != nil || cursor == "" {
		t.Fatalf("cannot validate epoch: first page has no next_cursor")
	}
	// Exercise the real pinned dependency's mapping producer, not a fake
	// archive epoch setter. Producer A must reconcile it before B consumes it.
	if err := wa.Client.Store.LIDs.PutLIDMapping(context.Background(), lid, pn); err != nil {
		t.Fatal(err)
	}
	var merged MessagesOut
	call(t, cs, "list_messages", map[string]any{"chat": pn.String(), "limit": 100}, &merged)
	if len(merged.Messages) != 3 {
		t.Fatalf("mapping producer did not reconcile fixture: %+v", merged)
	}
	r := regressionCall(t, cs, "list_messages", map[string]any{"chat": pn.String(), "limit": 1, "cursor": cursor})
	text := strings.ToLower(regressionErrorText(r))
	if !r.IsError || !strings.Contains(text, "ordering") || !strings.Contains(text, "restart") {
		t.Fatalf("cursor after alias merge must explicitly require restart after ordering change: error=%v content=%s", r.IsError, text)
	}
}

func TestPrelinkContextDenseTieNeighbors(t *testing.T) {
	cs, wa := setup(t)
	chat := types.NewJID("120363000000000105", types.GroupServer)
	regressionTies(t, wa, chat, 25)
	var all MessagesOut
	call(t, cs, "list_messages", map[string]any{"chat": chat.String(), "limit": 100, "oldest_first": true}, &all)
	if len(all.Messages) != 25 || all.HasMore {
		t.Fatalf("fixture full order: %+v", all)
	}
	// Use the tool's complete chronological order to avoid prescribing a new
	// tie-breaker representation in the test. Both queries must agree on it.
	for _, i := range []int{0, 12, 24} {
		t.Run(fmt.Sprintf("target=%s", all.Messages[i].ID), func(t *testing.T) {
			var got ContextOut
			call(t, cs, "get_message_context", map[string]any{"chat": chat.String(), "message_id": all.Messages[i].ID, "before": 2, "after": 2}, &got)
			want := regressionIDs(all.Messages[max(0, i-2):min(len(all.Messages), i+3)])
			if got.Target == nil || got.Target.ID != all.Messages[i].ID || got.Target.ChatJID != chat.String() {
				t.Errorf("wrong target: %+v", got.Target)
			}
			if ids := regressionIDs(got.Messages); !reflect.DeepEqual(ids, want) {
				t.Errorf("immediate chronological neighbors: got %v, want %v", ids, want)
			}
		})
	}
}

func TestPrelinkMessageIDAmbiguity(t *testing.T) {
	cs, wa := setup(t)
	ctx := context.Background()
	for _, chat := range []types.JID{alice, group} {
		if err := wa.ingestMessage(ctx, textMsg(chat, alice, "DUPLICATE-ID", t0.Add(2*time.Hour), "message identity fixture")); err != nil {
			t.Fatal(err)
		}
	}
	regressionAmbiguous(t, cs, "get_message_context", map[string]any{"message_id": "DUPLICATE-ID", "before": 1, "after": 1}, alice.String(), group.String())
	// Media lookup shares the same message resolver and must reject before the
	// disconnected/download checks, giving the caller actionable candidates.
	regressionAmbiguous(t, cs, "download_media", map[string]any{"message_id": "DUPLICATE-ID"}, alice.String(), group.String())
	for _, chat := range []types.JID{alice, group} {
		var out ContextOut
		call(t, cs, "get_message_context", map[string]any{"chat": chat.String(), "message_id": "DUPLICATE-ID", "before": 1, "after": 1}, &out)
		if out.Target == nil || out.Target.ChatJID != chat.String() {
			t.Errorf("explicit chat did not disambiguate: %+v", out.Target)
		}
	}
	var unique ContextOut
	call(t, cs, "get_message_context", map[string]any{"message_id": "A1", "before": 1, "after": 1}, &unique)
	if unique.Target == nil || unique.Target.ChatJID != alice.String() {
		t.Errorf("unique unqualified ID must remain supported: %+v", unique.Target)
	}
}

func TestPrelinkExactNameAmbiguity(t *testing.T) {
	cs, wa := setup(t)
	ctx := context.Background()
	g1 := types.NewJID("120363000000000106", types.GroupServer)
	g2 := types.NewJID("120363000000000107", types.GroupServer)
	c1 := types.NewJID("491533333331", types.DefaultUserServer)
	c2 := types.NewJID("491533333332", types.DefaultUserServer)
	for i, chat := range []types.JID{g1, g2} {
		if err := wa.ingestMessage(ctx, textMsg(chat, alice, fmt.Sprintf("NAME-G%d", i), t0.Add(time.Hour), "name ambiguity fixture")); err != nil {
			t.Fatal(err)
		}
		if err := wa.store.SetChatName(ctx, chat.String(), true, []string{"Shared Team", "SHARED TEAM"}[i]); err != nil {
			t.Fatal(err)
		}
	}
	for i, contact := range []types.JID{c1, c2} {
		if err := wa.Client.Store.Contacts.PutContactName(ctx, contact, "Sam", []string{"Sam Same", "SAM SAME"}[i]); err != nil {
			t.Fatal(err)
		}
		if err := wa.ingestMessage(ctx, textMsg(contact, contact, fmt.Sprintf("NAME-C%d", i), t0.Add(time.Hour), "name ambiguity fixture")); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("group_exact_casefold", func(t *testing.T) {
		regressionAmbiguous(t, cs, "get_chat", map[string]any{"chat": "sHaReD tEaM"}, g1.String(), g2.String())
		regressionAmbiguous(t, cs, "list_messages", map[string]any{"chat": "Shared Team"}, g1.String(), g2.String())
	})
	t.Run("contact_exact_casefold", func(t *testing.T) {
		regressionAmbiguous(t, cs, "search_messages", map[string]any{"query": "name ambiguity fixture", "sender": "sAm SaMe"}, c1.String(), c2.String())
		regressionAmbiguous(t, cs, "list_messages", map[string]any{"chat": "Sam Same"}, c1.String(), c2.String())
	})
	for _, chat := range []types.JID{g1, g2, c1, c2} {
		var got MessagesOut
		call(t, cs, "list_messages", map[string]any{"chat": chat.String()}, &got)
		if len(got.Messages) != 1 || got.Messages[0].ChatJID != chat.String() {
			t.Errorf("explicit JID must work: %s %+v", chat, got)
		}
	}
	var unique MessagesOut
	call(t, cs, "list_messages", map[string]any{"chat": "Alice Anders"}, &unique)
	if len(unique.Messages) != 4 {
		t.Errorf("unique exact contact regressed: %+v", unique)
	}
	call(t, cs, "list_messages", map[string]any{"chat": "Team Lunch"}, &unique)
	if len(unique.Messages) != 2 {
		t.Errorf("unique exact group regressed: %+v", unique)
	}
}

func TestPrelinkArchiveOnlySenderMe(t *testing.T) {
	owner, wa := setup(t)
	ctx := context.Background()
	own := wa.Client.Store.ID.ToNonAD()
	for i, mine := range []bool{true, false, true} {
		sender := alice
		if mine {
			sender = own
		}
		evt := textMsg(alice, sender, fmt.Sprintf("OWN-%d", i), t0.Add(time.Duration(i+20)*time.Minute), "persisted identity fixture")
		evt.Info.IsFromMe = mine
		if err := wa.ingestMessage(ctx, evt); err != nil {
			t.Fatal(err)
		}
	}
	// A separate encrypted DB handle and Store cannot obtain identity from a WA
	// object. The only account available to this App is the persisted fixture.
	db, err := securestore.Open(filepath.Join(wa.dataDir, "whatsapp.db"), false, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	reader := regressionClient(t, &App{store: NewStore(db), wa: nil, mode: "archive-reader"})
	var status StatusOut
	call(t, reader, "whatsapp_status", nil, &status)
	if status.Account != own.String() || !status.LoggedIn {
		t.Fatalf("persisted synthetic identity absent: %+v", status)
	}
	for name, cs := range map[string]*mcp.ClientSession{"owner": owner, "archive_only": reader} {
		t.Run(name, func(t *testing.T) {
			for _, tool := range []string{"list_messages", "search_messages"} {
				t.Run(tool, func(t *testing.T) {
					args := map[string]any{"chat": alice.String(), "sender": own.String()}
					if tool == "search_messages" {
						args["query"] = "persisted identity fixture"
					}
					var explicit, mine MessagesOut
					call(t, cs, tool, args, &explicit)
					want := []string{"A0", "OWN-0", "OWN-2"}
					if tool == "search_messages" {
						want = []string{"OWN-0", "OWN-2"}
					}
					if !reflect.DeepEqual(regressionIDs(explicit.Messages), want) {
						t.Fatalf("explicit own JID control: got %v want %v", regressionIDs(explicit.Messages), want)
					}
					t.Logf("explicit persisted own JID control passed: %v", want)
					args["sender"] = "me"
					call(t, cs, tool, args, &mine)
					if !reflect.DeepEqual(regressionIDs(mine.Messages), want) {
						t.Errorf("sender=me: got %v want %v", regressionIDs(mine.Messages), want)
					}
					for _, m := range mine.Messages {
						if !m.FromMe || m.Sender != "me" || m.SenderJID != own.String() {
							t.Errorf("incorrect own attribution: %+v", m)
						}
					}
				})
			}
		})
	}
}
