//go:build libsqlite3

package main

// TASK-WC-SCHOOL-ALERTS-20261108 / REQ-WC-004: exact owner-managed selection.
// Manual Go trace mapping; automatic Go anchor scanning is unsupported.
import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/hansen/whatsapp-mcp/internal/securestore"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"
)

type schoolWireGroup struct {
	ChatJID        string `json:"chat_jid"`
	Name           string `json:"name"`
	SelectionState string `json:"selection_state"`
}
type schoolWireSelection struct {
	Initialized                bool              `json:"initialized"`
	Revision                   int64             `json:"revision"`
	Groups                     []schoolWireGroup `json:"groups"`
	ControlsScope              string            `json:"controls_scope"`
	SubscriptionChangesApplied bool              `json:"subscription_changes_applied"`
	NativeMonitorSyncRequired  bool              `json:"native_monitor_sync_required"`
	MonitoringStatus           string            `json:"monitoring_status"`
}

func schoolRead(t *testing.T, cs *mcp.ClientSession) schoolWireSelection {
	t.Helper()
	var out schoolWireSelection
	call(t, cs, "list_school_groups", map[string]any{}, &out)
	if out.Groups == nil || out.ControlsScope != "school_watchlist" || out.SubscriptionChangesApplied || !out.NativeMonitorSyncRequired || out.MonitoringStatus != "not_verified" {
		t.Fatalf("selection must report configured-only scope and native uncertainty: %+v", out)
	}
	return out
}
func schoolUpdate(t *testing.T, cs *mcp.ClientSession, action string, jids []string, revision int64) schoolWireSelection {
	t.Helper()
	var out schoolWireSelection
	call(t, cs, "update_school_groups", map[string]any{"action": action, "chat_jids": jids, "expected_revision": revision}, &out)
	if out.ControlsScope != "school_watchlist" || out.SubscriptionChangesApplied || !out.NativeMonitorSyncRequired || out.MonitoringStatus != "not_verified" {
		t.Fatalf("false native monitoring claim: %+v", out)
	}
	return out
}
func schoolReject(t *testing.T, cs *mcp.ClientSession, args map[string]any) {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "update_school_groups", Arguments: args})
	if err == nil && !result.IsError {
		t.Fatal("invalid update unexpectedly succeeded")
	}
	if err == nil && strings.Contains(regressionErrorText(result), "private SQL diagnostic") {
		t.Fatal("SQL diagnostic leaked through MCP")
	}
	if err == nil && len(regressionErrorText(result)) > 256 {
		t.Fatal("unbounded watchlist error")
	}
}
func schoolGroup(t *testing.T, app *App, n int, name string) string {
	t.Helper()
	jid := fmt.Sprintf("120363555%09d@g.us", n)
	if err := app.store.SetChatName(context.Background(), jid, true, name); err != nil {
		t.Fatal(err)
	}
	return jid
}

func TestSchoolWatchlistWirePersistenceAndControls(t *testing.T) {
	app, cleanup, dir := evOwnedApp(t)
	cs := regressionClient(t, app)
	tools, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := map[string]bool{}
	for _, tool := range tools.Tools {
		if tool.Name == "list_school_groups" || tool.Name == "update_school_groups" {
			if tool.Annotations == nil {
				t.Fatal("missing watchlist annotations")
			}
			annotations[tool.Name] = tool.Annotations.ReadOnlyHint
		}
	}
	if len(annotations) != 2 || !annotations["list_school_groups"] || annotations["update_school_groups"] {
		t.Fatalf("incorrect read/write tool annotations: %v", annotations)
	}
	initial := schoolRead(t, cs)
	if !initial.Initialized || initial.Revision != 0 || len(initial.Groups) != 0 {
		t.Fatalf("owner startup should initialize empty selection: %+v", initial)
	}
	j1, j2 := schoolGroup(t, app, 1, "HSS First"), schoolGroup(t, app, 2, "LSS Second")
	added := schoolUpdate(t, cs, "add", []string{j2, j1}, initial.Revision)
	if added.Revision != 1 || len(added.Groups) != 2 {
		t.Fatalf("add=%+v", added)
	}
	paused := schoolUpdate(t, cs, "pause", []string{j1}, added.Revision)
	if paused.Revision != 2 {
		t.Fatalf("pause=%+v", paused)
	}
	resumed := schoolUpdate(t, cs, "resume", []string{j1}, paused.Revision)
	if resumed.Revision != 3 {
		t.Fatalf("resume=%+v", resumed)
	}
	paused = schoolUpdate(t, cs, "pause", []string{j1}, resumed.Revision)
	if err := app.store.SetChatName(context.Background(), j1, true, "Renamed current group"); err != nil {
		t.Fatal(err)
	}
	current := schoolRead(t, cs)
	if len(current.Groups) != 2 || current.Groups[0] != (schoolWireGroup{j1, "Renamed current group", "paused"}) || current.Groups[1] != (schoolWireGroup{j2, "LSS Second", "active"}) {
		t.Fatalf("fresh label/stable exact identity/state: %+v", current)
	}
	before, err := app.store.CountMessages(context.Background(), group.String())
	if err != nil {
		t.Fatal(err)
	}
	removed := schoolUpdate(t, cs, "remove", []string{j2}, current.Revision)
	if len(removed.Groups) != 1 || removed.Groups[0].ChatJID != j1 {
		t.Fatalf("remove=%+v", removed)
	}
	after, err := app.store.CountMessages(context.Background(), group.String())
	if err != nil || before != after {
		t.Fatal("selection controls changed archive")
	}
	// Close the actual owner, then reopen the encrypted DB with a genuine read-only handle.
	cs.Close()
	cleanup()
	db, err := securestore.Open(filepath.Join(dir, "whatsapp.db"), true, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reader := regressionClient(t, &App{store: NewStore(db), mode: "archive-reader"})
	persisted := schoolRead(t, reader)
	if !reflect.DeepEqual(removed, persisted) {
		t.Fatalf("encrypted reopen lost selection: before=%+v after=%+v", removed, persisted)
	}
	schoolReject(t, reader, map[string]any{"action": "resume", "chat_jids": []string{j1}, "expected_revision": persisted.Revision})
}

func TestSchoolWatchlistAtomicValidationAndRevision(t *testing.T) {
	app, _, _ := evOwnedApp(t)
	cs := regressionClient(t, app)
	initial := schoolRead(t, cs)
	j1, j2 := schoolGroup(t, app, 11, "HSS A"), schoolGroup(t, app, 12, "Graad B")
	baseline := schoolUpdate(t, cs, "add", []string{j1}, initial.Revision)
	unknown := "120363555999999999@g.us"
	invalid := [][]string{{j2, alice.String()}, {j2, unknown}, {j2, "HSS"}, {j2, "*@g.us"}, {j2, strings.Replace(j1, "@", ":1@", 1)}, {j2, j2}, {" " + j2}, {j2, "bad@g.us"}, {}}
	for _, jids := range invalid {
		schoolReject(t, cs, map[string]any{"action": "add", "chat_jids": jids, "expected_revision": baseline.Revision})
		if got := schoolRead(t, cs); !reflect.DeepEqual(got, baseline) {
			t.Fatalf("failed validation partially mutated list: ids=%v got=%+v", jids, got)
		}
	}
	for _, action := range []string{"remove", "pause", "resume"} {
		schoolReject(t, cs, map[string]any{"action": action, "chat_jids": []string{j1, unknown}, "expected_revision": baseline.Revision})
		if got := schoolRead(t, cs); !reflect.DeepEqual(got, baseline) {
			t.Fatal("unknown selection partially changed batch")
		}
	}
	schoolReject(t, cs, map[string]any{"action": "add", "chat_jids": []string{j2}, "expected_revision": baseline.Revision - 1})
	schoolReject(t, cs, map[string]any{"action": "add", "chat_jids": []string{j2}})
	schoolReject(t, cs, map[string]any{"action": "replace", "chat_jids": []string{j2}, "expected_revision": baseline.Revision})
	// Two real concurrent MCP updates with one revision: exactly one can commit.
	var wg sync.WaitGroup
	successes := make(chan bool, 2)
	for _, action := range []string{"pause", "remove"} {
		wg.Add(1)
		go func(action string) {
			defer wg.Done()
			r, e := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "update_school_groups", Arguments: map[string]any{"action": action, "chat_jids": []string{j1}, "expected_revision": baseline.Revision}})
			successes <- e == nil && !r.IsError
		}(action)
	}
	wg.Wait()
	close(successes)
	count := 0
	for ok := range successes {
		if ok {
			count++
		}
	}
	if count != 1 || schoolRead(t, cs).Revision != baseline.Revision+1 {
		t.Fatalf("CAS committed %d updates", count)
	}
}

func TestSchoolWatchlistDatabaseFailureRollsBack(t *testing.T) {
	app, _, _ := evOwnedApp(t)
	cs := regressionClient(t, app)
	baseline := schoolRead(t, cs)
	j1, j2 := schoolGroup(t, app, 21, "HSS Good"), schoolGroup(t, app, 22, "LSS Failure")
	_, err := app.store.db.Exec(`CREATE TRIGGER reject_school_selection BEFORE INSERT ON mcp_school_watchlist WHEN NEW.chat_jid = '` + j2 + `' BEGIN SELECT RAISE(FAIL,'private SQL diagnostic must stay internal'); END`)
	if err != nil {
		t.Fatal(err)
	}
	schoolReject(t, cs, map[string]any{"action": "add", "chat_jids": []string{j1, j2}, "expected_revision": baseline.Revision})
	if got := schoolRead(t, cs); !reflect.DeepEqual(got, baseline) {
		t.Fatalf("SQL failure committed partial selection/revision: %+v", got)
	}
}

func TestSchoolWatchlistCapacityAndIdempotentActions(t *testing.T) {
	app, _, _ := evOwnedApp(t)
	cs := regressionClient(t, app)
	baseline := schoolRead(t, cs)
	var jids []string
	for n := 0; n < 33; n++ {
		jids = append(jids, schoolGroup(t, app, 100+n, fmt.Sprintf("HSS %d", n)))
	}
	schoolReject(t, cs, map[string]any{"action": "add", "chat_jids": jids, "expected_revision": baseline.Revision})
	selected := schoolUpdate(t, cs, "add", jids[:32], baseline.Revision)
	if len(selected.Groups) != 32 {
		t.Fatal("max32 selection not supported")
	}
	schoolReject(t, cs, map[string]any{"action": "add", "chat_jids": jids[32:], "expected_revision": selected.Revision})
	if got := schoolRead(t, cs); !reflect.DeepEqual(got, selected) {
		t.Fatal("capacity overflow mutated selection")
	}
	duplicate := schoolUpdate(t, cs, "add", jids[:1], selected.Revision)
	if !reflect.DeepEqual(selected, duplicate) {
		t.Fatal("existing exact add should be idempotent without revision advance")
	}
}

func TestSchoolWatchlistReaderNoMigrationAndOwnerFence(t *testing.T) {
	_, w := setup(t)
	var before int
	if err := w.store.db.QueryRow(`SELECT count(*) FROM sqlite_master`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	reader := regressionClient(t, &App{store: w.store, mode: "archive-reader"})
	unconfigured := schoolRead(t, reader)
	if unconfigured.Initialized || unconfigured.Revision != 0 || len(unconfigured.Groups) != 0 {
		t.Fatalf("legacy reader should be unconfigured: %+v", unconfigured)
	}
	schoolReject(t, reader, map[string]any{"action": "add", "chat_jids": []string{group.String()}, "expected_revision": int64(0)})
	var after int
	if err := w.store.db.QueryRow(`SELECT count(*) FROM sqlite_master`).Scan(&after); err != nil || after != before {
		t.Fatal("reader migrated schema")
	}
	owner, _, _ := evOwnedApp(t)
	baseline := schoolRead(t, regressionClient(t, owner))
	for _, invalid := range []*App{{store: owner.store, wa: owner.wa}, {store: w.store, wa: owner.wa, authority: owner.authority}} {
		client := regressionClient(t, invalid)
		schoolReject(t, client, map[string]any{"action": "add", "chat_jids": []string{group.String()}, "expected_revision": baseline.Revision})
	}
	owner.authority.held.Store(false)
	schoolReject(t, regressionClient(t, owner), map[string]any{"action": "add", "chat_jids": []string{group.String()}, "expected_revision": baseline.Revision})
}

func TestSchoolWatchlistUnknownSchemaFailsClosed(t *testing.T) {
	for _, version := range []string{"2", "invalid"} {
		t.Run(version, func(t *testing.T) {
			app, cleanup, dir := evOwnedApp(t)
			cs := regressionClient(t, app)
			initial := schoolRead(t, cs)
			jid := schoolGroup(t, app, 301, "HSS retained")
			selected := schoolUpdate(t, cs, "add", []string{jid}, initial.Revision)
			if _, err := app.store.db.Exec(`UPDATE mcp_meta SET value=? WHERE key='school_watchlist_schema_version'`, version); err != nil {
				t.Fatal(err)
			}
			before := map[string]string{}
			rows, err := app.store.db.Query(`SELECT key,value FROM mcp_meta WHERE key LIKE 'school_watchlist_%'`)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var key, value string
				if err := rows.Scan(&key, &value); err != nil {
					t.Fatal(err)
				}
				before[key] = value
			}
			if err := rows.Close(); err != nil {
				t.Fatal(err)
			}
			if before["school_watchlist_schema_version"] != version {
				t.Fatal("version fixture was not applied")
			}
			reader := regressionClient(t, &App{store: app.store, mode: "archive-reader"})
			result, err := reader.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_school_groups", Arguments: map[string]any{}})
			if err == nil && !result.IsError {
				t.Fatal("reader accepted unsupported school schema")
			}
			reader.Close()
			cs.Close()
			cleanup()
			_, closeUnexpected, err := openForServeWith(context.Background(), dir, zerolog.Nop(), ServeDependencies{ArchiveKeys: evArchiveKeys{}, Connect: func(context.Context, *WA) error { return nil }})
			if err == nil {
				closeUnexpected()
				t.Fatal("owner migrated unsupported school schema")
			}
			db, err := securestore.Open(filepath.Join(dir, "whatsapp.db"), true, bytes.Repeat([]byte{0x42}, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			after := map[string]string{}
			rows, err = db.Query(`SELECT key,value FROM mcp_meta WHERE key LIKE 'school_watchlist_%'`)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var key, value string
				if err := rows.Scan(&key, &value); err != nil {
					t.Fatal(err)
				}
				after[key] = value
			}
			if err := rows.Close(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("rejected startup mutated school metadata: %v -> %v", before, after)
			}
			var state string
			if err := db.QueryRow(`SELECT selection_state FROM mcp_school_watchlist WHERE chat_jid=?`, jid).Scan(&state); err != nil || state != selected.Groups[0].SelectionState {
				t.Fatalf("rejected startup changed desired selection: %q %v", state, err)
			}
		})
	}
}
