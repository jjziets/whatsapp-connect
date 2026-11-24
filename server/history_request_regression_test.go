//go:build libsqlite3

package main

// Definition-only draft. Activate after accepted A HistorySnapshot handoff.
import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"
)

func requestHistoryFixture(t *testing.T, wa *WA, chat types.JID, ids ...string) {
	t.Helper()
	conv := &waHistorySync.Conversation{ID: proto.String(chat.String())}
	for _, id := range ids {
		conv.Messages = append(conv.Messages, &waHistorySync.HistorySyncMsg{Message: &waWeb.WebMessageInfo{
			Key:              &waCommon.MessageKey{RemoteJID: proto.String(chat.String()), Participant: proto.String(alice.String()), ID: proto.String(id)},
			MessageTimestamp: proto.Uint64(uint64(t0.Unix())), Message: &waE2E.Message{Conversation: proto.String("request observation fixture")},
		}})
	}
	wa.ingestHistory(context.Background(), &waHistorySync.HistorySync{SyncType: waHistorySync.HistorySync_ON_DEMAND.Enum(), Conversations: []*waHistorySync.Conversation{conv}})
}

type requestObservation struct {
	out RequestHistoryOut
	err error
}

// Only clock delivery is controlled. All snapshots/counters come from Store
// and real ingestion; this helper contains no substitute count algorithm.
func requestObserve(t *testing.T, app *App, chat string, before HistorySnapshot, nticks int, timeout bool) requestObservation {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks, deadline := make(chan time.Time), make(chan time.Time)
	done := make(chan requestObservation, 1)
	go func() {
		out, err := app.observeHistory(ctx, chat, 20, before, ticks, deadline)
		done <- requestObservation{out, err}
	}()
	// This real-time guard detects deadlock only; it never supplies a production
	// observation tick/deadline or decides the expected outcome.
	guard := time.NewTimer(3 * time.Second)
	defer guard.Stop()
	for i := 0; i < nticks; i++ {
		select {
		case ticks <- t0.Add(time.Duration(i) * time.Second):
		case got := <-done:
			return got
		case <-guard.C:
			t.Fatal("waiter failed to consume deterministic tick")
		}
	}
	if timeout {
		select {
		case deadline <- t0.Add(time.Minute):
		case got := <-done:
			return got
		case <-guard.C:
			t.Fatal("waiter failed to consume deterministic deadline")
		}
	}
	select {
	case got := <-done:
		return got
	case <-guard.C:
		t.Fatal("waiter did not terminate")
		return requestObservation{}
	}
}

func requestAssertOutput(t *testing.T, got requestObservation, count int, outcome string) {
	t.Helper()
	if got.err != nil {
		t.Fatalf("observeHistory: %v", got.err)
	}
	if got.out.NewMessages != count || got.out.Requested != 20 {
		t.Errorf("observation counts: got %+v want new_messages=%d requested=20", got.out, count)
	}
	data, err := json.Marshal(got.out)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["attribution"] != "observed_during_wait" || raw["wait_outcome"] != outcome {
		t.Errorf("missing explicit attribution/outcome: %s", data)
	}
	if raw["complete"] == true || raw["history_complete"] == true {
		t.Errorf("observing a delta cannot establish completeness: %s", data)
	}
	if outcome == "timeout" && (!strings.Contains(strings.ToLower(got.out.Note), "complet") || !strings.Contains(strings.ToLower(got.out.Note), "not")) {
		t.Errorf("timeout must explicitly state completeness is not established: %s", data)
	}
}

func TestPrelinkRequestHistoryObservedDelta(t *testing.T) {
	for _, scenario := range []string{"live_only", "selected_history_only", "replay_and_other_chat_only"} {
		t.Run(scenario, func(t *testing.T) {
			_, wa := setup(t)
			ctx := context.Background()
			if scenario == "replay_and_other_chat_only" {
				requestHistoryFixture(t, wa, group, "REQUEST-H1")
			}
			before, err := wa.store.HistoryProgress(ctx, group.String())
			if err != nil {
				t.Fatal(err)
			}
			if err := wa.ingestMessage(ctx, textMsg(group, alice, "REQUEST-LIVE", t0.Add(time.Hour), "live arrival during history wait")); err != nil {
				t.Fatal(err)
			}
			want := 0
			switch scenario {
			case "selected_history_only":
				requestHistoryFixture(t, wa, group, "REQUEST-H1", "REQUEST-H2")
				requestHistoryFixture(t, wa, group, "REQUEST-H1", "REQUEST-H2") // replay contributes zero
				requestHistoryFixture(t, wa, alice, "REQUEST-OTHER")            // different chat contributes zero
				want = 2
			case "replay_and_other_chat_only":
				requestHistoryFixture(t, wa, group, "REQUEST-H1")
				requestHistoryFixture(t, wa, alice, "REQUEST-OTHER")
			}
			final, err := wa.store.HistoryProgress(ctx, group.String())
			if err != nil {
				t.Fatal(err)
			}
			if final.OrderEpoch != before.OrderEpoch || final.HistoryInserted-before.HistoryInserted != int64(want) {
				t.Fatalf("actual producer precondition: before=%+v final=%+v want delta=%d", before, final, want)
			}
			got := requestObserve(t, &App{store: wa.store, wa: nil, mode: "archive-reader"}, group.String(), before, 3, want == 0)
			outcome := "observed"
			if want == 0 {
				outcome = "timeout"
			}
			requestAssertOutput(t, got, want, outcome)
		})
	}
}

func TestPrelinkRequestHistoryEpochChangeRejectsMergedDelta(t *testing.T) {
	_, wa := setup(t)
	ctx := context.Background()
	lid := types.NewJID("99880000388", types.HiddenUserServer)
	pn := types.NewJID("491544440388", types.DefaultUserServer)
	requestHistoryFixture(t, wa, lid, "REQUEST-MOVED")
	before, err := wa.store.HistoryProgress(ctx, pn.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := wa.Client.Store.LIDs.PutLIDMapping(ctx, lid, pn); err != nil {
		t.Fatal(err)
	}
	final, err := wa.store.HistoryProgress(ctx, pn.String())
	if err != nil {
		t.Fatal(err)
	}
	if final.OrderEpoch == before.OrderEpoch || final.HistoryInserted <= before.HistoryInserted {
		t.Fatalf("actual alias merge must change epoch and move count: before=%+v final=%+v", before, final)
	}
	got := requestObserve(t, &App{store: wa.store, wa: nil}, pn.String(), before, 1, false)
	if got.err == nil || (!strings.Contains(strings.ToLower(got.err.Error()), "identity") && !strings.Contains(strings.ToLower(got.err.Error()), "ordering")) {
		t.Errorf("epoch change requires explicit identity/ordering error: %+v", got)
	}
	if got.out.NewMessages != 0 {
		t.Errorf("merged counter delta falsely reported as new history: %+v", got.out)
	}
}

func TestPrelinkRequestHistoryReadFailureAndCancellation(t *testing.T) {
	for _, scenario := range []string{"read_failure", "cancelled", "timeout"} {
		t.Run(scenario, func(t *testing.T) {
			_, wa := setup(t)
			ctx := context.Background()
			before, err := wa.store.HistoryProgress(ctx, group.String())
			if err != nil {
				t.Fatal(err)
			}
			app := &App{store: wa.store, wa: nil}
			if scenario == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				out, err := app.observeHistory(cancelled, group.String(), 20, before, make(chan time.Time), make(chan time.Time))
				if !errors.Is(err, context.Canceled) || out.NewMessages != 0 {
					t.Errorf("cancellation must propagate without apparent success: out=%+v err=%v", out, err)
				}
				return
			}
			if scenario == "read_failure" {
				if err := wa.store.db.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := wa.store.HistoryProgress(ctx, group.String()); err == nil {
					t.Fatal("closed real database must fail HistoryProgress")
				}
			}
			got := requestObserve(t, app, group.String(), before, 1, scenario == "timeout")
			if scenario == "read_failure" {
				if got.err == nil || got.out.NewMessages != 0 {
					t.Errorf("Store read failure must propagate without a healthy default: out=%+v err=%v", got.out, got.err)
				}
			} else {
				requestAssertOutput(t, got, 0, "timeout")
			}
		})
	}
}
