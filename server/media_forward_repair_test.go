//go:build libsqlite3

package main

// TRACEWEAVER: C-007 / TRACE-OWNERMSG-007 / VER-OWNERMSG-007.
import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"image/color"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
)

func repairAssertRestricted(t *testing.T, cs *mcp.ClientSession, args map[string]any) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "prepare_media_forward", Arguments: args})
	if err != nil || !res.IsError || len(res.Content) == 0 || !strings.Contains(fmt.Sprint(res.Content[0]), "restricted") {
		t.Fatalf("affirmatively restricted source must reject the preview: %v, %v", res, err)
	}
}

func repairAssertStaleWriteRejected(t *testing.T, cs *mcp.ClientSession, p map[string]any) {
	t.Helper()
	delete(p, "confirmation_notice")
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "forward_media", Arguments: p})
	if err != nil || !res.IsError {
		t.Fatalf("stale approval for newly restricted source must reject before reservation: %v, %v", res, err)
	}
}

func repairSyntheticForwardMedia(t *testing.T, w *WA, chat types.JID, id string, plain []byte) {
	t.Helper()
	dir := filepath.Join(w.dataDir, "media", chat.String())
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".jpg"), plain, 0600); err != nil {
		t.Fatal(err)
	}
	spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(req *http.Request) (*http.Response, error) {
		return spResponse(req, []byte(`{"url":"https://mmg.whatsapp.net/synthetic","direct_path":"/synthetic"}`), -1), nil
	})}, "mmg.whatsapp.net")
}

func repairLiveInfo(chat, sender types.JID, id string) types.MessageInfo {
	return types.MessageInfo{
		MessageSource: types.MessageSource{Chat: chat, Sender: sender, IsGroup: chat.Server == types.GroupServer},
		ID:            id,
		Timestamp:     t0,
	}
}

func repairDispatchEvent(t *testing.T, w *WA, event any) {
	t.Helper()
	// This is the pinned SDK's dispatch method and calls the registered owner
	// callback without starting a real provider session.
	if w.Client.DangerousInternals().DispatchEvent(event) {
		t.Fatal("pinned SDK event dispatch failed")
	}
}

func repairHistory(w *WA, web *waWeb.WebMessageInfo) {
	w.ingestHistory(context.Background(), &waHistorySync.HistorySync{
		Conversations: []*waHistorySync.Conversation{{
			ID:       proto.String(group.String()),
			Messages: []*waHistorySync.HistorySyncMsg{{Message: web}},
		}},
	})
}

func TestMediaForwardRepairAfterRead(t *testing.T) {
	for _, shape := range []string{"live", "history", "legacy-raw", "prepared-then-duplicate"} {
		t.Run(shape, func(t *testing.T) {
			a, transport := messageApp(t)
			w := a.wa
			cs := regressionClient(t, a)
			id := "fixture-after-read-" + shape
			msg, _ := mediaForwardContractImage(t, "Synthetic after-read timer", color.RGBA{R: 90, A: 255})
			var preview map[string]any
			if shape == "prepared-then-duplicate" {
				archiveIngest(t, w, group, bob, id, t0, msg, false)
				preview = mediaForwardTestPreview(t, cs, id)
			}
			msg.ImageMessage.ContextInfo = &waE2E.ContextInfo{AfterReadDuration: proto.Uint32(60)}
			switch shape {
			case "history":
				repairHistory(w, archiveWeb(group, bob, id, t0, msg))
			case "legacy-raw":
				raw, err := proto.Marshal(msg)
				if err != nil {
					t.Fatal(err)
				}
				// Model the earlier archive writer that stored only the normalized
				// payload and retained no forward provenance.
				if err := w.store.UpsertMessage(context.Background(), &StoredMessage{
					ChatJID: group.String(), ID: id, SenderJID: bob.String(), Timestamp: t0,
					Content: extractContent(msg), Raw: raw,
				}); err != nil {
					t.Fatal(err)
				}
			default:
				event := &events.Message{Info: repairLiveInfo(group, bob, id), RawMessage: msg}
				repairDispatchEvent(t, w, event.UnwrapRaw())
			}
			if preview != nil {
				repairAssertStaleWriteRejected(t, cs, preview)
			}
			repairAssertRestricted(t, cs, mediaForwardTestArgs(id))
			if (preview != nil && mediaForwardContractOutbox(t, a)[1] != 0) || transport.calls.Load() != 0 {
				t.Fatal("restricted after-read item produced a reservation or recipient invocation")
			}
		})
	}
}

func TestMediaForwardRepairHistorySignals(t *testing.T) {
	a, _ := messageApp(t)
	w := a.wa
	cs := regressionClient(t, a)
	for _, signal := range []string{"admin-revoke", "revoke-time", "history-edited", "history-edited-bodyless"} {
		for _, before := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/before-original=%t", signal, before), func(t *testing.T) {
				id := fmt.Sprintf("fixture-%s-%t", signal, before)
				msg, _ := mediaForwardContractImage(t, "Synthetic original photo", color.RGBA{G: 179, A: 255})
				ordinary := func() { archiveIngest(t, w, group, bob, id, t0, msg, false) }
				if !before {
					ordinary()
				}
				web := archiveWeb(group, bob, id, t0, nil)
				switch signal {
				case "admin-revoke":
					web.MessageStubType = waWeb.WebMessageInfo_ADMIN_REVOKE.Enum()
				case "revoke-time":
					web.RevokeMessageTimestamp = proto.Uint64(uint64(t0.Unix() + 60))
				default:
					web.GroupHistoryIndividualMessageInfo = &waWeb.GroupHistoryIndividualMessageInfo{EditedAfterReceivedAsHistory: proto.Bool(true)}
					if signal == "history-edited" {
						web.Message = msg
					}
				}
				repairHistory(w, web)
				if before {
					ordinary()
				}
				repairAssertRestricted(t, cs, mediaForwardTestArgs(id))
				if got := archiveMessage(t, w, group, id); got.Deleted || got.Edited || got.Text != msg.GetImageMessage().GetCaption() {
					t.Fatal("forwarding privacy witness changed the ordinary archive reducer")
				}
			})
		}
	}
}

func TestMediaForwardRepairHistoryBeforeParsing(t *testing.T) {
	for _, tc := range []struct {
		name         string
		before       bool
		unrestricted bool
	}{
		{name: "admin-before-original", before: true},
		{name: "admin-after-preview"},
		{name: "revoke-stub"},
		{name: "revoke-timestamp"},
		{name: "history-edit"},
		{name: "raw-after-read"},
		{name: "conversation-sharing-limit"},
		{name: "invalid-alias-metadata"},
		{name: "ordinary-senderless", before: true, unrestricted: true},
		{name: "missing-message-id", unrestricted: true},
		{name: "mismatched-chat", unrestricted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			a, transport := messageApp(t)
			w := a.wa
			cs := regressionClient(t, a)
			chat := group
			badAlias := tc.name == "invalid-alias-metadata"
			if badAlias {
				chat = bob
			}
			const id = "fixture-history-marker"
			msg, plain := mediaForwardContractImage(t, "Synthetic original photo", color.RGBA{G: 179, A: 255})
			ordinary := func() { archiveIngest(t, w, chat, bob, id, t0, msg, false) }
			args := mediaForwardTestArgs(id)
			args["source_chat_jid"] = chat.String()
			var preview map[string]any
			if !tc.before {
				ordinary()
				call(t, cs, "prepare_media_forward", args, &preview)
			}
			if preview != nil && !tc.unrestricted {
				// A hypothetical erroneous dispatch can reach only synthetic
				// upload and recipient transports, with no provider connection.
				repairSyntheticForwardMedia(t, w, chat, id, plain)
			}

			// Build the provider history item without either optional participant
			// field. The SDK infers direct senders, while the group parser fails.
			web := &waWeb.WebMessageInfo{
				Key:              &waCommon.MessageKey{RemoteJID: proto.String(chat.String()), ID: proto.String(id)},
				MessageTimestamp: proto.Uint64(uint64(t0.Unix())),
			}
			chunk := archiveChunk(chat, web)
			switch tc.name {
			case "admin-before-original", "admin-after-preview":
				web.MessageStubType = waWeb.WebMessageInfo_ADMIN_REVOKE.Enum()
			case "revoke-stub":
				web.MessageStubType = waWeb.WebMessageInfo_REVOKE.Enum()
			case "revoke-timestamp", "invalid-alias-metadata":
				web.RevokeMessageTimestamp = proto.Uint64(uint64(t0.Unix() + 60))
			case "history-edit":
				web.GroupHistoryIndividualMessageInfo = &waWeb.GroupHistoryIndividualMessageInfo{EditedAfterReceivedAsHistory: proto.Bool(true)}
			case "raw-after-read":
				inner := proto.CloneOf(msg)
				inner.ImageMessage.ContextInfo = &waE2E.ContextInfo{AfterReadDuration: proto.Uint32(60)}
				web.Message = &waE2E.Message{DeviceSentMessage: &waE2E.DeviceSentMessage{Message: inner}}
			case "conversation-sharing-limit":
				chunk.Conversations[0].LimitSharing = proto.Bool(true)
			case "ordinary-senderless":
				web.Message = proto.CloneOf(msg)
			case "missing-message-id":
				web.MessageStubType = waWeb.WebMessageInfo_ADMIN_REVOKE.Enum()
				web.Key.ID = nil
			case "mismatched-chat":
				web.MessageStubType = waWeb.WebMessageInfo_ADMIN_REVOKE.Enum()
				web.Key.RemoteJID = proto.String(alice.String())
			}
			if badAlias {
				chunk.Conversations[0].LidJID = proto.String("9999:not-a-device@lid")
			}
			w.ingestHistory(ctx, chunk)
			telemetry, err := w.store.IngestTelemetry(ctx)
			wantParse, wantMetadata, wantCode := int64(1), int64(0), "history_message_parse_failed"
			if badAlias {
				wantParse, wantMetadata, wantCode = 0, 1, "history_alias_failed"
			}
			if err != nil || telemetry.HistoryReceived != 1 || telemetry.HistoryFailed != 1 ||
				telemetry.HistoryParseFailed != wantParse || telemetry.HistoryMetadataFailed != wantMetadata ||
				telemetry.HistoryInserted != 0 || telemetry.LastErrorCode != wantCode {
				t.Fatalf("history failure telemetry changed: %+v, %v", telemetry, err)
			}
			if tc.before {
				if _, err := w.store.RawMessage(ctx, chat.String(), id); !errors.Is(err, sql.ErrNoRows) {
					t.Fatalf("unparsed history created a message row: %v", err)
				}
				ordinary()
			}
			if got := archiveMessage(t, w, chat, id); got.Deleted || got.Edited || got.Text != msg.GetImageMessage().GetCaption() {
				t.Fatal("history restriction changed the archived original")
			}
			if tc.unrestricted {
				var got map[string]any
				call(t, cs, "prepare_media_forward", args, &got)
				if got["source_provenance"] != "known_ordinary" {
					t.Fatal("unbound or ordinary senderless history affected independent provenance")
				}
				return
			}
			if preview != nil {
				t.Run("stale-write", func(t *testing.T) { repairAssertStaleWriteRejected(t, cs, preview) })
			}
			t.Run("preview", func(t *testing.T) { repairAssertRestricted(t, cs, args) })
			if reservations, calls := mediaForwardContractOutbox(t, a)[1], transport.calls.Load(); reservations != 0 || calls != 0 {
				t.Fatalf("history restriction allowed %d reservations and %d recipient invocations", reservations, calls)
			}
		})
	}
}

func TestMediaForwardRepairUnavailableViewOnce(t *testing.T) {
	a, _ := messageApp(t)
	w := a.wa
	cs := regressionClient(t, a)
	for _, shape := range []string{"before-original", "after-original", "generic-control"} {
		t.Run(shape, func(t *testing.T) {
			id := "fixture-view-once-event-" + shape
			ordinary := func() {
				msg, _ := mediaForwardContractImage(t, "Synthetic ordinary copy", color.RGBA{B: 213, A: 255})
				archiveIngest(t, w, group, bob, id, t0, msg, true)
			}
			if shape != "before-original" {
				ordinary()
			}
			event := &events.UndecryptableMessage{Info: repairLiveInfo(group, bob, id)}
			if shape != "generic-control" {
				event.IsUnavailable, event.UnavailableType = true, events.UnavailableTypeViewOnce
			}
			repairDispatchEvent(t, w, event)
			if shape == "before-original" {
				ordinary()
			}
			if shape == "generic-control" {
				if p := mediaForwardTestPreview(t, cs, id); p["source_provenance"] != "known_ordinary" {
					t.Fatal("generic decryption failure overrode independent provenance")
				}
			} else {
				repairAssertRestricted(t, cs, mediaForwardTestArgs(id))
			}
		})
	}
}

func TestMediaForwardRepairExpiryDuringFinalLookup(t *testing.T) {
	a, transport := messageApp(t)
	w := a.wa
	const id = "fixture-expiry-final-lookup"
	msg, data := mediaForwardContractImage(t, "Synthetic approval deadline", color.RGBA{B: 185, A: 255})
	archiveIngest(t, w, group, bob, id, t0, msg, false)
	dir := filepath.Join(w.dataDir, "media", group.String())
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".jpg"), data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, preview, err := a.prepareMediaForward(ctx, nil, PrepareMediaForwardArgs{
		RequestID: "fixture-expiry", SourceChatJID: group.String(), SourceMessageID: id, ChatJID: alice.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	p := preview.ForwardMediaArgs
	expires := time.Now().Add(2 * time.Second)
	p.ExpiresAt = expires.Format(time.RFC3339Nano)
	p.PayloadDigest = p.digest()
	type heldUpload struct{ deadline time.Time }
	held := make(chan heldUpload, 1)
	spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			return nil, errors.New("unexpected fixture HTTP method")
		}
		_ = req.Body.Close()
		// Hold a real late read in Store.Names, after the slow transfer.
		w.store.namesMu.Lock()
		deadline, _ := req.Context().Deadline()
		held <- heldUpload{deadline: deadline}
		response := []byte(`{"url":"https://mmg.whatsapp.net/fixture","direct_path":"/fixture?a=1"}`)
		return spResponse(req, response, int64(len(response))), nil
	})}, "mmg.whatsapp.net")
	type result struct {
		status SendStatus
		err    error
	}
	done := make(chan result, 1)
	go func() {
		_, status, err := a.forwardMedia(ctx, nil, p)
		done <- result{status: status, err: err}
	}()
	var post heldUpload
	select {
	case post = <-held:
	case r := <-done:
		t.Fatalf("forward returned before provider upload: %v, %v", r.status.State, r.err)
	case <-time.After(time.Second):
		t.Fatal("forward never reached fixture upload")
	}
	locked := true
	defer func() {
		if locked {
			w.store.namesMu.Unlock()
		}
	}()
	// Observe the exact final validation goroutine reaching the held lookup
	// before advancing past expiry. The test never depends on an assumed sleep
	// long enough for the goroutine to enter that lookup.
	stacks := make([]byte, 512*1024)
	for {
		n := runtime.Stack(stacks, true)
		atLookup := false
		for _, stack := range strings.Split(string(stacks[:n]), "\n\n") {
			if strings.Contains(stack, "(*Store).Names") && strings.Contains(stack, "validateFreshMediaForward") &&
				strings.Contains(stack, "dispatchReservedMedia") && strings.Contains(stack, "sync.(*Mutex).Lock") {
				atLookup = true
				break
			}
		}
		if atLookup {
			break
		}
		if time.Until(expires) < 150*time.Millisecond {
			t.Fatal("could not witness in-flight final lookup before expiry")
		}
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(time.Until(expires) + 10*time.Millisecond)
	w.store.namesMu.Unlock()
	locked = false
	var first result
	select {
	case first = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch did not settle after the held final lookup was released")
	}
	if first.err != nil || transport.calls.Load() != 0 || first.status.State != "rejected" {
		t.Errorf("expired approval crossed recipient boundary: state=%q calls=%d err=%v", first.status.State, transport.calls.Load(), first.err)
	}
	if !post.deadline.Equal(expires) {
		t.Errorf("fixture upload context exceeded approval expiry: deadline=%s expiry=%s", post.deadline, expires)
	}
	_, repeat, err := a.forwardMedia(ctx, nil, p)
	if err != nil || repeat.State != "rejected" || repeat.MessageID != first.status.MessageID || transport.calls.Load() != 0 {
		t.Errorf("expired durable replay did not return the original rejection without a send: %v, %v", repeat.State, err)
	}
}

func TestMediaForwardRepairConflictingVerifiedAlias(t *testing.T) {
	ctx := context.Background()
	a, transport := messageApp(t)
	w := a.wa
	pn := types.NewJID("491522855511", types.DefaultUserServer)
	lid := types.NewJID("99882255", types.HiddenUserServer)
	const id = "fixture-alias-merge-conflict"
	msg, _ := mediaForwardContractImage(t, "Synthetic alias conflict", color.RGBA{R: 130, A: 255})
	archiveIngest(t, w, pn, pn, id, t0, msg, false)
	cs := regressionClient(t, a)
	args := mediaForwardTestArgs(id)
	args["source_chat_jid"] = pn.String()
	var p map[string]any
	call(t, cs, "prepare_media_forward", args, &p)

	wrapped := &waE2E.Message{ViewOnceMessage: &waE2E.FutureProofMessage{Message: msg}}
	archiveIngest(t, w, lid, lid, id, t0.Add(time.Minute), wrapped, true)
	err := w.Client.Store.LIDs.PutLIDMapping(ctx, lid, pn)
	if err == nil || !strings.Contains(err.Error(), "archive identity reconciliation") {
		t.Fatalf("verified observer must still refuse incompatible archive originals: %v", err)
	}
	// Confirm both the provider-side durability and the unchanged archive
	// identity conflict, rather than injecting or assuming a conflicting map.
	var durableLID string
	if err := w.store.db.QueryRowContext(ctx, "SELECT lid FROM whatsmeow_lid_map WHERE pn=?", pn.User).Scan(&durableLID); err != nil || durableLID != lid.User {
		t.Fatalf("provider mapping did not commit before the archive rollback: %v", err)
	}
	if j, err := w.store.CanonicalJID(ctx, lid); err != nil || j != lid {
		t.Fatalf("conflicting immutable archive originals were merged: %v, %v", j, err)
	}
	t.Run("stale-write", func(t *testing.T) { repairAssertStaleWriteRejected(t, cs, p) })
	t.Run("preview", func(t *testing.T) { repairAssertRestricted(t, cs, args) })
	if transport.calls.Load() != 0 || mediaForwardContractOutbox(t, a)[1] != 0 {
		t.Fatal("conflicting verified alias produced a reservation or recipient invocation")
	}
}

func TestMediaForwardRepairHistoryMixedChatAfterAliasConflict(t *testing.T) {
	for _, shape := range []string{"lid-conversation", "pn-conversation", "unrelated-pn-key", "unverified-lid-key"} {
		t.Run(shape, func(t *testing.T) {
			ctx := context.Background()
			a, transport := messageApp(t)
			w := a.wa
			pn := types.NewJID("491522855511", types.DefaultUserServer)
			lid := types.NewJID("99882255", types.HiddenUserServer)
			const id, conflictID = "fixture-selected-pn-photo", "fixture-independent-alias-conflict"
			msg, plain := mediaForwardContractImage(t, "Synthetic PN-only photo", color.RGBA{G: 160, A: 255})
			archiveIngest(t, w, pn, pn, id, t0, msg, false)
			archiveIngest(t, w, pn, pn, conflictID, t0, archiveText("PN conflict original"), false)
			archiveIngest(t, w, lid, lid, conflictID, t0.Add(time.Minute), archiveText("LID conflict original"), false)

			// The actual observer can commit the SDK pair while the separate
			// archive merge refuses an immutable collision on another item.
			err := w.Client.Store.LIDs.PutLIDMapping(ctx, lid, pn)
			if err == nil || !strings.Contains(err.Error(), "archive identity reconciliation") {
				t.Fatalf("expected independent archive alias merge refusal: %v", err)
			}
			var durableLID string
			if err := w.store.db.QueryRowContext(ctx, "SELECT lid FROM whatsmeow_lid_map WHERE pn=?", pn.User).Scan(&durableLID); err != nil || durableLID != lid.User {
				t.Fatalf("verified mapping did not commit before archive refusal: %q, %v", durableLID, err)
			}
			if _, err := w.store.RawMessage(ctx, lid.String(), id); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("selected item must only exist at its PN before history: %v", err)
			}
			cs := regressionClient(t, a)
			args := mediaForwardTestArgs(id)
			args["source_chat_jid"] = pn.String()
			var preview map[string]any
			call(t, cs, "prepare_media_forward", args, &preview)
			if preview["source_provenance"] != "known_ordinary" {
				t.Fatal("selected PN item must have ordinary provenance before history")
			}
			repairSyntheticForwardMedia(t, w, pn, id, plain)

			chat, itemChat := lid, pn
			switch shape {
			case "pn-conversation":
				chat, itemChat = pn, lid
			case "unrelated-pn-key":
				itemChat = alice
			case "unverified-lid-key":
				chat, itemChat = pn, types.NewJID("99882256", types.HiddenUserServer)
			}
			web := &waWeb.WebMessageInfo{
				Key:                    &waCommon.MessageKey{RemoteJID: proto.String(itemChat.String()), ID: proto.String(id)},
				MessageTimestamp:       proto.Uint64(uint64(t0.Unix())),
				RevokeMessageTimestamp: proto.Uint64(uint64(t0.Unix() + 60)),
			}
			chunk := archiveChunk(chat, web)
			if chat == pn {
				chunk.Conversations[0].LidJID = proto.String(lid.String())
			}
			w.ingestHistory(ctx, chunk)
			telemetry, err := w.store.IngestTelemetry(ctx)
			// The per-conversation reconciliation and the end-of-batch
			// reconciliation retry both encounter the same independent row.
			if err != nil || telemetry.HistoryReceived != 1 || telemetry.HistoryFailed != 1 ||
				telemetry.HistoryMetadataFailed != 2 || telemetry.HistoryParseFailed != 0 ||
				telemetry.HistoryInserted != 0 || telemetry.LastErrorCode != "identity_reconciliation_failed" {
				t.Fatalf("batch did not preserve independent reconciliation failure: %+v, %v", telemetry, err)
			}
			if j, err := w.store.CanonicalJID(ctx, lid); err != nil || j != lid {
				t.Fatalf("conflicting archive alias was merged: %v, %v", j, err)
			}
			if pnRow, lidRow := archiveMessage(t, w, pn, conflictID), archiveMessage(t, w, lid, conflictID); pnRow.Text != "PN conflict original" || lidRow.Text != "LID conflict original" || pnRow.Timestamp.Equal(lidRow.Timestamp) {
				t.Fatal("failed merge changed an independent immutable row")
			}
			if row := archiveMessage(t, w, pn, id); row.Deleted || row.Edited || row.Text != msg.GetImageMessage().GetCaption() {
				t.Fatal("history restriction changed the selected archive original")
			}
			if shape == "unrelated-pn-key" || shape == "unverified-lid-key" {
				var current map[string]any
				call(t, cs, "prepare_media_forward", args, &current)
				var restricted bool
				err := w.store.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM mcp_media_forward_provenance WHERE id=? AND sha256='')", id).Scan(&restricted)
				if err != nil || restricted || current["source_provenance"] != "known_ordinary" {
					t.Fatalf("unbound mismatched chat created a restriction: %t, %v", restricted, err)
				}
				return
			}
			t.Run("stale-write", func(t *testing.T) { repairAssertStaleWriteRejected(t, cs, preview) })
			t.Run("preview", func(t *testing.T) { repairAssertRestricted(t, cs, args) })
			if reservations, calls := mediaForwardContractOutbox(t, a)[1], transport.calls.Load(); reservations != 0 || calls != 0 {
				t.Fatalf("verified history restriction allowed %d reservations and %d recipient invocations", reservations, calls)
			}
		})
	}
}

func TestMediaForwardRepairHistoryMixedChatWithArchiveAlias(t *testing.T) {
	ctx := context.Background()
	a, transport := messageApp(t)
	w := a.wa
	pn := types.NewJID("491522855511", types.DefaultUserServer)
	lid := types.NewJID("99882255", types.HiddenUserServer)
	const id = "fixture-archive-alias-photo"
	msg, plain := mediaForwardContractImage(t, "Synthetic archive alias photo", color.RGBA{G: 160, A: 255})

	// The conversation's optional LidJID field establishes the archive alias.
	// No SDK PhoneNumberToLidMappings records are part of this history batch.
	initial := archiveChunk(pn, archiveWeb(pn, pn, id, t0, msg))
	initial.Conversations[0].LidJID = proto.String(lid.String())
	w.ingestHistory(ctx, initial)
	var acceptedPN string
	if err := w.store.db.QueryRowContext(ctx, "SELECT pn FROM mcp_aliases WHERE lid=?", lid.String()).Scan(&acceptedPN); err != nil || acceptedPN != pn.String() {
		t.Fatalf("history conversation did not establish the archive alias: %q, %v", acceptedPN, err)
	}
	var sdkMapping bool
	if err := w.store.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM whatsmeow_lid_map WHERE lid=? OR pn=?)", lid.User, pn.User).Scan(&sdkMapping); err != nil || sdkMapping {
		t.Fatalf("archive alias fixture must have no SDK mapping: %t, %v", sdkMapping, err)
	}

	cs := regressionClient(t, a)
	args := mediaForwardTestArgs(id)
	args["source_chat_jid"] = pn.String()
	var preview map[string]any
	call(t, cs, "prepare_media_forward", args, &preview)
	if preview["source_provenance"] != "known_ordinary" {
		t.Fatal("selected photo must have ordinary provenance before the revoke")
	}
	repairSyntheticForwardMedia(t, w, pn, id, plain)

	// Later history uses the LID for the conversation and the PN in the
	// original message key. The provider revoke stub carries no message body.
	revoke := archiveWeb(pn, pn, id, t0.Add(time.Minute), nil)
	revoke.MessageStubType = waWeb.WebMessageInfo_REVOKE.Enum()
	w.ingestHistory(ctx, archiveChunk(lid, revoke))
	telemetry, err := w.store.IngestTelemetry(ctx)
	if err != nil || telemetry.HistoryReceived != 1 || telemetry.HistoryDuplicate != 1 ||
		telemetry.HistoryFailed != 0 || telemetry.HistoryMetadataFailed != 0 {
		t.Fatalf("archive alias revoke must retain the history duplicate outcome: %+v, %v", telemetry, err)
	}
	if row := archiveMessage(t, w, pn, id); row.Deleted || row.Edited || row.Text != msg.GetImageMessage().GetCaption() {
		t.Fatal("history revoke witness changed the archived original")
	}
	t.Run("preview", func(t *testing.T) { repairAssertRestricted(t, cs, args) })
	t.Run("stale-write", func(t *testing.T) { repairAssertStaleWriteRejected(t, cs, preview) })
	if reservations, calls := mediaForwardContractOutbox(t, a)[1], transport.calls.Load(); reservations != 0 || calls != 0 {
		t.Fatalf("archive alias revoke allowed %d reservations and %d recipient invocations", reservations, calls)
	}
}

func TestMediaForwardRepairSenderlessSDKProtocolTargets(t *testing.T) {
	for _, tc := range []struct {
		name       string
		edit       bool
		restricted bool
	}{
		{name: "revoke", restricted: true},
		{name: "edit", edit: true, restricted: true},
		{name: "omitted-remote-jids", restricted: true},
		{name: "missing-type"},
		{name: "unknown-type", edit: true},
		{name: "missing-target", edit: true},
		{name: "unrelated-target-chat", edit: true},
		{name: "unrelated-envelope-chat", edit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			a, transport := messageApp(t)
			w := a.wa
			cs := regressionClient(t, a)
			const targetID, eventID = "fixture-sdk-target", "fixture-sdk-event"
			msg, plain := mediaForwardContractImage(t, "Synthetic protocol source photo", color.RGBA{B: 203, A: 255})
			archiveIngest(t, w, group, bob, targetID, t0, msg, false)
			archiveIngest(t, w, group, bob, eventID, t0, msg, false)
			preview := mediaForwardTestPreview(t, cs, targetID)
			repairSyntheticForwardMedia(t, w, group, targetID, plain)

			msgBody := w.Client.BuildRevoke(group, bob, targetID)
			protocol := msgBody.GetProtocolMessage()
			if tc.edit {
				msgBody = w.Client.BuildEdit(group, targetID, archiveText("Synthetic edited caption"))
				protocol = msgBody.GetEditedMessage().GetMessage().GetProtocolMessage()
			}
			// The enclosing history item has a different ID from the original
			// and omits both optional sender fields.
			web := &waWeb.WebMessageInfo{
				Key:              &waCommon.MessageKey{RemoteJID: proto.String(group.String()), ID: proto.String(eventID)},
				MessageTimestamp: proto.Uint64(uint64(t0.Unix() + 60)),
				Message:          msgBody,
			}
			switch tc.name {
			case "omitted-remote-jids":
				protocol.Key.RemoteJID, web.Key.RemoteJID = nil, nil
			case "missing-type":
				protocol.Type = nil // GetType() would default to REVOKE.
			case "unknown-type":
				protocol.Type = waE2E.ProtocolMessage_Type(999).Enum()
			case "missing-target":
				protocol.Key.ID = nil
			case "unrelated-target-chat":
				protocol.Key.RemoteJID = proto.String(alice.String())
			case "unrelated-envelope-chat":
				web.Key.RemoteJID = proto.String(alice.String())
			}
			w.ingestHistory(ctx, archiveChunk(group, web))
			telemetry, err := w.store.IngestTelemetry(ctx)
			if err != nil || telemetry.HistoryReceived != 1 || telemetry.HistoryFailed != 1 ||
				telemetry.HistoryParseFailed != 1 || telemetry.HistoryMetadataFailed != 0 ||
				telemetry.HistoryInserted != 0 || telemetry.LastErrorCode != "history_message_parse_failed" {
				t.Fatalf("senderless mutation must be a parser failure: %+v, %v", telemetry, err)
			}
			for _, id := range []string{targetID, eventID} {
				if row := archiveMessage(t, w, group, id); row.Deleted || row.Edited || row.Text != msg.GetImageMessage().GetCaption() {
					t.Fatalf("senderless protocol item changed archived content for %s", id)
				}
			}
			if tc.restricted {
				t.Run("stale-target-write", func(t *testing.T) { repairAssertStaleWriteRejected(t, cs, preview) })
				t.Run("target-preview", func(t *testing.T) { repairAssertRestricted(t, cs, mediaForwardTestArgs(targetID)) })
			} else if current := mediaForwardTestPreview(t, cs, targetID); current["source_provenance"] != "known_ordinary" {
				t.Fatal("unbound protocol target affected independent ordinary provenance")
			}
			if current := mediaForwardTestPreview(t, cs, eventID); current["source_provenance"] != "known_ordinary" {
				t.Fatal("protocol event ID affected independent ordinary provenance")
			}
			if reservations, calls := mediaForwardContractOutbox(t, a)[1], transport.calls.Load(); reservations != 0 || calls != 0 {
				t.Fatalf("protocol restriction allowed %d reservations and %d recipient invocations", reservations, calls)
			}
		})
	}
}
