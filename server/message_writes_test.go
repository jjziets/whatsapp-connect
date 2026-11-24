//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"
)

type fakeMessageTransport struct {
	calls atomic.Int32
	send  func(context.Context, types.JID, *waE2E.Message, ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error)
	group *types.GroupInfo
}

func (f *fakeMessageTransport) IsConnected() bool { return true }
func (f *fakeMessageTransport) GetGroupInfo(context.Context, types.JID) (*types.GroupInfo, error) {
	if f.group == nil {
		return nil, errors.New("synthetic group unavailable")
	}
	return f.group, nil
}
func (f *fakeMessageTransport) SendMessage(c context.Context, j types.JID, m *waE2E.Message, e ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
	f.calls.Add(1)
	if f.send != nil {
		return f.send(c, j, m, e...)
	}
	return whatsmeow.SendResponse{ID: e[0].ID, Timestamp: time.Now(), Chat: j}, nil
}
func messageApp(t *testing.T) (*App, *fakeMessageTransport) {
	_, w := setup(t)
	a := &eventOwnerAuthority{}
	a.held.Store(true)
	f := &fakeMessageTransport{}
	w.messageTransport = f
	ownLID := types.NewJID("66554400", types.HiddenUserServer)
	w.Client.Store.LID = ownLID
	for _, pair := range []struct{ lid, pn types.JID }{{types.NewJID("66554433", types.HiddenUserServer), alice}, {ownLID, w.ownJID()}} {
		if e := w.Client.Store.LIDs.PutLIDMapping(context.Background(), pair.lid, pair.pn); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Client.Store.Save(context.Background()); e != nil {
		t.Fatal(e)
	}
	return &App{store: w.store, wa: w, authority: a, messageWrites: true}, f
}
func previewMessage(t *testing.T, a *App, id, chat, quote string) SendTextArgs {
	t.Helper()
	_, p, e := a.prepareMessage(context.Background(), nil, PrepareMessageArgs{RequestID: id, ChatJID: chat, Text: "Exact synthetic text.\n👍", ReplyToMessageID: quote})
	if e != nil {
		t.Fatal(e)
	}
	return p.SendTextArgs
}
func sendMessage(t *testing.T, a *App, p SendTextArgs) SendStatus {
	t.Helper()
	_, s, e := a.sendText(context.Background(), nil, p)
	if e != nil {
		t.Fatal(e)
	}
	return s
}

// A single focused integration protects reservation-before-network, immutable replay,
// concurrent RPC deduplication, exact quote construction and real normalized archive.
func TestOwnerMessageDispatchDurableReplay(t *testing.T) {
	a, f := messageApp(t)
	aliceLID := types.NewJID("66554433", types.HiddenUserServer)
	if e := a.wa.Client.Store.LIDs.PutLIDMapping(context.Background(), aliceLID, alice); e != nil {
		t.Fatal(e)
	}
	p := previewMessage(t, a, "durable-replay", alice.String(), "A1")
	f.send = func(c context.Context, j types.JID, m *waE2E.Message, e ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
		s, err := a.store.sendStatus(c, p.RequestID)
		if err != nil || s.State != "dispatching" || s.MessageID != e[0].ID {
			t.Errorf("reservation not durably visible before SDK: %+v %v", s, err)
		}
		q := m.GetExtendedTextMessage().GetContextInfo()
		if q.GetStanzaID() != "A1" || q.GetParticipant() != aliceLID.String() || q.GetRemoteJID() != aliceLID.String() || q.GetQuotedMessage().GetConversation() != "hi, lunch tomorrow?" || m.GetExtendedTextMessage().GetText() != p.Text {
			t.Errorf("wrong quote protobuf: %v", m)
		}
		return whatsmeow.SendResponse{ID: e[0].ID, Timestamp: time.Now(), Chat: j}, nil
	}
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() { defer wg.Done(); _, _, err := a.sendText(context.Background(), nil, p); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.calls.Load() != 1 {
		t.Fatalf("SDK calls=%d", f.calls.Load())
	}
	s := sendMessage(t, a, p)
	if s.State != "server_acknowledged" {
		t.Fatalf("ack=%+v", s)
	}
	m, err := a.store.Message(context.Background(), alice.String(), s.MessageID)
	if err != nil || !m.FromMe || m.Text != p.Text || m.QuotedID != "A1" {
		t.Fatalf("local archive=%+v %v", m, err)
	}
	// Real live own-message producer must deduplicate the local ACK archive.
	echo := textMsg(alice, a.wa.ownJID(), s.MessageID, time.Now(), p.Text)
	echo.Info.IsFromMe = true
	echo.Message = &waE2E.Message{ExtendedTextMessage: &waE2E.ExtendedTextMessage{Text: proto.String(p.Text), ContextInfo: &waE2E.ContextInfo{StanzaID: proto.String("A1")}}}
	if err := a.wa.ingestMessage(context.WithValue(context.Background(), eventLiveOriginKey{}, true), echo); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := a.store.db.QueryRow(`SELECT count(*) FROM mcp_messages WHERE chat_jid=? AND id=?`, alice.String(), s.MessageID).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("echo dedup %d %v", rows, err)
	}
	// Current freshness changes cannot invalidate an already reserved immutable replay.
	_, err = a.store.db.Exec(`UPDATE mcp_messages SET text='edited later',edited=1 WHERE chat_jid=? AND id='A1'`, alice.String())
	if err != nil {
		t.Fatal(err)
	}
	if got := sendMessage(t, a, p); got.State != s.State {
		t.Fatal(got)
	}
	conflict := p
	conflict.Text = "different"
	if _, _, err = a.sendText(context.Background(), nil, conflict); err == nil {
		t.Fatal("request conflict accepted")
	}
	if f.calls.Load() != 1 {
		t.Fatal("replay sent again")
	}
}

func TestOwnerMessagePublicWriteBoundary(t *testing.T) {
	a, _ := messageApp(t)
	p := previewMessage(t, a, "public-send", alice.String(), "")
	cs := regressionClient(t, a)
	raw, _ := json.Marshal(p)
	var args map[string]any
	json.Unmarshal(raw, &args)
	r, e := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "send_text", Arguments: args})
	if e != nil || r.IsError {
		t.Fatalf("enabled active owner tool absent/fails: %+v %v", r, e)
	}
	tools, e := cs.ListTools(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, tool := range tools.Tools {
		if tool.Name == "send_text" {
			found = true
			ann := tool.Annotations
			if ann == nil || ann.ReadOnlyHint || ann.DestructiveHint == nil || !*ann.DestructiveHint || ann.OpenWorldHint == nil || !*ann.OpenWorldHint || !ann.IdempotentHint {
				t.Fatalf("unsafe send annotations: %+v", ann)
			}
		}
	}
	if !found {
		t.Fatal("missing send tool")
	}
	for _, mutate := range []func(*App){func(a *App) { a.messageWrites = false }, func(a *App) { a.authority.held.Store(false) }, func(a *App) { a.wa = nil }} {
		b := *a
		auth := &eventOwnerAuthority{}
		auth.held.Store(true)
		b.authority = auth
		mutate(&b)
		_, _, err := b.sendText(context.Background(), nil, p)
		if err == nil {
			t.Fatal("disabled/inactive/reader dispatch accepted")
		}
	}
}

func TestOwnerMessageValidationAndUncertainty(t *testing.T) {
	a, f := messageApp(t)
	for _, text := range []string{"", " \n", "bad\x00", "bad\x1b", string([]byte{0xff}), strings.Repeat("a", 4097)} {
		if _, _, e := a.prepareMessage(context.Background(), nil, PrepareMessageArgs{ChatJID: alice.String(), Text: text}); e == nil {
			t.Fatalf("invalid text accepted %q", text)
		}
	}
	for _, chat := range []string{"status@broadcast", "123@newsletter", "123:4@s.whatsapp.net", "123@s.whatsapp.net", "someone", types.MetaAIJID.String()} {
		if _, _, e := a.prepareMessage(context.Background(), nil, PrepareMessageArgs{ChatJID: chat, Text: "x"}); e == nil {
			t.Fatalf("invalid target accepted %s", chat)
		}
	}
	for _, quote := range []string{"G1", "missing"} {
		if _, _, e := a.prepareMessage(context.Background(), nil, PrepareMessageArgs{ChatJID: alice.String(), Text: "x", ReplyToMessageID: quote}); e == nil {
			t.Fatal("cross-chat/missing quote accepted")
		}
	}
	for _, failure := range []error{context.Canceled, whatsmeow.ErrMessageTimedOut, errors.New("synthetic transport uncertain")} {
		p := previewMessage(t, a, opaqueMessageID(), alice.String(), "")
		f.send = func(context.Context, types.JID, *waE2E.Message, ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
			return whatsmeow.SendResponse{}, failure
		}
		s := sendMessage(t, a, p)
		if s.State != "outcome_unknown" {
			t.Fatalf("ambiguous error=%+v", s)
		}
		sendMessage(t, a, p)
	}
	if f.calls.Load() != 3 {
		t.Fatalf("uncertain retried: %d", f.calls.Load())
	}
}

// Ensure ordinary nil-raw, own-authored and group text fixtures are valid source
// snapshots, rather than a fabricated inbound ContextInfo-only approximation.
func TestOwnerMessageOwnAndGroupQuotes(t *testing.T) {
	a, f := messageApp(t)
	own := a.wa.ownJID()
	ownMsg := textMsg(group, own, "OWN-GROUP-TEXT", t0, "my group text")
	ownMsg.Info.IsFromMe = true
	if err := a.wa.ingestMessage(context.Background(), ownMsg); err != nil {
		t.Fatal(err)
	}
	f.group = &types.GroupInfo{JID: group, Participants: []types.GroupParticipant{{JID: own, IsAdmin: true}, {JID: bob}}}
	for _, tc := range []struct {
		chat             types.JID
		id, author, text string
	}{{group, "OWN-GROUP-TEXT", own.String(), "my group text"}, {group, "G1", bob.String(), "Lunch poll anyone?"}} {
		p := previewMessage(t, a, opaqueMessageID(), tc.chat.String(), tc.id)
		f.send = func(_ context.Context, j types.JID, m *waE2E.Message, e ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
			q := m.GetExtendedTextMessage().GetContextInfo()
			if q.GetParticipant() != tc.author || q.GetQuotedMessage().GetConversation() != tc.text || q.GetRemoteJID() != tc.chat.String() {
				t.Errorf("quote=%v", q)
			}
			return whatsmeow.SendResponse{ID: e[0].ID, Chat: j, Timestamp: time.Now()}, nil
		}
		sendMessage(t, a, p)
	}
}

func TestOwnerMessageLIDQuoteAddressing(t *testing.T) {
	a, f := messageApp(t)
	aliceLID := types.NewJID("66554433", types.HiddenUserServer)
	ownLID := types.NewJID("66554400", types.HiddenUserServer)
	ctx := context.Background()
	for _, pair := range []struct{ lid, pn types.JID }{{aliceLID, alice}, {ownLID, a.wa.ownJID()}} {
		if e := a.wa.Client.Store.LIDs.PutLIDMapping(ctx, pair.lid, pair.pn); e != nil {
			t.Fatal(e)
		}
	}
	// Real history/live parser producers, ordinary text with nil raw storage.
	archiveIngest(t, a.wa, alice, alice, "history-lid-text", t0, archiveText("History snapshot"), true)
	for _, tc := range []struct {
		chat           types.JID
		quote          string
		author, remote types.JID
	}{{alice, "history-lid-text", aliceLID, aliceLID}, {alice, "A0", ownLID, aliceLID}, {group, "G1", bobLID, group}} {
		f.group = &types.GroupInfo{JID: group, AddressingMode: types.AddressingModeLID, Participants: []types.GroupParticipant{{JID: ownLID}, {JID: bobLID}}}
		p := previewMessage(t, a, opaqueMessageID(), tc.chat.String(), tc.quote)
		f.send = func(_ context.Context, j types.JID, m *waE2E.Message, e ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
			q := m.GetExtendedTextMessage().GetContextInfo()
			if q.GetParticipant() != tc.author.String() || q.GetRemoteJID() != tc.remote.String() {
				t.Errorf("PN/LID context wrong: author=%s remote=%s want=%s/%s", q.GetParticipant(), q.GetRemoteJID(), tc.author, tc.remote)
			}
			return whatsmeow.SendResponse{ID: e[0].ID, Timestamp: time.Now(), Chat: tc.remote, Sender: ownLID}, nil
		}
		s := sendMessage(t, a, p)
		if s.State != "server_acknowledged" {
			t.Fatalf("verified rewrite not archived: %+v", s)
		}
	}
	// The SDK would fetch a missing LID before sending a PN. A reply must fail
	// before reservation when its actual quote addressing cannot be verified.
	b, g := messageApp(t)
	b.wa.Client.Store.LID = types.EmptyJID
	q := previewMessage(t, b, "missing-lid", alice.String(), "A0")
	if _, _, e := b.sendText(ctx, nil, q); e == nil {
		t.Fatal("missing DM addressing accepted")
	}
	if g.calls.Load() != 0 {
		t.Fatal("unverified quote dispatched")
	}
}

func TestOwnerMessageFreshQuoteAndGroupRights(t *testing.T) {
	a, f := messageApp(t)
	aliceLID := types.NewJID("66554433", types.HiddenUserServer)
	if e := a.wa.Client.Store.LIDs.PutLIDMapping(context.Background(), aliceLID, alice); e != nil {
		t.Fatal(e)
	}
	p := previewMessage(t, a, "edited-quote", alice.String(), "A1")
	archiveIngest(t, a.wa, alice, alice, "EDIT-A1", time.Now(), archiveEdit("A1", "hi, lunch tomorrow?", time.Now()), false)
	if _, _, e := a.sendText(context.Background(), nil, p); e == nil {
		t.Fatal("edited-same-text quote accepted")
	}
	if _, _, e := a.prepareMessage(context.Background(), nil, PrepareMessageArgs{ChatJID: alice.String(), Text: "x", ReplyToMessageID: "A1"}); e == nil {
		t.Fatal("edited quote must be explicitly unsupported for this first slice")
	}
	for _, g := range []*types.GroupInfo{
		{JID: group, GroupParent: types.GroupParent{IsParent: true}},
		{JID: group, Participants: []types.GroupParticipant{{JID: bob}}},
		{JID: group, GroupAnnounce: types.GroupAnnounce{IsAnnounce: true}, Participants: []types.GroupParticipant{{JID: a.wa.ownJID()}}},
	} {
		f.group = g
		p := previewMessage(t, a, opaqueMessageID(), group.String(), "")
		if _, _, e := a.sendText(context.Background(), nil, p); e == nil {
			t.Fatal("unsupported group send permitted")
		}
	}
	if f.calls.Load() != 0 {
		t.Fatalf("invalid quote/group invoked SDK %d", f.calls.Load())
	}
}

func TestAdversarialConflictingProviderMapping(t *testing.T) {
	a, f := messageApp(t)
	ctx := context.Background()
	old := types.NewJID("99988001", types.HiddenUserServer)
	if e := a.wa.Client.Store.LIDs.PutLIDMapping(ctx, old, bob); e != nil {
		t.Fatal(e)
	}
	if e := a.wa.Client.Store.LIDs.PutLIDMapping(ctx, old, alice); e == nil {
		t.Fatal("expected archive identity conflict")
	}
	mapped, e := a.wa.Client.Store.LIDs.GetLIDForPN(ctx, alice)
	if e != nil {
		t.Fatal(e)
	}
	canonical, e := a.store.CanonicalJID(ctx, mapped)
	if e != nil || canonical != bob {
		t.Fatalf("divergence fixture failed: %v %v", canonical, e)
	}
	p := previewMessage(t, a, "review-conflict", alice.String(), "")
	f.send = func(ctx context.Context, j types.JID, m *waE2E.Message, x ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
		wire, _ := a.wa.Client.Store.LIDs.GetLIDForPN(ctx, j)
		t.Logf("SDK would rewrite confirmed PN %s to conflicting wire LID %s", j, wire)
		return whatsmeow.SendResponse{ID: x[0].ID, Chat: wire, Timestamp: time.Now()}, nil
	}
	_, s, e := a.sendText(ctx, nil, p)
	if f.calls.Load() != 0 {
		t.Fatalf("unsafe SDK invocation despite known identity conflict: calls=%d result=%+v error=%v", f.calls.Load(), s, e)
	}
}
func TestAdversarialQuoteUsesCurrentMapping(t *testing.T) {
	a, f := messageApp(t)
	ctx := context.Background()
	old := types.NewJID("99988002", types.HiddenUserServer)
	current := types.NewJID("99988003", types.HiddenUserServer)
	for _, lid := range []types.JID{old, current} {
		if e := a.wa.Client.Store.LIDs.PutLIDMapping(ctx, lid, alice); e != nil {
			t.Fatal(e)
		}
	}
	p := previewMessage(t, a, "review-alias-rollover", alice.String(), "A1")
	f.send = func(ctx context.Context, j types.JID, m *waE2E.Message, x ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
		q := m.GetExtendedTextMessage().GetContextInfo()
		if q.GetParticipant() != current.String() {
			t.Errorf("stale quote participant=%s current=%s remote=%s", q.GetParticipant(), current, q.GetRemoteJID())
		}
		return whatsmeow.SendResponse{ID: x[0].ID, Chat: current, Timestamp: time.Now()}, nil
	}
	sendMessage(t, a, p)
}
func TestAdversarialQuoteControls(t *testing.T) {
	a, _ := messageApp(t)
	evt := textMsg(alice, alice, "review-controls", time.Now(), "quoted\u202eabc\u202c\x1b[2J")
	if e := a.wa.ingestMessage(context.Background(), evt); e != nil {
		t.Fatal(e)
	}
	_, p, e := a.prepareMessage(context.Background(), nil, PrepareMessageArgs{ChatJID: alice.String(), Text: "ordinary", ReplyToMessageID: "review-controls"})
	if e == nil && strings.ContainsAny(p.ConfirmationNotice, "\u202e\x1b") {
		t.Fatal("untrusted quote control characters emitted raw into confirmation notice")
	}
}

func TestIndependentKnownLegacyGroupPreview(t *testing.T) {
	a, f := messageApp(t)
	oldGroup := types.NewJID("491500000001-1500000000", types.GroupServer)
	if err := a.wa.ingestMessage(context.Background(), textMsg(oldGroup, alice, "LEGACY-GROUP", t0, "synthetic legacy group")); err != nil {
		t.Fatal(err)
	}
	f.group = &types.GroupInfo{JID: oldGroup, Participants: []types.GroupParticipant{{JID: a.wa.ownJID()}}}
	_, _, err := a.prepareMessage(context.Background(), nil, PrepareMessageArgs{RequestID: "known-legacy-group", ChatJID: oldGroup.String(), Text: "synthetic outgoing"})
	if err != nil {
		t.Fatalf("known regular legacy group cannot be previewed: %v", err)
	}
}

func TestOwnerMessagePinnedDestinationAndGroupRollover(t *testing.T) {
	a, f := messageApp(t)
	ctx := context.Background()
	ownLID := types.NewJID("66554400", types.HiddenUserServer)
	a.wa.Client.Store.LID = ownLID
	if e := a.wa.Client.Store.LIDs.PutLIDMapping(ctx, ownLID, a.wa.ownJID()); e != nil {
		t.Fatal(e)
	}
	old, current := types.NewJID("99988101", types.HiddenUserServer), types.NewJID("99988102", types.HiddenUserServer)
	for _, j := range []types.JID{old, current} {
		if e := a.wa.Client.Store.LIDs.PutLIDMapping(ctx, j, alice); e != nil {
			t.Fatal(e)
		}
	}
	p := previewMessage(t, a, "pin-destination", alice.String(), "")
	f.send = func(_ context.Context, to types.JID, _ *waE2E.Message, e ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
		if to != current {
			t.Errorf("direct SDK destination not pinned: %s", to)
		}
		return whatsmeow.SendResponse{ID: e[0].ID, Chat: current, Timestamp: time.Now()}, nil
	}
	sendMessage(t, a, p)
	if e := a.wa.ingestMessage(ctx, textMsg(group, alice, "CURRENT-GROUP-AUTHOR", t0, "group author")); e != nil {
		t.Fatal(e)
	}
	f.group = &types.GroupInfo{JID: group, AddressingMode: types.AddressingModeLID, Participants: []types.GroupParticipant{{JID: a.wa.Client.Store.GetLID()}, {JID: current}}}
	p = previewMessage(t, a, "group-rollover", group.String(), "CURRENT-GROUP-AUTHOR")
	f.send = func(_ context.Context, to types.JID, m *waE2E.Message, e ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
		if got := m.GetExtendedTextMessage().GetContextInfo().GetParticipant(); got != current.String() {
			t.Errorf("group quote used historical alias %s", got)
		}
		return whatsmeow.SendResponse{ID: e[0].ID, Chat: to, Timestamp: time.Now()}, nil
	}
	sendMessage(t, a, p)
}

func TestOwnerMessageSDKLoggingPrivacy(t *testing.T) {
	_, w := setup(t)
	var sink bytes.Buffer
	logger := zerolog.New(zerolog.SyncWriter(&sink)).Level(zerolog.DebugLevel)
	logged, e := newWA(context.Background(), w.store.db, w.store, w.dataDir, logger)
	if e != nil {
		t.Fatal(e)
	}
	const secret = "SYNTHETIC-PRIVATE-CONTENT"
	sub := logged.Client.Log.Sub("SYNTHETIC-MODULE-491511111111@s.whatsapp.net")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sub.Debugf("Replacing SendMessage destination with LID %s -> %s", alice, bobLID)
			sub.Warnf("%s", secret)
			sub.Errorf("%s", secret)
			sub.Infof("%s", secret)
		}()
	}
	wg.Wait()
	out := sink.String()
	for _, sensitive := range []string{secret, alice.String(), bobLID.String(), "SYNTHETIC-MODULE"} {
		if strings.Contains(out, sensitive) {
			t.Fatalf("SDK logger leaked synthetic private argument/module %q", sensitive)
		}
	}
	if !strings.Contains(out, "sdk_warning") {
		t.Fatal("fixed useful SDK severity diagnostic missing")
	}
}

func TestOwnerMessageNoticeIDControlsRemainVisible(t *testing.T) {
	a, _ := messageApp(t)
	id := "QUOTE\nSPOOF\x1b"
	raw := "first line\nquoted\u202econtent\u202c\x1b[2J"
	if e := a.wa.ingestMessage(context.Background(), textMsg(alice, alice, id, t0, raw)); e != nil {
		t.Fatal(e)
	}
	_, p, e := a.prepareMessage(context.Background(), nil, PrepareMessageArgs{ChatJID: alice.String(), Text: "approved\ntext", ReplyToMessageID: id})
	if e != nil {
		t.Fatal(e)
	}
	if p.ReplyTo.MessageID != id || p.ReplyTo.Text != raw || p.Text != "approved\ntext" {
		t.Fatal("notice sanitization modified immutable approval payload")
	}
	if strings.Contains(p.ConfirmationNotice, "message QUOTE\nSPOOF") || strings.ContainsAny(p.ConfirmationNotice, "\x1b\u202e\u202c") {
		t.Fatal("raw quote ID/text controls in confirmation notice")
	}
}

// Pinned SDK Device.GetLID preserves a linked-device address; provider mapping
// lookup for the account PN preserves Device0. Persist/reopen the actual SDK
// device row so the fixture cannot hide device qualifiers as the original did.
func TestOwnerMessageDeviceQualifiedOwnerSelf(t *testing.T) {
	for _, agent := range []uint8{0, 1} {
		t.Run(fmt.Sprint("agent=", agent), func(t *testing.T) {
			a, f := messageApp(t)
			ctx := context.Background()
			own := a.wa.ownJID()
			deviceLID := a.wa.Client.Store.GetLID()
			deviceLID.Device = 7
			deviceLID.RawAgent = agent
			a.wa.Client.Store.LID = deviceLID
			if e := a.wa.Client.Store.Save(ctx); e != nil {
				t.Fatal(e)
			}
			self := textMsg(own, own, "SYNTHETIC-SELF-HISTORY", t0, "synthetic self context")
			self.Info.IsFromMe = true
			if e := a.wa.ingestMessage(ctx, self); e != nil {
				t.Fatal(e)
			}
			dir := a.wa.dataDir
			if e := a.wa.drainAndClose(); e != nil {
				t.Fatal(e)
			}
			b, cleanup, e := openForServeWith(ctx, dir, zerolog.Nop(), ServeDependencies{ArchiveKeys: evArchiveKeys{}, Connect: func(context.Context, *WA) error { return nil }})
			if e != nil {
				t.Fatal(e)
			}
			defer cleanup()
			b.messageWrites = true
			b.wa.messageTransport = f
			if got := b.wa.Client.Store.GetLID(); got != deviceLID {
				t.Fatalf("SDK serialization lost device identity: got=%s expected=%s", got, deviceLID)
			}
			provider, e := b.wa.Client.Store.LIDs.GetLIDForPN(ctx, own)
			if e != nil || provider != deviceLID.ToNonAD() || provider.Device != 0 {
				t.Fatalf("not a faithful SDK account mapping: %s %v", provider, e)
			}
			p := previewMessage(t, b, "device-qualified-self", own.String(), "")
			f.send = func(_ context.Context, to types.JID, m *waE2E.Message, x ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
				if to != provider || to.Device != 0 || m.GetConversation() != p.Text {
					t.Errorf("unpinned self payload: to=%s text=%q", to, m.GetConversation())
				}
				return whatsmeow.SendResponse{ID: x[0].ID, Chat: to, Timestamp: time.Now()}, nil
			}
			raw, _ := json.Marshal(p)
			var args map[string]any
			json.Unmarshal(raw, &args)
			result, e := regressionClient(t, b).CallTool(ctx, &mcp.CallToolParams{Name: "send_text", Arguments: args})
			if e != nil {
				t.Fatal(e)
			}
			if result.IsError {
				status, se := b.store.sendStatus(ctx, p.RequestID)
				if se != nil || f.calls.Load() != 0 || status.State != "unknown" {
					t.Fatalf("rejection crossed reservation/SDK: calls=%d state=%s error=%v", f.calls.Load(), status.State, se)
				}
				detail := ""
				for _, item := range result.Content {
					if text, ok := item.(*mcp.TextContent); ok {
						detail += text.Text
					}
				}
				if !strings.Contains(detail, "current owner addressing unavailable") {
					t.Fatalf("unexpected rejection instead of owner-addressing regression: %s", detail)
				}
				t.Fatalf("valid persisted device-qualified owner rejected before dispatch (calls=0,status=unknown): %s", detail)
			}
			var sent SendStatus
			encoded, _ := json.Marshal(result.StructuredContent)
			if e = json.Unmarshal(encoded, &sent); e != nil {
				t.Fatal(e)
			}
			if sent.State != "server_acknowledged" || f.calls.Load() != 1 {
				t.Fatalf("synthetic self result: %+v calls=%d", sent, f.calls.Load())
			}
			if got := b.wa.Client.Store.GetLID(); got != deviceLID {
				t.Fatalf("readiness mutated SDK identity: %s", got)
			}
			archived, e := b.store.Message(ctx, own.String(), sent.MessageID)
			if e != nil || !archived.FromMe || archived.Text != p.Text {
				t.Fatalf("self archive: %+v %v", archived, e)
			}
			sendMessage(t, b, p)
			if f.calls.Load() != 1 {
				t.Fatal("self replay dispatched again")
			}
		})
	}
}

func TestOwnerMessageInvalidOwnerLIDDoesNotReserve(t *testing.T) {
	for _, kind := range []string{"missing", "different-account", "wrong-server", "wrong-integrator"} {
		t.Run(kind, func(t *testing.T) {
			a, f := messageApp(t)
			p := previewMessage(t, a, "invalid-owner-address", alice.String(), "")
			bad := a.wa.Client.Store.GetLID()
			bad.Device = 7
			switch kind {
			case "missing":
				bad = types.EmptyJID
			case "different-account":
				bad.User = "11223344"
			case "wrong-server":
				bad.Server = types.DefaultUserServer
			case "wrong-integrator":
				bad.Integrator = 1
			}
			a.wa.Client.Store.LID = bad
			raw, _ := json.Marshal(p)
			var args map[string]any
			json.Unmarshal(raw, &args)
			result, e := regressionClient(t, a).CallTool(context.Background(), &mcp.CallToolParams{Name: "send_text", Arguments: args})
			if e != nil || !result.IsError {
				t.Fatalf("invalid owner accepted: %+v %v", result, e)
			}
			status, se := a.store.sendStatus(context.Background(), p.RequestID)
			var rows int
			qe := a.store.db.QueryRow(`SELECT count(*) FROM mcp_outbox`).Scan(&rows)
			if se != nil || qe != nil || status.State != "unknown" || rows != 0 || f.calls.Load() != 0 {
				t.Fatalf("invalid identity reserved/dispatched: state=%s rows=%d calls=%d errors=%v/%v", status.State, rows, f.calls.Load(), se, qe)
			}
			if a.wa.Client.Store.GetLID() != bad {
				t.Fatal("invalid SDK identity silently rewritten")
			}
		})
	}
}
