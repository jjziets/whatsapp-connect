package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sqlite "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waCompanionReg"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

// WA owns the linked-device connection and mirrors everything it receives into the Store.
// Bare builds against unpatched upstream must fail; use scripts/build-server.sh.
const requiredSDKSendQueueRevision = whatsmeow.WhatsAppConnectSendQueueRevision

type WA struct {
	Client  *whatsmeow.Client
	store   *Store
	log     zerolog.Logger
	dataDir string

	// Inert test observers; nil during normal execution.
	historyCheckpoint  func()
	mediaSaveForTest   func(string, []byte) error
	mediaFinishForTest func()
	progress           *syncProgressState
	mediaCancels       map[string]context.CancelFunc

	lifecycleMu   sync.Mutex
	lifecycleCond *sync.Cond
	activeWork    int
	activeHistory int
	closing       bool
	closeOnce     sync.Once
	closeErr      error
	// Shared across Apps attached to this owner, before any durable reservation.
	messageBusy             bool
	messageCancel           context.CancelFunc
	messageTransport        messageTransport
	messageRequest          string
	messageReserved         chan struct{}
	confirmationInvocations atomic.Uint64

	loggedOut       atomic.Bool
	lastHistoryEvt  atomic.Int64 // unix nanos of the last history sync blob processed
	historyMessages atomic.Int64 // newly inserted history originals since start
	unhealthy       atomic.Bool  // telemetry persistence unavailable; process-local diagnostic
}

func init() {
	// Shown in the phone's "Linked devices" list.
	store.SetOSInfo("WhatsApp Connect", [3]uint32{1, 0, 0})
	store.DeviceProps.PlatformType = waCompanionReg.DeviceProps_DESKTOP.Enum()
}

func newWA(ctx context.Context, db *sql.DB, st *Store, dataDir string, log zerolog.Logger) (*WA, error) {
	sdkLog := privateSDKLogger{log: log.With().Str("component", "whatsmeow").Logger()}
	container := sqlstore.NewWithDB(db, "sqlite3", sdkLog)
	if err := container.Upgrade(ctx); err != nil {
		return nil, fmt.Errorf("upgrade whatsmeow store: %w", err)
	}
	if err := st.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate archive: %w", err)
	}
	device, err := container.GetFirstDevice(ctx)
	if err != nil {
		return nil, fmt.Errorf("load device: %w", err)
	}
	if device.LIDs == nil {
		device.LIDs = container.LIDMap
	}
	w := &WA{store: st, log: log, dataDir: dataDir, progress: newSyncProgress(), mediaCancels: map[string]context.CancelFunc{}}
	device.LIDs = &archiveLIDObserver{LIDStore: device.LIDs, archive: st, owner: w}
	device.Container = &archiveDeviceContainer{DeviceContainer: device.Container, archive: st, owner: w}
	client := whatsmeow.NewClient(device, sdkLog)
	w.Client = client
	w.setMediaHTTPClient(&http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()})
	client.AddEventHandler(w.handleEvent)
	if err := w.reconcileKnownAliases(ctx); err != nil {
		w.ingestFailure(ctx, "identity_startup_failed", err)
	}
	return w, nil
}

// C-008/C-007: permanent shared SDK/store logging boundary. Never format SDK
// strings, arguments or module names: they may contain identifiers or content.
// Value-only immutable adapter is safe across concurrent SDK diagnostics.
type privateSDKLogger struct{ log zerolog.Logger }

func (l privateSDKLogger) Warnf(_ string, _ ...any) {
	l.log.Warn().Str("code", "sdk_warning").Msg("WhatsApp SDK diagnostic")
}
func (l privateSDKLogger) Errorf(_ string, _ ...any) {
	l.log.Error().Str("code", "sdk_error").Msg("WhatsApp SDK diagnostic")
}
func (l privateSDKLogger) Infof(_ string, _ ...any) {
	l.log.Info().Str("code", "sdk_info").Msg("WhatsApp SDK diagnostic")
}
func (l privateSDKLogger) Debugf(_ string, _ ...any) {
	l.log.Debug().Str("code", "sdk_debug").Msg("WhatsApp SDK diagnostic")
}
func (l privateSDKLogger) Sub(_ string) waLog.Logger { return l }

// C-001/C-003/C-006: owner-only shutdown stops admission and drains received work.
type archiveWorkKey struct{}
type archiveWork struct {
	owner  *WA
	active bool
}

var errArchiveClosing = errors.New("archive owner is closing; callback not admitted")

func (w *WA) admitWork(ctx context.Context, history bool) (context.Context, func(), bool) {
	w.lifecycleMu.Lock()
	if parent, ok := ctx.Value(archiveWorkKey{}).(*archiveWork); ok && parent.owner == w && parent.active {
		// The caller already owns a live admission. Nested synchronous operations
		// retain that ownership, even after shutdown has stopped new admissions.
		w.lifecycleMu.Unlock()
		return context.WithoutCancel(ctx), func() {}, true
	}
	if w.closing {
		w.lifecycleMu.Unlock()
		return ctx, nil, false
	}
	if w.lifecycleCond == nil {
		w.lifecycleCond = sync.NewCond(&w.lifecycleMu)
	}
	work := &archiveWork{owner: w, active: true}
	w.activeWork++
	if history {
		w.activeHistory++
	}
	w.lifecycleMu.Unlock()
	finish := func() {
		w.lifecycleMu.Lock()
		work.active = false
		w.activeWork--
		if history {
			w.activeHistory--
		}
		w.lifecycleCond.Broadcast()
		w.lifecycleMu.Unlock()
	}
	return context.WithValue(context.WithoutCancel(ctx), archiveWorkKey{}, work), finish, true
}
func (w *WA) historyIdleReady(now, started time.Time, idle time.Duration) bool {
	w.lifecycleMu.Lock()
	defer w.lifecycleMu.Unlock()
	if w.closing || w.activeHistory > 0 {
		return false
	}
	ref := started
	if last := w.lastHistoryEvt.Load(); last > 0 {
		ref = time.Unix(0, last)
	}
	return now.Sub(ref) >= idle
}
func (w *WA) drainAndClose() error {
	w.closeOnce.Do(func() {
		w.lifecycleMu.Lock()
		w.closing = true
		if w.messageCancel != nil {
			w.messageCancel()
		}
		for _, cancel := range w.mediaCancels {
			cancel()
		}
		if w.lifecycleCond == nil {
			w.lifecycleCond = sync.NewCond(&w.lifecycleMu)
		}
		w.lifecycleMu.Unlock()
		w.Client.Disconnect()
		w.lifecycleMu.Lock()
		for w.activeWork > 0 {
			w.lifecycleCond.Wait()
		}
		w.lifecycleMu.Unlock()
		w.closeErr = errors.Join(w.stopSyncProgress(), w.store.db.Close())
	})
	return w.closeErr
}

// A child reservation is created while its admitted parent is still running;
// shutdown cannot observe zero active work between the callback and goroutine.
func (w *WA) startGroupRefresh(parent context.Context) {
	w.lifecycleMu.Lock()
	work := &archiveWork{owner: w, active: true}
	w.activeWork++
	w.lifecycleMu.Unlock()
	ctx := context.WithValue(context.WithoutCancel(parent), archiveWorkKey{}, work)
	go func() {
		defer func() {
			w.lifecycleMu.Lock()
			work.active = false
			w.activeWork--
			w.lifecycleCond.Broadcast()
			w.lifecycleMu.Unlock()
		}()
		w.refreshGroupsAdmitted(ctx)
	}()
}

func (w *WA) LoggedIn() bool { return w.Client.Store.ID != nil && !w.loggedOut.Load() }

type eventLiveOriginKey struct{}

func (w *WA) handleEvent(rawEvt any) {
	_, history := rawEvt.(*events.HistorySync)
	ctx, finish, ok := w.admitWork(context.Background(), history)
	if !ok {
		w.log.Warn().Str("code", "callback_not_admitted").Msg("archive owner is closing")
		return
	}
	defer finish()
	switch evt := rawEvt.(type) {
	case *events.Message:
		ctx = context.WithValue(ctx, eventLiveOriginKey{}, true)
		if err := w.ingestMessage(ctx, evt); err != nil {
			w.ingestFailure(ctx, "live_message_write_failed", err)
		}
	case *events.UndecryptableMessage:
		if evt.IsUnavailable && evt.UnavailableType == events.UnavailableTypeViewOnce {
			if err := w.store.restrictForwardSource(ctx, evt.Info.Chat, evt.Info.ID, ""); err != nil {
				w.ingestFailure(ctx, "live_message_write_failed", err)
			}
		}
	case *events.HistorySync:
		w.ingestHistoryAdmitted(ctx, evt.Data)
	case *events.GroupInfo:
		name := ""
		if evt.Name != nil {
			name = evt.Name.Name
		}
		if err := w.store.SetChatName(ctx, evt.JID.String(), true, name); err != nil {
			w.ingestFailure(ctx, "group_metadata_failed", err)
			if e := w.store.groupSummary(ctx, "partial", 1); e != nil {
				w.ingestFailure(ctx, "telemetry_persistence_failed", e)
			}
		}
	case *events.JoinedGroup:
		if err := w.store.SetChatName(ctx, evt.JID.String(), true, evt.GroupName.Name); err != nil {
			w.ingestFailure(ctx, "group_metadata_failed", err)
			if e := w.store.groupSummary(ctx, "partial", 1); e != nil {
				w.ingestFailure(ctx, "telemetry_persistence_failed", e)
			}
		}
	case *events.Connected:
		_ = w.publishSyncProgress(context.Background(), true)
		w.log.Info().Msg("connected to WhatsApp")
		w.startGroupRefresh(ctx)
	case *events.LoggedOut:
		w.loggedOut.Store(true)
		w.store.eventsMu.RLock()
		service := w.store.events
		w.store.eventsMu.RUnlock()
		if service != nil {
			if err := service.revokeAll(ctx, "logged_out"); err != nil {
				w.ingestFailure(ctx, "events_logout_failed", err)
			}
		}
		w.log.Error().Str("reason", evt.Reason.String()).Msg("logged out by WhatsApp; run `whatsapp-mcp login` again")
	case *events.Disconnected:
		_ = w.publishSyncProgress(context.Background(), true)
		w.log.Warn().Msg("disconnected from WhatsApp (will auto-reconnect)")
	}
}

// WC-PRELINK-01: C-002/C-003/C-006; actual dependency event translation.
// First Save initializes Whatsmeow stores and replaces Device.LIDs/Container.
// Reinstall the observer at that actual initialization boundary as well.
type archiveDeviceContainer struct {
	store.DeviceContainer
	archive *Store
	owner   *WA
}

func (o *archiveDeviceContainer) PutDevice(ctx context.Context, device *store.Device) error {
	if o.owner != nil {
		admitted, finish, ok := o.owner.admitWork(ctx, false)
		if !ok {
			return errArchiveClosing
		}
		defer finish()
		ctx = admitted
	}
	err := o.DeviceContainer.PutDevice(ctx, device)
	device.Container = o
	if observer, ok := device.LIDs.(*archiveLIDObserver); !ok || observer.archive != o.archive {
		device.LIDs = &archiveLIDObserver{LIDStore: device.LIDs, archive: o.archive, owner: o.owner}
	}
	return err
}

type archiveLIDObserver struct {
	store.LIDStore
	archive *Store
	owner   *WA
}

func (o *archiveLIDObserver) PutLIDMapping(ctx context.Context, lid, pn types.JID) error {
	if o.owner != nil {
		admitted, finish, ok := o.owner.admitWork(ctx, false)
		if !ok {
			return errArchiveClosing
		}
		defer finish()
		ctx = admitted
	}
	if err := o.LIDStore.PutLIDMapping(ctx, lid, pn); err != nil {
		return err
	}
	return o.archive.AcceptAlias(ctx, lid, pn)
}
func (o *archiveLIDObserver) PutManyLIDMappings(ctx context.Context, pairs []store.LIDMapping) error {
	if o.owner != nil {
		admitted, finish, ok := o.owner.admitWork(ctx, false)
		if !ok {
			return errArchiveClosing
		}
		defer finish()
		ctx = admitted
	}
	// Upstream compacts its input slice in place when mappings are cached. Keep
	// independent evidence so an identical-pair retry still reaches the archive.
	evidence := append([]store.LIDMapping(nil), pairs...)
	if err := o.LIDStore.PutManyLIDMappings(ctx, pairs); err != nil {
		return err
	}
	var errs []error
	for _, pair := range evidence {
		if pair.LID.Server != types.HiddenUserServer || pair.PN.Server != types.DefaultUserServer {
			continue
		}
		if err := o.archive.AcceptAlias(ctx, pair.LID, pair.PN); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
func (w *WA) ingestFailure(ctx context.Context, code string, err error) {
	// Record the original failure before attempting SQL-backed telemetry, whose
	// independent failure must not replace the ingest cause. Never format err.
	archiveDiagnostic(w.log.Warn().Str("code", code), err).Msg("archive operation failed")
	if e := w.store.recordFailure(ctx, code); e != nil {
		w.unhealthy.Store(true)
		archiveDiagnostic(w.log.Error().Str("code", "telemetry_persistence_failed"), e).Msg("archive diagnostics could not be persisted")
	}
}

// Only fixed enums and numeric codes cross the operational logging boundary.
func archiveDiagnostic(event *zerolog.Event, err error) *zerolog.Event {
	stage, class := "unknown", "other"
	primary, extended := 0, 0
	var diagnostic interface{ SQLiteDiagnostic() (string, int, int) }
	if errors.As(err, &diagnostic) {
		stage, primary, extended = diagnostic.SQLiteDiagnostic()
	} else {
		var cause sqlite.Error
		if errors.As(err, &cause) {
			primary, extended = int(cause.Code), int(cause.ExtendedCode)
		}
	}
	switch stage {
	case "transaction_begin", "transaction_body", "transaction_commit", "cipher_key", "cipher_verify", "cipher_config", "wal_mode":
	default:
		stage = "unknown"
	}
	switch {
	case errors.Is(err, context.Canceled):
		class = "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		class = "deadline"
	case primary != 0:
		class = "sqlite"
	}
	event = event.Str("stage", stage).Str("class", class)
	if primary != 0 {
		event = event.Int("sqlite_code", primary).Int("sqlite_extended", extended)
	}
	return event
}
func (w *WA) reconcileKnownAliases(ctx context.Context) error {
	rows, err := w.store.db.QueryContext(ctx, `SELECT lid,pn FROM whatsmeow_lid_map`)
	if err != nil {
		return err
	}
	var pairs []store.LIDMapping
	for rows.Next() {
		var lid, pn string
		if err := rows.Scan(&lid, &pn); err != nil {
			rows.Close()
			return err
		}
		pairs = append(pairs, store.LIDMapping{LID: types.NewJID(lid, types.HiddenUserServer), PN: types.NewJID(pn, types.DefaultUserServer)})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var errs []error
	for _, pair := range pairs {
		if err := w.store.AcceptAlias(ctx, pair.LID, pair.PN); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
func (w *WA) refreshGroups() {
	ctx, finish, ok := w.admitWork(context.Background(), false)
	if !ok {
		return
	}
	defer finish()
	w.refreshGroupsAdmitted(ctx)
}
func (w *WA) refreshGroupsAdmitted(ctx context.Context) {
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	groups, err := w.Client.GetJoinedGroups(requestCtx)
	if err != nil {
		w.ingestFailure(ctx, "group_discovery_failed", err)
		if err := w.store.groupSummary(ctx, "failed", 1); err != nil {
			w.ingestFailure(ctx, "telemetry_persistence_failed", err)
		}
		return
	}
	var failed int64
	for _, g := range groups {
		if err := w.store.SetChatName(ctx, g.JID.String(), true, g.Name); err != nil {
			failed++
			w.ingestFailure(ctx, "group_metadata_failed", err)
		}
	}
	if err := w.reconcileKnownAliases(ctx); err != nil {
		failed++
		w.ingestFailure(ctx, "identity_reconciliation_failed", err)
	}
	status := "complete"
	if failed > 0 {
		status = "partial"
	}
	if err := w.store.groupSummary(ctx, status, failed); err != nil {
		w.ingestFailure(ctx, "telemetry_persistence_failed", err)
	}
}
func (w *WA) resolveCanonical(ctx context.Context, jid, alt types.JID) (types.JID, error) {
	jid = jid.ToNonAD()
	if jid.Server != types.HiddenUserServer {
		return jid, nil
	}
	accepted, err := w.store.CanonicalJID(ctx, jid)
	if err != nil {
		return jid, err
	}
	if accepted != jid {
		if alt.Server == types.DefaultUserServer && !alt.IsEmpty() && alt.ToNonAD() != accepted {
			if err := w.store.AcceptAlias(ctx, jid, alt); err != nil {
				return jid, err
			}
		}
		return accepted, nil
	}
	if alt.Server == types.DefaultUserServer && !alt.IsEmpty() {
		if err := w.store.AcceptAlias(ctx, jid, alt); err != nil {
			return jid, err
		}
		return alt.ToNonAD(), nil
	}
	if w.Client.Store.LIDs != nil {
		pn, err := w.Client.Store.LIDs.GetPNForLID(ctx, jid)
		if err != nil {
			return jid, err
		}
		if !pn.IsEmpty() {
			if err := w.store.AcceptAlias(ctx, jid, pn); err != nil {
				return jid, err
			}
			return pn.ToNonAD(), nil
		}
	}
	return jid, nil
}
func (w *WA) canonical(ctx context.Context, jid, alt types.JID) types.JID {
	canonical, err := w.resolveCanonical(ctx, jid, alt)
	if err != nil {
		w.ingestFailure(ctx, "identity_reconciliation_failed", err)
		return jid.ToNonAD()
	}
	return canonical
}
func (w *WA) ownJID() types.JID {
	if w.Client.Store.ID == nil {
		return types.EmptyJID
	}
	return w.Client.Store.ID.ToNonAD()
}
func (w *WA) ingestMessage(ctx context.Context, evt *events.Message) error {
	_, err := w.ingestMessageOutcome(ctx, evt, false)
	return err
}
func (w *WA) ingestMessageOutcome(ctx context.Context, evt *events.Message, history bool) (IngestOutcome, error) {
	ctx, finish, ok := w.admitWork(ctx, history)
	if !ok {
		return IngestFailed, errArchiveClosing
	}
	defer finish()
	return w.ingestMessageAdmitted(ctx, evt, history)
}
func (w *WA) ingestMessageAdmitted(ctx context.Context, evt *events.Message, history bool) (IngestOutcome, error) {
	info := evt.Info
	if info.Chat.Server == types.BroadcastServer && info.Chat.User == "status" {
		return IngestIgnored, nil
	}
	web := evt.SourceWebMsg
	if restrictedForwardHistoryMutation(web) {
		if err := w.store.restrictForwardHistorySource(ctx, info.Chat, web, false); err != nil {
			return IngestFailed, err
		}
		// Preserve the archive's existing handling of the provider revoke stub.
		if web.GetMessageStubType() == waWeb.WebMessageInfo_REVOKE {
			return IngestDuplicate, nil
		}
	}
	var alt types.JID
	if !info.IsGroup {
		if info.IsFromMe {
			alt = info.RecipientAlt
		} else {
			alt = info.SenderAlt
		}
	}
	chat, err := w.resolveCanonical(ctx, info.Chat, alt)
	if err != nil {
		return IngestFailed, err
	}
	sender, err := w.resolveCanonical(ctx, info.Sender, info.SenderAlt)
	if err != nil {
		return IngestFailed, err
	}
	if info.IsFromMe {
		if own := w.ownJID(); !own.IsEmpty() {
			sender = own
		}
	}
	live, _ := ctx.Value(eventLiveOriginKey{}).(bool)
	in := archiveInput{live: live && !history, kind: "original", m: StoredMessage{ChatJID: chat.String(), ID: info.ID, SenderJID: sender.String(), FromMe: info.IsFromMe, Timestamp: info.Timestamp, PushName: info.PushName}, ms: info.Timestamp.UnixMilli(), eventID: info.ID}
	msg := evt.Message
	if msg == nil {
		return IngestIgnored, nil
	}
	// History parsing replaces Message and Info.ID for edits, while RawMessage
	// and SourceWebMsg retain the target/version/envelope provenance. UnwrapRaw
	// is applied to an event copy to preserve the caller's Info/Message fields.
	raw := (&events.Message{RawMessage: evt.RawMessage}).UnwrapRaw().Message
	pm := msg.GetProtocolMessage()
	if raw.GetProtocolMessage().GetType() == waE2E.ProtocolMessage_MESSAGE_EDIT {
		pm = raw.GetProtocolMessage()
	}
	if evt.SourceWebMsg != nil {
		in.eventID = evt.SourceWebMsg.GetKey().GetID()
	}
	if pm != nil {
		in.m.ID = pm.GetKey().GetID()
		switch pm.GetType() {
		case waE2E.ProtocolMessage_REVOKE:
			in.kind = "delete"
		case waE2E.ProtocolMessage_MESSAGE_EDIT:
			in.kind = "edit"
			msg = pm.GetEditedMessage()
			in.m.Content = extractContent(msg)
			if in.m.Kind == "" {
				return IngestIgnored, nil
			}
			if pm.GetTimestampMS() > 0 {
				in.ms = pm.GetTimestampMS()
			}
		default:
			return IngestIgnored, nil
		}
	} else if r := msg.GetReactionMessage(); r != nil {
		in.kind = "reaction"
		in.m.ID = r.GetKey().GetID()
		in.emoji = r.GetText()
		if r.GetSenderTimestampMS() > 0 {
			in.ms = r.GetSenderTimestampMS()
		}
	}
	if in.kind == "original" {
		in.m.Content = extractContent(msg)
		restricted, _ := ctx.Value(forwardConversationRestrictionKey{}).(bool)
		in.forwardProof = observeForwardSource(evt, restricted)
		if in.m.Kind == "" {
			if !in.forwardProof.restricted {
				return IngestIgnored, nil
			}
			in.kind = "restricted_media_envelope"
		}
	}
	if in.m.Downloadable {
		in.m.Raw, err = proto.Marshal(msg)
		if err != nil {
			return IngestFailed, err
		}
	}
	return w.store.ingest(ctx, in, history)
}
func (w *WA) ingestHistory(ctx context.Context, data *waHistorySync.HistorySync) {
	ctx, finish, ok := w.admitWork(ctx, true)
	if !ok {
		w.log.Warn().Str("code", "history_not_admitted").Msg("archive owner is closing")
		return
	}
	defer finish()
	w.ingestHistoryAdmitted(ctx, data)
}
func (w *WA) ingestHistoryAdmitted(ctx context.Context, data *waHistorySync.HistorySync) {
	progressID := w.historyProgressStart(data)
	summary := IngestTelemetry{SchemaVersion: 1, LastHistoryReceivedAt: time.Now().UTC().Format(time.RFC3339Nano), LastHistorySyncType: data.GetSyncType().String(), LastHistoryStatus: "partial"}
	if err := w.store.historySummary(ctx, summary, false); err != nil {
		w.ingestFailure(ctx, "telemetry_persistence_failed", err)
	}
	metadataFailure := func(code string, err error) {
		summary.HistoryMetadataFailed++
		summary.LastErrorCode = code
		w.ingestFailure(ctx, code, err)
	}
	for _, conv := range data.GetConversations() {
		rawChat, err := types.ParseJID(conv.GetID())
		if err == nil && (rawChat.User == "" || rawChat.Server == "") {
			err = errors.New("history chat address missing user or server")
		}
		if err != nil {
			metadataFailure("history_chat_parse_failed", err)
			for range conv.GetMessages() {
				summary.HistoryReceived++
				summary.HistoryFailed++
				summary.HistoryParseFailed++
			}
			continue
		}
		if rawChat.Server == types.BroadcastServer {
			for range conv.GetMessages() {
				summary.HistoryReceived++
				summary.HistoryIgnored++
			}
			continue
		}
		conversationRestricted := conv.GetLimitSharing() || conv.GetEphemeralExpiration() > 0 ||
			conv.GetAfterReadDuration() > 0 || conv.GetDisappearingMode() != nil
		// A valid history identity can carry a restriction without enough
		// sender or alias metadata to ingest any ordinary message content.
		var restrictionFailures map[int]bool
		if rawChat.String() == conv.GetID() {
			for i, hm := range conv.GetMessages() {
				if err := w.store.restrictForwardHistorySource(ctx, rawChat, hm.GetMessage(), conversationRestricted); err != nil {
					metadataFailure("history_forward_restriction_failed", err)
					if restrictionFailures == nil {
						restrictionFailures = make(map[int]bool)
					}
					restrictionFailures[i] = true
				}
			}
		}
		var alt types.JID
		if conv.GetPnJID() != "" {
			alt, err = types.ParseJID(conv.GetPnJID())
			if err != nil {
				metadataFailure("history_alias_parse_failed", err)
			}
		}
		if rawChat.Server == types.DefaultUserServer && conv.GetLidJID() != "" {
			lid, e := types.ParseJID(conv.GetLidJID())
			if e == nil {
				e = w.store.AcceptAlias(ctx, lid, rawChat)
			}
			if e != nil {
				metadataFailure("history_alias_failed", e)
				for range conv.GetMessages() {
					summary.HistoryReceived++
					summary.HistoryFailed++
				}
				continue
			}
		}
		chat, err := w.resolveCanonical(ctx, rawChat, alt)
		if err != nil {
			metadataFailure("identity_reconciliation_failed", err)
			for range conv.GetMessages() {
				summary.HistoryReceived++
				summary.HistoryFailed++
			}
			continue
		}
		chatFailures := summary.HistoryFailed + summary.HistoryMetadataFailed
		w.chatProgressBoundary(chat.String(), true, false)
		name := conv.GetName()
		if name == "" {
			name = conv.GetDisplayName()
		}
		isGroup := chat.Server == types.GroupServer
		if err := w.store.SetChatName(ctx, chat.String(), isGroup, name); err != nil {
			metadataFailure("history_chat_metadata_failed", err)
		}
		if ts := conv.GetConversationTimestamp(); ts > 0 {
			if err := w.store.TouchChat(ctx, chat.String(), isGroup, time.Unix(int64(ts), 0)); err != nil {
				metadataFailure("history_chat_metadata_failed", err)
			}
		}
		messageCtx := ctx
		if conversationRestricted {
			messageCtx = context.WithValue(ctx, forwardConversationRestrictionKey{}, true)
		}
		for i, hm := range conv.GetMessages() {
			func() {
				defer func() {
					w.historyProgressCounts(progressID, summary)
					if w.historyCheckpoint != nil {
						w.historyCheckpoint()
					}
				}()
				summary.HistoryReceived++
				evt, err := w.Client.ParseWebMessage(rawChat, hm.GetMessage())
				if err != nil {
					summary.HistoryFailed++
					summary.HistoryParseFailed++
					summary.LastErrorCode = "history_message_parse_failed"
					w.ingestFailure(ctx, summary.LastErrorCode, err)
					return
				}
				if restrictionFailures[i] {
					summary.HistoryFailed++
					return
				}
				outcome, err := w.ingestMessageOutcome(messageCtx, evt, true)
				if err != nil {
					summary.HistoryFailed++
					summary.LastErrorCode = "history_message_write_failed"
					w.ingestFailure(ctx, summary.LastErrorCode, err)
					return
				}
				switch outcome {
				case IngestInserted:
					summary.HistoryInserted++
				case IngestUpdated:
					summary.HistoryUpdated++
				case IngestDuplicate:
					summary.HistoryDuplicate++
				case IngestIgnored:
					summary.HistoryIgnored++
				default:
					summary.HistoryFailed++
				}
			}()
		}
		if err := w.store.SetChatState(ctx, chat.String(), conv.GetUnreadCount(), conv.GetArchived()); err != nil {
			metadataFailure("history_chat_state_failed", err)
		}
		w.chatProgressBoundary(chat.String(), false, summary.HistoryFailed+summary.HistoryMetadataFailed > chatFailures)
	}
	if err := w.reconcileKnownAliases(ctx); err != nil {
		metadataFailure("identity_reconciliation_failed", err)
	}
	summary.LastHistoryCompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	summary.LastHistoryStatus = "complete"
	if summary.HistoryFailed+summary.HistoryMetadataFailed > 0 {
		summary.LastHistoryStatus = "partial"
		if summary.HistoryInserted+summary.HistoryUpdated+summary.HistoryDuplicate+summary.HistoryIgnored == 0 {
			summary.LastHistoryStatus = "failed"
		}
	}
	if err := w.store.historySummary(ctx, summary, true); err != nil {
		w.ingestFailure(ctx, "telemetry_persistence_failed", err)
	}
	w.historyProgressEnd(progressID, summary)
	w.historyMessages.Add(summary.HistoryInserted)
	w.lastHistoryEvt.Store(time.Now().UnixNano())
	w.log.Info().Str("status", summary.LastHistoryStatus).Int64("received", summary.HistoryReceived).Int64("inserted", summary.HistoryInserted).Int64("failed", summary.HistoryFailed).Msg("history chunk processed; phone coverage unknown")
}

// RequestOlderHistory asks the phone for `count` messages older than the oldest one archived
// for the chat. The answer arrives asynchronously as an ON_DEMAND history sync.
func (w *WA) RequestOlderHistory(ctx context.Context, chat types.JID, count int) error {
	// C-007/C-006: peer history requests use the SDK's same non-cancelable
	// send mutex. Share owner admission so new sends never queue behind them.
	w.lifecycleMu.Lock()
	if w.closing || w.messageBusy {
		w.lifecycleMu.Unlock()
		return errors.New("owner send path busy or closing; history request not dispatched")
	}
	if w.lifecycleCond == nil {
		w.lifecycleCond = sync.NewCond(&w.lifecycleMu)
	}
	w.messageBusy = true
	w.messageRequest = ""
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	w.messageCancel = cancel
	w.activeWork++
	w.lifecycleMu.Unlock()
	defer func() {
		cancel()
		w.lifecycleMu.Lock()
		w.activeWork--
		w.messageBusy = false
		w.messageCancel = nil
		w.lifecycleCond.Broadcast()
		w.lifecycleMu.Unlock()
	}()
	oldest, err := w.store.OldestMessage(ctx, chat.String())
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("no messages archived for %s yet, so there is no anchor to page back from", chat)
	} else if err != nil {
		return err
	}
	target := chat
	// The phone keys many 1:1 threads by LID nowadays; ask using the address it knows.
	if chat.Server == types.DefaultUserServer {
		if lid, err := w.Client.Store.LIDs.GetLIDForPN(ctx, chat); err == nil && !lid.IsEmpty() {
			target = lid
		}
	}
	info := &types.MessageInfo{
		MessageSource: types.MessageSource{Chat: target, IsFromMe: oldest.FromMe, IsGroup: chat.Server == types.GroupServer},
		ID:            oldest.ID,
		Timestamp:     oldest.Timestamp,
	}
	own := w.ownJID()
	if own.IsEmpty() {
		return whatsmeow.ErrNotLoggedIn
	}
	transport := w.messageTransport
	if transport == nil {
		transport = w.Client
	}
	// Exact pinned SendPeerMessage adapter, with a bounded response timeout.
	_, err = transport.SendMessage(ctx, own, w.Client.BuildHistorySyncRequest(info, count), whatsmeow.SendRequestExtra{Peer: true, Timeout: 25 * time.Second})
	return err
}

// DownloadMedia fetches and decrypts a media message, caching it under <data-dir>/media.
func (w *WA) DownloadMedia(ctx context.Context, m *MessageRow) (string, []byte, error) {
	return w.downloadMediaProgress(ctx, m)
}

func extensionFor(m *MessageRow) string {
	if ext := filepath.Ext(m.FileName); ext != "" && len(ext) <= 8 {
		return ext
	}
	mt := strings.TrimSpace(strings.Split(m.Mime, ";")[0])
	switch mt {
	case "image/jpeg":
		return ".jpg"
	case "audio/ogg":
		return ".ogg"
	case "video/mp4":
		return ".mp4"
	case "image/webp":
		return ".webp"
	}
	if exts, _ := mime.ExtensionsByType(mt); len(exts) > 0 {
		return exts[0]
	}
	return ".bin"
}

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == 0 || r == ':' {
			return '_'
		}
		return r
	}, s)
}
