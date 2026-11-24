package main

// TRACEWEAVER: C-007 / TRACE-OWNERMSG-007 / VER-OWNERMSG-007.
// Host confirmation is the approval boundary. Digests only detect payload changes.
import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
)

type PrepareMessageArgs struct {
	RequestID        string `json:"request_id,omitempty"`
	ChatJID          string `json:"chat_jid"`
	Text             string `json:"text"`
	ReplyToMessageID string `json:"reply_to_message_id,omitempty"`
}

type MessageQuote struct {
	MessageID  string `json:"message_id"`
	ChatJID    string `json:"chat_jid"`
	AuthorJID  string `json:"author_jid"`
	AuthorName string `json:"author_name"`
	Text       string `json:"text"`
}

// SendTextArgs is deliberately flat: the host sees every meaningful field.
type SendTextArgs struct {
	RequestID     string        `json:"request_id"`
	AccountJID    string        `json:"account_jid"`
	ChatJID       string        `json:"chat_jid"`
	DisplayName   string        `json:"display_name"`
	IsGroup       bool          `json:"is_group"`
	Text          string        `json:"text"`
	ReplyTo       *MessageQuote `json:"reply_to,omitempty"`
	PayloadDigest string        `json:"payload_digest"`
	ExpiresAt     string        `json:"expires_at"`
}

type MessagePreview struct {
	SendTextArgs
	ConfirmationNotice string `json:"confirmation_notice"`
}

type SendStatusArgs struct {
	RequestID string `json:"request_id"`
}
type SendStatus struct {
	RequestID       string            `json:"request_id"`
	State           string            `json:"state"`
	Payload         *SendTextArgs     `json:"payload,omitempty"`
	MediaPayload    *ForwardMediaArgs `json:"media_payload,omitempty"`
	MessageID       string            `json:"message_id,omitempty"`
	Outcome         string            `json:"outcome,omitempty"`
	ServerTimestamp string            `json:"server_timestamp,omitempty"`
	WireChat        string            `json:"wire_chat,omitempty"`
	WireSender      string            `json:"wire_sender,omitempty"`
	rawPayload      string
}

type ConfirmationTestStatus struct {
	Enabled     bool   `json:"enabled"`
	Invocations uint64 `json:"invocations"`
}

func validateMessageServeOptions(transport string, events, writes, qualification bool) error {
	if writes && qualification {
		return errors.New("message confirmation test and real message writes are mutually exclusive")
	}
	if (writes || qualification) && (events || transport != "stdio") {
		return errors.New("message modes require stdio with Events disabled; use the authenticated owner HTTP side listener for HTTP")
	}
	return nil
}

// Qualification has no transport or outbox access. It is deliberately entered
// before real dispatch admission and returns no chosen ID/acknowledgement.
func (a *App) confirmationTestMessage(ctx context.Context, p SendTextArgs) (*mcp.CallToolResult, SendStatus, error) {
	if a.messageWrites || a.wa == nil || !a.authority.active() {
		return nil, SendStatus{}, errors.New("inert qualification requires an exclusive active owner mode")
	}
	a.wa.confirmationInvocations.Add(1)
	if err := a.validateFreshMessage(ctx, p); err != nil {
		return nil, SendStatus{}, err
	}
	return nil, SendStatus{RequestID: p.RequestID, State: "confirmation_test_only_not_sent", Outcome: "confirmation_test_only_not_sent", Payload: &p}, nil
}

// The only replaceable network edge; production uses the pinned SDK client.
type messageTransport interface {
	SendMessage(context.Context, types.JID, *waE2E.Message, ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error)
	GetGroupInfo(context.Context, types.JID) (*types.GroupInfo, error)
	IsConnected() bool
}

func (a *App) sendText(ctx context.Context, _ *mcp.CallToolRequest, p SendTextArgs) (*mcp.CallToolResult, SendStatus, error) {
	if a.messageConfirmationTest {
		return a.confirmationTestMessage(ctx, p)
	}
	if !a.messageWrites || a.wa == nil || !a.authority.active() {
		return nil, SendStatus{}, errors.New("message writes require an enabled active owner")
	}
	if !validRequestID(p.RequestID) {
		return nil, SendStatus{}, errors.New("invalid request_id")
	}
	own, err := a.messageOwner(ctx, p.AccountJID)
	if err != nil {
		return nil, SendStatus{}, err
	}
	op, prior, err := a.beginMessage(ctx, p.RequestID, func(ctx context.Context) (SendStatus, error) {
		return a.existingMessage(ctx, p)
	})
	if op == nil {
		return nil, prior, err
	}
	defer op.finish()
	if !messageConnected(op.ctx, op.transport) {
		return nil, SendStatus{}, errors.New("owner is offline; no message reserved")
	}
	if err := a.validateFreshMessage(op.ctx, p); err != nil {
		return nil, SendStatus{}, err
	}
	wire, msg, err := a.messageProto(op.ctx, p, op.transport)
	if err != nil {
		return nil, SendStatus{}, err
	}
	if err = op.ctx.Err(); err != nil {
		return nil, SendStatus{}, err
	}
	if !a.authority.active() {
		return nil, SendStatus{}, errors.New("owner authority revoked")
	}
	chosen := a.wa.Client.GenerateMessageID()
	out, won, err := a.store.reserveMessage(op.ctx, p, chosen)
	op.notifyReservation()
	if err != nil || !won {
		return nil, out, err
	}
	response, sendErr := op.transport.SendMessage(op.ctx, wire, msg, whatsmeow.SendRequestExtra{ID: chosen, Timeout: 25 * time.Second})
	return nil, a.settleDispatchedMessage(op.ctx, out, p, own, msg, response, sendErr), nil
}

func (a *App) messageOwner(ctx context.Context, account string) (types.JID, error) {
	own, err := a.store.OwnJID(ctx)
	if err != nil || own.String() != account || a.wa.ownJID() != own || !a.wa.LoggedIn() {
		return types.EmptyJID, errors.New("message owner identity changed or unavailable")
	}
	return own, nil
}

type messageAdmission struct {
	ctx               context.Context
	transport         messageTransport
	notifyReservation func()
	finish            func()
}

// Text and media use the same admission and duplicate reservation edge.
// History requests share the owner's messageBusy flag.
func (a *App) beginMessage(ctx context.Context, requestID string, lookup func(context.Context) (SendStatus, error)) (*messageAdmission, SendStatus, error) {
	if prior, err := lookup(ctx); err != nil || prior.State != "unknown" {
		return nil, prior, err
	}
	w := a.wa
	w.lifecycleMu.Lock()
	if w.closing {
		w.lifecycleMu.Unlock()
		return nil, SendStatus{}, errArchiveClosing
	}
	if w.messageBusy {
		id, ready := w.messageRequest, w.messageReserved
		w.lifecycleMu.Unlock()
		if id != requestID {
			return nil, SendStatus{}, errors.New("another message is being dispatched; no reservation made")
		}
		select {
		case <-ready:
		case <-ctx.Done():
			return nil, SendStatus{}, ctx.Err()
		}
		prior, err := lookup(ctx)
		if err == nil && prior.State == "unknown" {
			err = errors.New("original reservation unavailable; no message dispatched by this call")
		}
		return nil, prior, err
	}
	if w.lifecycleCond == nil {
		w.lifecycleCond = sync.NewCond(&w.lifecycleMu)
	}
	w.messageBusy = true
	w.messageRequest = requestID
	reserved := make(chan struct{})
	w.messageReserved = reserved
	dispatchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	w.messageCancel = cancel
	work := &archiveWork{owner: w, active: true}
	w.activeWork++
	dispatchCtx = context.WithValue(dispatchCtx, archiveWorkKey{}, work)
	w.lifecycleMu.Unlock()

	reservedClosed := false
	notifyReservation := func() {
		if !reservedClosed {
			close(reserved)
			reservedClosed = true
		}
	}
	transport := w.messageTransport
	if transport == nil {
		transport = w.Client
	}
	return &messageAdmission{
		ctx: dispatchCtx, transport: transport, notifyReservation: notifyReservation,
		finish: func() {
			cancel()
			notifyReservation()
			w.lifecycleMu.Lock()
			work.active = false
			w.activeWork--
			w.messageBusy = false
			w.messageRequest = ""
			w.messageCancel = nil
			w.lifecycleCond.Broadcast()
			w.lifecycleMu.Unlock()
		},
	}, SendStatus{}, nil
}

func messageConnected(ctx context.Context, transport messageTransport) bool {
	if contextual, ok := transport.(interface{ IsConnectedContext(context.Context) bool }); ok {
		return contextual.IsConnectedContext(ctx)
	}
	return transport.IsConnected()
}

func (a *App) settleDispatchedMessage(dispatchCtx context.Context, out SendStatus, target SendTextArgs, own types.JID, msg *waE2E.Message, response whatsmeow.SendResponse, sendErr error) SendStatus {
	chosen := out.MessageID
	// Retain cancellation for network work. Only bounded DB/archive settlement
	// detaches it, using the still-admitted work before the owner may close DB.
	settleCtx, settleCancel := context.WithTimeout(context.WithoutCancel(dispatchCtx), 5*time.Second)
	defer settleCancel()
	out.State = "outcome_unknown"
	out.Outcome = "send_outcome_unknown_do_not_retry"
	if sendErr == nil {
		out.WireChat = response.Chat.String()
		out.WireSender = response.Sender.String()
		out.ServerTimestamp = response.Timestamp.UTC().Format(time.RFC3339Nano)
		actual, identityErr := a.store.CanonicalJID(settleCtx, response.Chat)
		if response.ID == chosen && !response.Timestamp.IsZero() && identityErr == nil && actual.String() == target.ChatJID {
			// The ACK's Sender is documented unreliable; use the verified owner.
			evt := &events.Message{Info: types.MessageInfo{MessageSource: types.MessageSource{Chat: mustMessageJID(target.ChatJID), Sender: own, IsFromMe: true, IsGroup: target.IsGroup}, ID: chosen, Timestamp: response.Timestamp}, RawMessage: msg}
			evt.UnwrapRaw()
			if _, archiveErr := a.wa.ingestMessageAdmitted(settleCtx, evt, false); archiveErr == nil {
				out.State = "server_acknowledged"
				out.Outcome = "server_acknowledged_not_delivery_or_read"
			} else {
				out.Outcome = "server_acknowledged_archive_unavailable_do_not_retry"
			}
		} else {
			out.Outcome = "server_response_identity_unverified_do_not_retry"
		}
	}
	return a.persistMessageOutcome(settleCtx, out)
}

func (a *App) persistMessageOutcome(ctx context.Context, out SendStatus) SendStatus {
	if err := a.store.settleMessage(ctx, out); err != nil {
		out.State = "outcome_unknown"
		out.Outcome = "settlement_storage_unavailable_do_not_retry"
	}
	return out
}

func mustMessageJID(raw string) types.JID { j, _ := types.ParseJID(raw); return j }

func (a *App) existingMessage(ctx context.Context, p SendTextArgs) (SendStatus, error) {
	b, _ := json.Marshal(p)
	return a.store.existingOutboxMessage(ctx, p.RequestID, string(b))
}

func (a *App) validateFreshMessage(ctx context.Context, p SendTextArgs) error {
	exp, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	now := time.Now()
	if err != nil || !exp.After(now) || exp.After(now.Add(15*time.Minute+time.Second)) {
		return errors.New("preview expired or invalid; prepare and confirm again")
	}
	quoteID := ""
	if p.ReplyTo != nil {
		quoteID = p.ReplyTo.MessageID
	}
	fresh, err := a.messagePayload(ctx, PrepareMessageArgs{RequestID: p.RequestID, ChatJID: p.ChatJID, Text: p.Text, ReplyToMessageID: quoteID})
	if err != nil {
		return err
	}
	fresh.ExpiresAt = p.ExpiresAt
	fresh.PayloadDigest = messageDigest(fresh)
	want, _ := json.Marshal(p)
	got, _ := json.Marshal(fresh)
	if string(want) != string(got) {
		return errors.New("preview payload changed; prepare and confirm again")
	}
	return nil
}

// Use current reciprocal provider identity, cross-checked with the accepted archive.
// Retained historical aliases are evidence, not a choice of present wire identity.
func (a *App) currentMessageLID(ctx context.Context, pn types.JID) (types.JID, error) {
	if pn.Server != types.DefaultUserServer || pn.Device != 0 {
		return types.EmptyJID, errors.New("current individual identity unavailable")
	}
	lid, err := a.wa.Client.Store.LIDs.GetLIDForPN(ctx, pn)
	if err != nil || lid.IsEmpty() {
		return types.EmptyJID, errors.New("send requires a verified current PN/LID mapping")
	}
	if pn == a.wa.ownJID() && a.wa.Client.Store.GetLID().ToNonAD() != lid {
		return types.EmptyJID, errors.New("current owner addressing unavailable")
	}
	parsed, err := supportedMessageJID(lid.String())
	if err != nil || parsed.Server != types.HiddenUserServer {
		return types.EmptyJID, errors.New("current LID unavailable")
	}
	reverse, err := a.wa.Client.Store.LIDs.GetPNForLID(ctx, lid)
	if err != nil || reverse != pn {
		return types.EmptyJID, errors.New("provider identity mapping is not reciprocal")
	}
	canonical, err := a.store.CanonicalJID(ctx, lid)
	if err != nil || canonical != pn {
		return types.EmptyJID, errors.New("provider and archive identity mappings disagree")
	}
	return lid, nil
}

func (a *App) messageWire(ctx context.Context, p SendTextArgs, transport messageTransport) (types.JID, types.JID, error) {
	chat := mustMessageJID(p.ChatJID)
	wire := chat
	author := types.EmptyJID
	if p.ReplyTo != nil {
		author = mustMessageJID(p.ReplyTo.AuthorJID)
	}
	if !p.IsGroup {
		var err error
		wire, err = a.currentMessageLID(ctx, chat)
		if err != nil {
			return types.EmptyJID, types.EmptyJID, err
		}
		if _, err = a.currentMessageLID(ctx, a.wa.ownJID()); err != nil {
			return types.EmptyJID, types.EmptyJID, err
		}
		if p.ReplyTo != nil {
			if author == chat {
				author = wire
			} else {
				author, err = a.currentMessageLID(ctx, author)
				if err != nil {
					return types.EmptyJID, types.EmptyJID, err
				}
			}
		}
	} else {
		g, err := transport.GetGroupInfo(ctx, chat)
		if err != nil || g == nil || g.JID != chat || g.IsParent || g.Suspended {
			return types.EmptyJID, types.EmptyJID, errors.New("regular group metadata unavailable")
		}
		if g.AddressingMode != "" && g.AddressingMode != types.AddressingModePN && g.AddressingMode != types.AddressingModeLID {
			return types.EmptyJID, types.EmptyJID, errors.New("unsupported group addressing mode")
		}
		if g.AddressingMode == types.AddressingModeLID && p.ReplyTo != nil {
			author, err = a.currentMessageLID(ctx, author)
			if err != nil {
				return types.EmptyJID, types.EmptyJID, err
			}
		}
		member, admin, quoteMember := false, false, p.ReplyTo == nil
		for _, participant := range g.Participants {
			canonical, err := a.store.CanonicalJID(ctx, participant.JID)
			if err != nil || canonical.Server != types.DefaultUserServer {
				continue
			}
			if participant.JID.Server == types.HiddenUserServer || g.AddressingMode == types.AddressingModeLID {
				current, err := a.currentMessageLID(ctx, canonical)
				if err != nil || current != participant.JID {
					continue
				}
			}
			if canonical.String() == p.AccountJID {
				member = true
				admin = participant.IsAdmin || participant.IsSuperAdmin
			}
			if p.ReplyTo != nil && canonical.String() == p.ReplyTo.AuthorJID {
				quoteMember = true
			}
		}
		if !member || (g.IsAnnounce && !admin) {
			return types.EmptyJID, types.EmptyJID, errors.New("owner lacks group send permission")
		}
		if !quoteMember {
			return types.EmptyJID, types.EmptyJID, errors.New("quote author current group identity unavailable")
		}
	}
	return wire, author, nil
}

func (a *App) messageProto(ctx context.Context, p SendTextArgs, transport messageTransport) (types.JID, *waE2E.Message, error) {
	wire, author, err := a.messageWire(ctx, p, transport)
	if err != nil {
		return types.EmptyJID, nil, err
	}
	if p.ReplyTo == nil {
		return wire, &waE2E.Message{Conversation: proto.String(p.Text)}, nil
	}
	return wire, &waE2E.Message{ExtendedTextMessage: &waE2E.ExtendedTextMessage{Text: proto.String(p.Text), ContextInfo: &waE2E.ContextInfo{StanzaID: proto.String(p.ReplyTo.MessageID), Participant: proto.String(author.String()), RemoteJID: proto.String(wire.String()), QuotedMessage: &waE2E.Message{Conversation: proto.String(p.ReplyTo.Text)}}}}, nil
}

func opaqueMessageID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("system random unavailable")
	}
	return hex.EncodeToString(b[:])
}

func validRequestID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func validateMessageText(text string) error {
	if !utf8.ValidString(text) || strings.TrimSpace(text) == "" || utf8.RuneCountInString(text) > 4096 {
		return errors.New("text must contain 1–4096 Unicode characters and valid UTF-8")
	}
	for _, r := range text {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.In(r, unicode.Cf) {
			return errors.New("text contains unsupported control characters")
		}
	}
	return nil
}

func supportedMessageJID(raw string) (types.JID, error) {
	j, err := types.ParseJID(raw)
	if err != nil || j.User == "" || j.String() != raw || j.Device != 0 || j.RawAgent != 0 || j.Integrator != 0 || j.IsBot() {
		return types.EmptyJID, errors.New("target must be an exact supported non-device JID")
	}
	if j.Server != types.DefaultUserServer && j.Server != types.HiddenUserServer && j.Server != types.GroupServer {
		return types.EmptyJID, errors.New("unsupported message target")
	}
	parts := []string{j.User}
	if j.Server == types.GroupServer {
		parts = strings.Split(j.User, "-")
		if len(parts) > 2 {
			return types.EmptyJID, errors.New("unsupported group target")
		}
	}
	for _, part := range parts {
		if part == "" {
			return types.EmptyJID, errors.New("unsupported message target")
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return types.EmptyJID, errors.New("unsupported message target")
			}
		}
	}

	return j, nil
}

// No live lookups and no alias writes: reader previews use stored verified identities.
func (a *App) messagePayload(ctx context.Context, args PrepareMessageArgs) (SendTextArgs, error) {
	var p SendTextArgs
	if err := validateMessageText(args.Text); err != nil {
		return p, err
	}
	if args.RequestID == "" {
		args.RequestID = opaqueMessageID()
	}
	if !validRequestID(args.RequestID) {
		return p, errors.New("invalid request_id")
	}
	j, own, name, err := a.messageTarget(ctx, args.ChatJID)
	if err != nil {
		return p, err
	}
	p = SendTextArgs{RequestID: args.RequestID, AccountJID: own.String(), ChatJID: j.String(), DisplayName: name, IsGroup: j.Server == types.GroupServer, Text: args.Text}
	if args.ReplyToMessageID != "" {
		m, err := a.store.Message(ctx, j.String(), args.ReplyToMessageID)
		if err != nil || m.Deleted || m.Edited || m.Kind != "text" || m.Text == "" {
			return SendTextArgs{}, errors.New("reply requires a non-edited, non-deleted same-chat archived text message")
		}
		author, err := supportedMessageJID(m.SenderJID)
		if m.FromMe {
			author = own
			err = nil
		}
		if err != nil || author.Server == types.GroupServer {
			return SendTextArgs{}, errors.New("quote author identity unavailable")
		}
		author, err = a.store.CanonicalJID(ctx, author)
		if err != nil || author.Server != types.DefaultUserServer {
			return SendTextArgs{}, errors.New("quote author identity is unverified")
		}
		an := a.store.Names(ctx)[author.String()]
		if m.FromMe {
			an = "me"
		}
		if an == "" {
			an = author.String()
		}
		p.ReplyTo = &MessageQuote{MessageID: m.ID, ChatJID: j.String(), AuthorJID: author.String(), AuthorName: an, Text: m.Text}
	}
	return p, nil
}

// Shared recipient resolution reads only local archived identities.
func (a *App) messageTarget(ctx context.Context, raw string) (chat, owner types.JID, name string, err error) {
	j, err := supportedMessageJID(raw)
	if err != nil {
		return types.EmptyJID, types.EmptyJID, "", err
	}
	j, err = a.store.CanonicalJID(ctx, j)
	if err != nil || j.Server == types.HiddenUserServer {
		return types.EmptyJID, types.EmptyJID, "", errors.New("target identity is unverified")
	}
	var known int
	err = a.store.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mcp_chats WHERE jid=? UNION ALL SELECT 1 FROM whatsmeow_contacts WHERE their_jid=?)`, j.String(), j.String()).Scan(&known)
	if err != nil || known == 0 {
		return types.EmptyJID, types.EmptyJID, "", errors.New("target must be a known archived chat or contact")
	}
	own, err := a.store.OwnJID(ctx)
	if err != nil || own.Server != types.DefaultUserServer {
		return types.EmptyJID, types.EmptyJID, "", errors.New("owner identity unavailable")
	}
	name = a.store.Names(ctx)[j.String()]
	if name == "" {
		name = j.String()
	}
	return j, own, name, nil
}

func messageDigest(p SendTextArgs) string {
	p.PayloadDigest = ""
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Preserve approved bytes in the payload; show unsupported incoming rendering
// controls visibly in the human notice, with no truncation of any field.
func visibleNoticeData(raw string) string {
	var out strings.Builder
	for _, r := range raw {
		if unicode.In(r, unicode.Cf) || (unicode.IsControl(r) && r != '\n' && r != '\t') {
			fmt.Fprintf(&out, "\\u{%04X}", r)
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}

// Names are untrusted. Quote them so newlines/control characters cannot mimic UI.
func confirmationNotice(p SendTextArgs) string {
	kind := "direct"
	if p.IsGroup {
		kind = "group"
	}
	n := fmt.Sprintf("Message preview for %q (%s, %s):\n%s", p.DisplayName, kind, p.ChatJID, p.Text)
	if q := p.ReplyTo; q != nil {
		n += fmt.Sprintf("\n[Replying to %q (%s), message %q:\n%s]", q.AuthorName, q.AuthorJID, visibleNoticeData(q.MessageID), visibleNoticeData(q.Text))
	}
	return n + "\nApprove this exact message in the host approval card."
}

func (a *App) prepareMessage(ctx context.Context, _ *mcp.CallToolRequest, args PrepareMessageArgs) (*mcp.CallToolResult, MessagePreview, error) {
	p, err := a.messagePayload(ctx, args)
	if err != nil {
		return nil, MessagePreview{}, err
	}
	p.ExpiresAt = time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339Nano)
	p.PayloadDigest = messageDigest(p)
	return nil, MessagePreview{SendTextArgs: p, ConfirmationNotice: confirmationNotice(p)}, nil
}

func (a *App) getSendStatus(ctx context.Context, _ *mcp.CallToolRequest, args SendStatusArgs) (*mcp.CallToolResult, SendStatus, error) {
	if !validRequestID(args.RequestID) {
		return nil, SendStatus{}, errors.New("invalid request_id")
	}
	s, err := a.store.sendStatus(ctx, args.RequestID)
	return nil, s, err
}
