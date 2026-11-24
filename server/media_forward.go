package main

// TRACEWEAVER: C-007 / TRACE-OWNERMSG-007 / VER-OWNERMSG-007.
import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/types"
)

const (
	forwardMediaOperation = "forward_media"
	legacyForwardAck      = "I confirm this historical item is an ordinary shareable attachment even though its original privacy restrictions cannot be verified."
)

type PrepareMediaForwardArgs struct {
	RequestID       string `json:"request_id,omitempty"`
	ChatJID         string `json:"chat_jid"`
	SourceChatJID   string `json:"source_chat_jid"`
	SourceMessageID string `json:"source_message_id"`
}

// Keep meaningful arguments flat and explicit for the host confirmation UI.
type ForwardMediaArgs struct {
	Operation        string  `json:"operation"`
	RequestID        string  `json:"request_id"`
	AccountJID       string  `json:"account_jid"`
	ChatJID          string  `json:"chat_jid"`
	DisplayName      string  `json:"display_name"`
	IsGroup          bool    `json:"is_group"`
	SourceChatJID    string  `json:"source_chat_jid"`
	SourceMessageID  string  `json:"source_message_id"`
	SourceName       string  `json:"source_display_name"`
	Kind             string  `json:"kind"`
	MIMEType         string  `json:"mime_type"`
	FileName         string  `json:"file_name"`
	SizeBytes        int64   `json:"size_bytes"`
	SHA256           string  `json:"sha256"`
	Caption          *string `json:"caption,omitempty"`
	SourceProvenance string  `json:"source_provenance"`
	LegacyAck        string  `json:"legacy_source_acknowledgement,omitempty"`
	PayloadDigest    string  `json:"payload_digest"`
	ExpiresAt        string  `json:"expires_at"`
}

type MediaForwardPreview struct {
	ForwardMediaArgs
	ConfirmationNotice string `json:"confirmation_notice"`
}

func (p ForwardMediaArgs) target() SendTextArgs {
	return SendTextArgs{AccountJID: p.AccountJID, ChatJID: p.ChatJID, IsGroup: p.IsGroup}
}

func (p ForwardMediaArgs) raw() string {
	b, _ := json.Marshal(p)
	return string(b)
}

func (p ForwardMediaArgs) digest() string {
	p.PayloadDigest = ""
	return digestPayload([]byte(p.raw()))
}

func (p *ForwardMediaArgs) bindSource(source forwardSource) {
	p.Kind, p.MIMEType, p.FileName = source.kind, source.mimeType, source.fileName
	p.SizeBytes, p.SHA256, p.Caption = int64(source.attachment.GetFileLength()), source.sha256, source.caption
	p.SourceProvenance = source.provenance
	p.LegacyAck = ""
	if source.provenance == forwardLegacy {
		p.LegacyAck = legacyForwardAck
	}
}

func (p ForwardMediaArgs) matchesSource(source forwardSource) bool {
	fresh := p
	fresh.bindSource(source)
	return p.raw() == fresh.raw()
}

func mediaForwardNotice(p ForwardMediaArgs) string {
	targetType := "direct"
	if p.IsGroup {
		targetType = "group"
	}
	name := "none"
	if p.FileName != "" {
		name = fmt.Sprintf("%q", p.FileName)
	}
	provenance := "Ordinary archived attachment"
	if p.SourceProvenance == forwardLegacy {
		provenance = "Historical attachment. The original privacy wrapper is unavailable. " + p.LegacyAck
	}
	n := fmt.Sprintf("Attachment forward preview for %q (%s, %s).\nSource: %q (%s), message %q\nAttachment: %s (%s), %d bytes\nFilename: %s\nSHA-256: %s\nPrivacy provenance: %s",
		visibleNoticeData(p.DisplayName), targetType, p.ChatJID, visibleNoticeData(p.SourceName), p.SourceChatJID, p.SourceMessageID,
		p.Kind, p.MIMEType, p.SizeBytes, name, p.SHA256, provenance)
	if p.Caption != nil {
		if *p.Caption == "" {
			n += "\nCaption: none"
		} else {
			n += "\nCaption (archived content):\n" + *p.Caption
		}
	}
	return n + "\nApprove this exact attachment in the host approval card."
}

func (a *App) mediaForwardPayload(ctx context.Context, args PrepareMediaForwardArgs) (ForwardMediaArgs, forwardSource, error) {
	var p ForwardMediaArgs
	if args.RequestID == "" {
		args.RequestID = opaqueMessageID()
	}
	if !validRequestID(args.RequestID) {
		return p, forwardSource{}, errors.New("invalid request_id")
	}
	chat, own, name, err := a.messageTarget(ctx, args.ChatJID)
	if err != nil {
		return p, forwardSource{}, err
	}
	src, err := a.store.mediaForwardSource(ctx, args.SourceChatJID, args.SourceMessageID)
	if err != nil {
		return p, forwardSource{}, err
	}
	sourceName := a.store.Names(ctx)[args.SourceChatJID]
	if sourceName == "" {
		sourceName = args.SourceChatJID
	}
	p = ForwardMediaArgs{
		Operation: forwardMediaOperation, RequestID: args.RequestID,
		AccountJID: own.String(), ChatJID: chat.String(), DisplayName: name, IsGroup: chat.Server == types.GroupServer,
		SourceChatJID: args.SourceChatJID, SourceMessageID: args.SourceMessageID, SourceName: sourceName,
	}
	p.bindSource(src)
	return p, src, nil
}

func (a *App) prepareMediaForward(ctx context.Context, _ *mcp.CallToolRequest, args PrepareMediaForwardArgs) (*mcp.CallToolResult, MediaForwardPreview, error) {
	p, _, err := a.mediaForwardPayload(ctx, args)
	if err != nil {
		return nil, MediaForwardPreview{}, err
	}
	p.ExpiresAt = time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339Nano)
	p.PayloadDigest = p.digest()
	return nil, MediaForwardPreview{ForwardMediaArgs: p, ConfirmationNotice: mediaForwardNotice(p)}, nil
}

func mediaForwardStillFresh(expiresAt string) bool {
	exp, err := time.Parse(time.RFC3339Nano, expiresAt)
	now := time.Now()
	return err == nil && exp.After(now) && !exp.After(now.Add(15*time.Minute+time.Second))
}

func (a *App) validateFreshMediaForward(ctx context.Context, p ForwardMediaArgs) (forwardSource, error) {
	if !mediaForwardStillFresh(p.ExpiresAt) {
		return forwardSource{}, errors.New("preview expired or invalid; prepare and confirm again")
	}
	fresh, source, err := a.mediaForwardPayload(ctx, PrepareMediaForwardArgs{
		RequestID: p.RequestID, ChatJID: p.ChatJID,
		SourceChatJID: p.SourceChatJID, SourceMessageID: p.SourceMessageID,
	})
	if err != nil {
		return forwardSource{}, err
	}
	if !mediaForwardStillFresh(p.ExpiresAt) {
		return forwardSource{}, errors.New("preview expired or invalid; prepare and confirm again")
	}
	fresh.ExpiresAt = p.ExpiresAt
	fresh.PayloadDigest = fresh.digest()
	if p.raw() != fresh.raw() {
		return forwardSource{}, errors.New("media preview payload changed; prepare and confirm again")
	}
	return source, nil
}

func (a *App) forwardMedia(ctx context.Context, _ *mcp.CallToolRequest, p ForwardMediaArgs) (*mcp.CallToolResult, SendStatus, error) {
	if !validRequestID(p.RequestID) || p.Operation != forwardMediaOperation {
		return nil, SendStatus{}, errors.New("invalid forward request")
	}
	if a.wa == nil || !a.authority.active() || a.messageWrites == a.messageConfirmationTest {
		return nil, SendStatus{}, errors.New("media forwarding requires an enabled active owner")
	}
	own, err := a.messageOwner(ctx, p.AccountJID)
	if err != nil {
		return nil, SendStatus{}, err
	}
	if a.messageConfirmationTest {
		a.wa.confirmationInvocations.Add(1)
		if _, err := a.validateFreshMediaForward(ctx, p); err != nil {
			return nil, SendStatus{}, err
		}
		return nil, SendStatus{
			RequestID: p.RequestID, State: "confirmation_test_only_not_sent",
			Outcome: "confirmation_test_only_not_sent", MediaPayload: &p,
		}, nil
	}
	raw := p.raw()
	op, prior, err := a.beginMessage(ctx, p.RequestID, func(ctx context.Context) (SendStatus, error) {
		return a.store.existingOutboxMessage(ctx, p.RequestID, raw)
	})
	if op == nil {
		return nil, prior, err
	}
	defer op.finish()
	// Immutable replays have already returned. An admitted new operation may
	// use only the earlier of its send budget and the confirmed approval expiry.
	expires, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if err != nil || !mediaForwardStillFresh(p.ExpiresAt) {
		return nil, SendStatus{}, errors.New("preview expired or invalid; prepare and confirm again")
	}
	mediaCtx, cancel := context.WithDeadline(op.ctx, expires)
	defer cancel()
	op.ctx = mediaCtx
	if !messageConnected(op.ctx, op.transport) {
		return nil, SendStatus{}, errors.New("owner is offline; no message reserved")
	}
	if _, err := a.validateFreshMediaForward(op.ctx, p); err != nil {
		return nil, SendStatus{}, err
	}
	wire, _, err := a.messageWire(op.ctx, p.target(), op.transport)
	if err != nil {
		return nil, SendStatus{}, err
	}
	if !a.authority.active() {
		return nil, SendStatus{}, errors.New("owner authority revoked")
	}
	chosen := a.wa.Client.GenerateMessageID()
	var source forwardSource
	out, won, err := a.store.reserveOutboxMessage(op.ctx, p.RequestID, p.AccountJID, raw, chosen, func(tx *sql.Tx) error {
		src, err := mediaForwardSourceTx(op.ctx, tx, p.SourceChatJID, p.SourceMessageID)
		if err != nil || !p.matchesSource(src) || !mediaForwardStillFresh(p.ExpiresAt) {
			return errors.New("media source changed before reservation")
		}
		source = src
		return nil
	})
	op.notifyReservation()
	if err != nil || !won {
		return nil, out, err
	}

	// From this point a cancellation or crash retains an immutable reservation.
	// A known pre-dispatch failure can be settled without reusing its ID.
	result := a.dispatchReservedMedia(op, out, p, source, wire, own)
	return nil, result, nil
}

func (a *App) dispatchReservedMedia(op *messageAdmission, out SendStatus, p ForwardMediaArgs, source forwardSource, wire, own types.JID) SendStatus {
	reject := func(outcome string) SendStatus {
		settleCtx, cancel := context.WithTimeout(context.WithoutCancel(op.ctx), 5*time.Second)
		defer cancel()
		out.State, out.Outcome = "rejected", outcome
		return a.persistMessageOutcome(settleCtx, out)
	}
	if !a.authority.active() || op.ctx.Err() != nil {
		return reject("media_authority_unavailable_before_recipient_send")
	}
	if _, err := a.messageOwner(op.ctx, p.AccountJID); err != nil {
		return reject("media_authority_unavailable_before_recipient_send")
	}
	if !mediaForwardStillFresh(p.ExpiresAt) {
		return reject("media_preview_expired_before_recipient_send")
	}
	upload, err := a.wa.uploadForwardMedia(op.ctx, p, source)
	if err != nil {
		return reject("media_transfer_failed_before_recipient_send")
	}
	currentWire, _, err := a.messageWire(op.ctx, p.target(), op.transport)
	if err != nil || currentWire != wire {
		return reject("media_destination_changed_before_recipient_send")
	}
	if currentOwner, err := a.messageOwner(op.ctx, p.AccountJID); err != nil || currentOwner != own {
		return reject("media_authority_unavailable_before_recipient_send")
	}
	// Check the archive again after all slow transfer and routing work.
	fresh, err := a.validateFreshMediaForward(op.ctx, p)
	if err != nil {
		return reject("media_preview_changed_before_recipient_send")
	}
	msg := forwardMediaProto(p, fresh, upload)
	if !a.authority.active() || !a.wa.LoggedIn() || op.ctx.Err() != nil {
		return reject("media_authority_unavailable_before_recipient_send")
	}
	if !mediaForwardStillFresh(p.ExpiresAt) {
		return reject("media_preview_expired_before_recipient_send")
	}
	response, sendErr := op.transport.SendMessage(op.ctx, currentWire, msg, whatsmeow.SendRequestExtra{ID: out.MessageID, Timeout: 25 * time.Second})
	return a.settleDispatchedMessage(op.ctx, out, p.target(), own, msg, response, sendErr)
}
