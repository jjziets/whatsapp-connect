package main

// TRACEWEAVER: C-007 / TRACE-OWNERMSG-007 / VER-OWNERMSG-007.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"mime"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	maxForwardBytes = 16 * 1024 * 1024
	forwardKnown    = "known_ordinary"
	forwardLegacy   = "legacy_unknown"
)

const forwardProvenanceSchema = `
CREATE TABLE IF NOT EXISTS mcp_media_forward_provenance (
  chat_jid TEXT NOT NULL,
  id TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  PRIMARY KEY (chat_jid, id, sha256)
) WITHOUT ROWID;
`

var (
	errForwardSource     = errors.New("eligible media source unavailable; select an exact archived attachment")
	errForwardRestricted = errors.New("restricted archived media cannot be forwarded")
)

// An empty fingerprint is a sticky restriction for the complete source
// identity, including duplicate or ambiguous originals. Nonempty fingerprints
// are positive witnesses that the corresponding original envelope was seen.
type forwardObservation struct {
	ordinaryHash string
	restricted   bool
}

type forwardAttachment interface {
	whatsmeow.DownloadableMessage
	proto.Message
	GetContextInfo() *waE2E.ContextInfo
	GetFileLength() uint64
	GetMimetype() string
}

type forwardSource struct {
	attachment forwardAttachment
	kind       string
	mimeType   string
	fileName   string
	sha256     string
	caption    *string
	provenance string
}

func archivedAttachment(msg *waE2E.Message) (string, forwardAttachment) {
	switch {
	case msg.GetImageMessage() != nil:
		return "image", msg.GetImageMessage()
	case msg.GetDocumentMessage() != nil:
		return "document", msg.GetDocumentMessage()
	case msg.GetAudioMessage() != nil && !msg.GetAudioMessage().GetPTT():
		return "audio", msg.GetAudioMessage()
	default:
		return "", nil
	}
}

func forwardFingerprint(hash []byte) string {
	if len(hash) != sha256.Size || bytes.Equal(hash, make([]byte, sha256.Size)) {
		return ""
	}
	return hex.EncodeToString(hash)
}

func restrictedForwardFields(m *waE2E.Message) bool {
	c := m.GetMessageContextInfo()
	if len(c.ProtoReflect().GetUnknown()) != 0 ||
		c.GetLimitSharing().GetSharingLimited() || c.GetLimitSharingV2().GetSharingLimited() ||
		m.GetViewOnceMessage() != nil || m.GetViewOnceMessageV2() != nil ||
		m.GetViewOnceMessageV2Extension() != nil || m.GetEphemeralMessage() != nil ||
		m.GetEditedMessage() != nil || m.GetKeepInChatMessage() != nil || m.GetLimitSharingMessage() != nil ||
		m.GetImageMessage().GetViewOnce() || m.GetAudioMessage().GetViewOnce() ||
		m.GetStatusMentionMessage() != nil || m.GetGroupStatusMentionMessage() != nil ||
		m.GetGroupStatusMessage() != nil || m.GetGroupStatusMessageV2() != nil ||
		m.GetSpoilerMessage() != nil || m.GetConditionalRevealMessage() != nil {
		return true
	}
	_, a := archivedAttachment(m)
	if a == nil {
		return false
	}
	x := a.GetContextInfo()
	return x.GetExpiration() > 0 || x.GetAfterReadDuration() > 0 || x.GetEphemeralSettingTimestamp() > 0 ||
		len(x.GetEphemeralSharedSecret()) > 0 || x.GetDisappearingMode() != nil ||
		x.GetIsGroupStatus() || x.GetStatusAudienceMetadata() != nil
}

func restrictedForwardHistoryMutation(web *waWeb.WebMessageInfo) bool {
	stub := web.GetMessageStubType()
	return stub == waWeb.WebMessageInfo_REVOKE || stub == waWeb.WebMessageInfo_ADMIN_REVOKE ||
		web.GetRevokeMessageTimestamp() > 0 ||
		web.GetGroupHistoryIndividualMessageInfo().GetEditedAfterReceivedAsHistory()
}

func restrictedForwardHistory(web *waWeb.WebMessageInfo) bool {
	return restrictedForwardHistoryMutation(web) ||
		web.GetEphemeralStartTimestamp() > 0 || web.GetEphemeralDuration() > 0 ||
		web.GetEphemeralOffToOn() || web.GetEphemeralOutOfSync() ||
		web.GetEphemeralExpirationTimestamp() > 0 || web.GetKeepInChat() != nil ||
		web.GetQuarantinedMessage() != nil || web.GetIsMentionedInStatus() ||
		web.GetBroadcast() || web.GetMulticast() || web.GetClearMedia()
}

// Inspect positive privacy fields without requiring a parsed sender or treating
// an unrecognized payload as evidence. Look through the transparent wrappers.
func restrictedForwardRawFields(m *waE2E.Message, depth int) bool {
	if m == nil || depth == 0 {
		return false
	}
	return restrictedForwardFields(m) ||
		restrictedForwardRawFields(m.GetDeviceSentMessage().GetMessage(), depth-1) ||
		restrictedForwardRawFields(m.GetDocumentWithCaptionMessage().GetMessage(), depth-1)
}

func historyForwardProtocolMessage(m *waE2E.Message) *waE2E.ProtocolMessage {
	for depth := 0; m != nil && depth < 4; depth++ {
		if pm := m.GetProtocolMessage(); pm != nil {
			return pm
		}
		switch {
		case m.GetDeviceSentMessage() != nil:
			m = m.GetDeviceSentMessage().GetMessage()
		case m.GetDocumentWithCaptionMessage() != nil:
			m = m.GetDocumentWithCaptionMessage().GetMessage()
		case m.GetEditedMessage() != nil:
			m = m.GetEditedMessage().GetMessage()
		default:
			return nil
		}
	}
	return nil
}

// Follow the two supported transparent wrappers. Any other populated outer
// payload or unknown field makes the envelope unsuitable as ordinary evidence.
func ordinaryForwardEnvelope(m *waE2E.Message) (forwardAttachment, bool) {
	for depth := 0; m != nil && depth < 4; depth++ {
		if restrictedForwardFields(m) || len(m.ProtoReflect().GetUnknown()) != 0 {
			return nil, false
		}
		var payloadCount int
		m.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
			switch field.Name() {
			case "messageContextInfo", "senderKeyDistributionMessage", "fastRatchetKeySenderKeyDistributionMessage":
			default:
				payloadCount++
			}
			return true
		})
		if payloadCount != 1 {
			return nil, false
		}
		switch {
		case m.GetDeviceSentMessage() != nil:
			m = m.GetDeviceSentMessage().GetMessage()
		case m.GetDocumentWithCaptionMessage() != nil:
			m = m.GetDocumentWithCaptionMessage().GetMessage()
		default:
			_, a := archivedAttachment(m)
			return a, a != nil
		}
	}
	return nil, false
}

// The SDK can leave some restricted wrappers intact. Recognize media in these
// without teaching the normal read/archive extractor to unwrap them.
func hasForwardMedia(m *waE2E.Message, depth int) bool {
	if m == nil || depth == 0 {
		return false
	}
	if _, a := archivedAttachment(m); a != nil {
		return true
	}
	for _, nested := range []*waE2E.Message{
		m.GetDeviceSentMessage().GetMessage(), m.GetDocumentWithCaptionMessage().GetMessage(),
		m.GetViewOnceMessage().GetMessage(), m.GetViewOnceMessageV2().GetMessage(),
		m.GetViewOnceMessageV2Extension().GetMessage(), m.GetEphemeralMessage().GetMessage(),
		m.GetLimitSharingMessage().GetMessage(), m.GetEditedMessage().GetMessage(),
		m.GetBotInvokeMessage().GetMessage(), m.GetGroupStatusMessage().GetMessage(),
		m.GetGroupStatusMessageV2().GetMessage(), m.GetSpoilerMessage().GetMessage(),
	} {
		if hasForwardMedia(nested, depth-1) {
			return true
		}
	}
	return false
}

type forwardConversationRestrictionKey struct{}

func observeForwardSource(evt *events.Message, conversationRestricted bool) forwardObservation {
	raw := evt.RawMessage
	if w := evt.SourceWebMsg; w != nil {
		raw = w.GetMessage()
	}
	_, attachment := archivedAttachment(evt.Message)
	if attachment == nil && !hasForwardMedia(raw, 8) {
		return forwardObservation{}
	}
	if conversationRestricted || evt.IsViewOnce || evt.IsEphemeral || evt.IsEdit || evt.IsBotInvoke ||
		evt.Info.Multicast || evt.Info.Edit == types.EditAttributeMessageEdit ||
		evt.Info.Edit == types.EditAttributeAdminEdit || evt.Info.Edit == types.EditAttributeSenderRevoke ||
		evt.Info.Edit == types.EditAttributeAdminRevoke ||
		restrictedForwardHistory(evt.SourceWebMsg) || restrictedForwardFields(evt.Message) {
		return forwardObservation{restricted: true}
	}
	if raw == nil {
		// Some archive inputs have already lost the original envelope.
		return forwardObservation{}
	}
	original, ok := ordinaryForwardEnvelope(raw)
	if !ok {
		return forwardObservation{restricted: true}
	}
	if attachment != nil && proto.Equal(original, attachment) {
		return forwardObservation{ordinaryHash: forwardFingerprint(attachment.GetFileSHA256())}
	}
	return forwardObservation{restricted: true}
}

func putForwardObservationTx(ctx context.Context, tx *sql.Tx, chat, id, hash string) error {
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO mcp_media_forward_provenance(chat_jid,id,sha256) VALUES(?,?,?)`, chat, id, hash)
	return err
}

func (s *Store) restrictForwardHistorySource(ctx context.Context, chat types.JID, web *waWeb.WebMessageInfo, conversationRestricted bool) error {
	envelope := web.GetKey()
	if envelope == nil {
		return nil
	}
	raw := web.GetMessage()
	if pm := historyForwardProtocolMessage(raw); pm != nil {
		// REVOKE is the protobuf enum default. A protocol mutation must name
		// its type and target explicitly, independently of the envelope ID.
		if pm.Type == nil || (pm.GetType() != waE2E.ProtocolMessage_REVOKE && pm.GetType() != waE2E.ProtocolMessage_MESSAGE_EDIT) {
			return nil
		}
		target := pm.GetKey()
		return s.restrictForwardSource(ctx, chat, target.GetID(), envelope.GetRemoteJID(), target.GetRemoteJID())
	}
	if conversationRestricted || restrictedForwardHistory(web) || restrictedForwardRawFields(raw, 4) {
		return s.restrictForwardSource(ctx, chat, envelope.GetID(), envelope.GetRemoteJID())
	}
	return nil
}

// Bind supplied addresses to one conversation before recording a restriction.
// A mixed PN/LID can be verified by the archive alias or the durable SDK pair.
func (s *Store) restrictForwardSource(ctx context.Context, chat types.JID, id string, itemChats ...string) error {
	j, err := supportedMessageJID(chat.ToNonAD().String())
	if err != nil || !validRequestID(id) {
		return nil
	}
	var counterpart types.JID
	for _, itemChat := range itemChats {
		if itemChat == "" {
			continue
		}
		raw, err := types.ParseJID(itemChat)
		if err != nil || raw.String() != itemChat {
			return nil
		}
		remote, err := supportedMessageJID(raw.ToNonAD().String())
		if err != nil {
			return nil
		}
		if remote == j {
			continue
		}
		if !counterpart.IsEmpty() && counterpart != remote {
			return nil
		}
		counterpart = remote
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		raw := j.String()
		var other string
		if counterpart.IsEmpty() {
			var err error
			other, err = canonicalTx(ctx, tx, raw)
			if err != nil {
				return err
			}
		} else {
			lid, pn := j, counterpart
			if j.Server == types.DefaultUserServer {
				lid, pn = counterpart, j
			}
			if lid.Server != types.HiddenUserServer || pn.Server != types.DefaultUserServer {
				return nil
			}
			canonical, err := canonicalTx(ctx, tx, lid.String())
			if err != nil {
				return err
			}
			if canonical != pn.String() {
				var verified bool
				err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM whatsmeow_lid_map WHERE lid=? AND pn=?)`, lid.User, pn.User).Scan(&verified)
				if err != nil || !verified {
					return err
				}
			}
			// Both supplied addresses are now verified. A different archive PN
			// is irrelevant when the SDK pair was the only match.
			other = counterpart.String()
		}
		if err := putForwardObservationTx(ctx, tx, raw, id, ""); err != nil || other == raw {
			return err
		}
		return putForwardObservationTx(ctx, tx, other, id, "")
	})
}

func forwardHashOf(raw []byte) string {
	var msg waE2E.Message
	if len(raw) == 0 || proto.Unmarshal(raw, &msg) != nil {
		return ""
	}
	_, a := archivedAttachment(&msg)
	if a == nil {
		return ""
	}
	return forwardFingerprint(a.GetFileSHA256())
}

func sameForwardContent(a, b StoredMessage) bool {
	return a.Kind == b.Kind && a.Text == b.Text && a.Mime == b.Mime &&
		a.FileName == b.FileName && a.Size == b.Size
}

func observeForwardOriginalTx(ctx context.Context, tx *sql.Tx, in archiveInput, old StoredMessage, duplicate bool) error {
	proof := in.forwardProof
	if proof.restricted {
		return putForwardObservationTx(ctx, tx, in.m.ChatJID, in.m.ID, "")
	}
	if proof.ordinaryHash == "" {
		return nil
	}
	if duplicate {
		oldHash := forwardHashOf(old.Raw)
		if oldHash == "" {
			return nil
		}
		if oldHash != proof.ordinaryHash || !sameForwardContent(old, in.m) ||
			old.SenderJID != in.m.SenderJID || old.Timestamp.Unix() != in.m.Timestamp.Unix() || old.FromMe != in.m.FromMe {
			// An ambiguous original must not receive a legacy override.
			return putForwardObservationTx(ctx, tx, in.m.ChatJID, in.m.ID, "")
		}
	}
	return putForwardObservationTx(ctx, tx, in.m.ChatJID, in.m.ID, proof.ordinaryHash)
}

func mergeForwardObservationsTx(ctx context.Context, tx *sql.Tx, lid, pn string) error {
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO mcp_media_forward_provenance(chat_jid,id,sha256)
		SELECT ?,id,sha256 FROM mcp_media_forward_provenance WHERE chat_jid=?`, pn, lid)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM mcp_media_forward_provenance WHERE chat_jid=?`, lid)
	return err
}

func validForwardCaption(s string) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) <= 4096 &&
		strings.IndexFunc(s, func(r rune) bool {
			return unicode.In(r, unicode.Cf) || (unicode.IsControl(r) && r != '\n' && r != '\t')
		}) == -1
}

func validForwardFilename(s string) bool {
	return len(s) > 0 && len(s) <= 255 && s == strings.TrimSpace(s) &&
		s != "." && s != ".." && !strings.ContainsAny(s, "/\\:") && utf8.ValidString(s) &&
		strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.In(r, unicode.Cf) }) == -1
}

func forwardMIME(kind, raw string) (string, bool) {
	m, params, err := mime.ParseMediaType(raw)
	if err != nil || len(raw) > 80 || strings.ContainsAny(raw, "\r\n\t") {
		return "", false
	}
	switch kind {
	case "image":
		return m, len(params) == 0 && oneOf(m, "image/jpeg", "image/png")
	case "document":
		return m, len(params) == 0 && m == "application/pdf"
	case "audio":
		return m, (len(params) == 0 && oneOf(m, "audio/mpeg", "audio/mp4", "audio/ogg")) ||
			(m == "audio/ogg" && len(params) == 1 && strings.EqualFold(params["codecs"], "opus"))
	default:
		return "", false
	}
}

// The SDK's verified mapping is committed before the archive reconciliation
// runs. A reader can observe that durable mapping while incompatible rows
// still exist under both identities. Detect the overlap in the source snapshot
// without forcing a merge or changing which stored row is returned for reads.
func forwardAliasOverlapTx(ctx context.Context, tx *sql.Tx, source types.JID, id string, tracked bool) (bool, error) {
	if source.Server != types.DefaultUserServer {
		return false, nil
	}
	var lidUser string
	err := tx.QueryRowContext(ctx, `SELECT lid FROM whatsmeow_lid_map WHERE pn=?`, source.User).Scan(&lidUser)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	lid := types.NewJID(lidUser, types.HiddenUserServer).String()
	if _, err := supportedMessageJID(lid); err != nil {
		return false, err
	}
	var overlaps bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM mcp_messages WHERE chat_jid=? AND id=?
		UNION ALL
		SELECT 1 FROM mcp_message_mutations WHERE chat_jid=? AND id=?
	)`, lid, id, lid, id).Scan(&overlaps); err != nil || overlaps || !tracked {
		return overlaps, err
	}
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM mcp_media_forward_provenance WHERE chat_jid=? AND id=?
	)`, lid, id).Scan(&overlaps)
	return overlaps, err
}

func mediaForwardSourceTx(ctx context.Context, tx *sql.Tx, chat, id string) (forwardSource, error) {
	if !validRequestID(id) {
		return forwardSource{}, errForwardSource
	}
	j, err := supportedMessageJID(chat)
	if err != nil || j.Server == types.HiddenUserServer {
		return forwardSource{}, errForwardSource
	}
	current, err := canonicalTx(ctx, tx, chat)
	if err != nil || current != chat {
		return forwardSource{}, errForwardSource
	}
	// The bytes saved here are the protobuf metadata. Plain media is obtained
	// later on the write path under its independent byte and deadline limits.
	m, edited, deleted, exists, err := loadMessageTx(ctx, tx, chat, id)
	if err != nil || !exists {
		return forwardSource{}, errForwardSource
	}
	if edited || deleted {
		return forwardSource{}, errForwardRestricted
	}
	var tracked bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='mcp_media_forward_provenance')`).Scan(&tracked); err != nil {
		return forwardSource{}, errForwardSource
	}
	overlaps, err := forwardAliasOverlapTx(ctx, tx, j, id, tracked)
	if err != nil {
		return forwardSource{}, errForwardSource
	}
	if overlaps {
		return forwardSource{}, errForwardRestricted
	}
	if tracked {
		var restricted bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mcp_media_forward_provenance WHERE chat_jid=? AND id=? AND sha256='')`, chat, id).Scan(&restricted); err != nil {
			return forwardSource{}, errForwardSource
		}
		if restricted {
			return forwardSource{}, errForwardRestricted
		}
	}
	var msg waE2E.Message
	if len(m.Raw) == 0 || len(m.Raw) > 2*1024*1024 || (proto.UnmarshalOptions{RecursionLimit: 32}).Unmarshal(m.Raw, &msg) != nil {
		return forwardSource{}, errForwardSource
	}
	if restrictedForwardFields(&msg) {
		return forwardSource{}, errForwardRestricted
	}
	a, ok := ordinaryForwardEnvelope(&msg)
	if !ok {
		return forwardSource{}, errForwardSource
	}
	kind, _ := archivedAttachment(&msg)
	if a.GetFileLength() == 0 || a.GetFileLength() > maxForwardBytes ||
		kind != m.Kind || a.GetMimetype() != m.Mime || int64(a.GetFileLength()) != m.Size {
		return forwardSource{}, errForwardSource
	}
	if _, ok := forwardMIME(kind, m.Mime); !ok {
		return forwardSource{}, errForwardSource
	}
	hash := forwardFingerprint(a.GetFileSHA256())
	if hash == "" {
		return forwardSource{}, errForwardSource
	}
	if kind == "document" {
		doc := msg.GetDocumentMessage()
		name := doc.GetFileName()
		if name == "" {
			name = doc.GetTitle()
		}
		if name != m.FileName || (name != "" && !validForwardFilename(name)) {
			return forwardSource{}, errForwardSource
		}
	} else if m.FileName != "" {
		return forwardSource{}, errForwardSource
	}
	source := forwardSource{attachment: a, kind: kind, mimeType: m.Mime, fileName: m.FileName, sha256: hash, provenance: forwardLegacy}
	if kind != "audio" {
		caption := msg.GetImageMessage().GetCaption()
		if kind == "document" {
			caption = msg.GetDocumentMessage().GetCaption()
		}
		if caption != m.Text || !validForwardCaption(caption) {
			return forwardSource{}, errForwardSource
		}
		source.caption = &caption
	}
	if tracked {
		var known bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mcp_media_forward_provenance WHERE chat_jid=? AND id=? AND sha256=?)`, chat, id, hash).Scan(&known); err != nil {
			return forwardSource{}, errForwardSource
		}
		if known {
			source.provenance = forwardKnown
		}
	}
	return source, nil
}

func (s *Store) mediaForwardSource(ctx context.Context, chat, id string) (forwardSource, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return forwardSource{}, errForwardSource
	}
	defer tx.Rollback()
	return mediaForwardSourceTx(ctx, tx, chat, id)
}
