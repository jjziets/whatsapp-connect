package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hansen/whatsapp-mcp/internal/securestore"
	sqlite "github.com/mattn/go-sqlite3"
	"go.mau.fi/whatsmeow/types"
)

// The whole state lives in one SQLite file: whatsmeow's own session/contact tables
// (whatsmeow_*) plus this server's message archive (mcp_*). Keeping them together
// lets the archive resolve names from whatsmeow_contacts / whatsmeow_lid_map.

const schema = `
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

CREATE INDEX IF NOT EXISTS mcp_messages_total_order ON mcp_messages(timestamp,chat_jid COLLATE BINARY,id COLLATE BINARY);
CREATE INDEX IF NOT EXISTS mcp_messages_chat_order ON mcp_messages(chat_jid COLLATE BINARY,timestamp,id COLLATE BINARY);

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

type Store struct {
	eventsMu           sync.RWMutex
	events             *EventService
	db                 *sql.DB
	writeMu            sync.Mutex
	telemetryUnhealthy atomic.Bool

	namesMu      sync.Mutex
	names        map[string]string
	namesExpires time.Time
}

func openDB(path string, readOnly bool, allowNewProfile ...bool) (*sql.DB, error) {
	allowCreate := len(allowNewProfile) == 1 && allowNewProfile[0]
	return securestore.OpenProfile(path, readOnly, allowCreate, securestore.NewNativeKeyStore())
}

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// WC-PRELINK-01: C-002/C-003/C-006; native manual trace review, Go scanner unsupported.
const archiveUpgrade = `
CREATE TABLE IF NOT EXISTS mcp_aliases (lid TEXT PRIMARY KEY,pn TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS mcp_originals (chat_jid TEXT NOT NULL,id TEXT NOT NULL,PRIMARY KEY(chat_jid,id));
CREATE TABLE IF NOT EXISTS mcp_message_mutations (chat_jid TEXT NOT NULL,id TEXT NOT NULL,ms INTEGER NOT NULL DEFAULT 0,event_id TEXT NOT NULL DEFAULT '',digest TEXT NOT NULL DEFAULT '',content TEXT NOT NULL DEFAULT '',raw BLOB,deleted INTEGER NOT NULL DEFAULT 0,legacy INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(chat_jid,id));
CREATE TABLE IF NOT EXISTS mcp_reaction_states (chat_jid TEXT NOT NULL,message_id TEXT NOT NULL,sender_jid TEXT NOT NULL,emoji TEXT NOT NULL,ms INTEGER NOT NULL,event_id TEXT NOT NULL DEFAULT '',digest TEXT NOT NULL DEFAULT '',PRIMARY KEY(chat_jid,message_id,sender_jid));
CREATE TABLE IF NOT EXISTS mcp_history_counts (chat_jid TEXT PRIMARY KEY,history_inserted INTEGER NOT NULL DEFAULT 0);
`

// WC-HISTORY-REPAIR-01: C-003/C-006, VER-HISTORY-001; manual Go trace review.
type transactionFailure struct {
	stage string
	cause error
}

func (e *transactionFailure) Error() string { return "archive transaction failed" }
func (e *transactionFailure) Unwrap() error { return e.cause }
func (e *transactionFailure) SQLiteDiagnostic() (string, int, int) {
	var diagnostic interface{ SQLiteDiagnostic() (string, int, int) }
	if errors.As(e.cause, &diagnostic) {
		return diagnostic.SQLiteDiagnostic()
	}
	var cause sqlite.Error
	if errors.As(e.cause, &cause) {
		return e.stage, int(cause.Code), int(cause.ExtendedCode)
	}
	return e.stage, 0, 0
}

func (s *Store) transaction(ctx context.Context, fn func(*sql.Tx) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			if canceled := ctx.Err(); canceled != nil {
				return canceled
			}
			return &transactionFailure{stage: "transaction_begin", cause: err}
		}
		// Also release the connection if a caller panics. Failed attempts are
		// explicitly rolled back below before any replay, never by this defer.
		defer tx.Rollback()
		if err = fn(tx); err != nil {
			// Never replay a body unless its entire SQL transaction is known to
			// have rolled back. ErrTxDone includes an already committed body.
			rollbackErr := tx.Rollback()
			if canceled := ctx.Err(); canceled != nil {
				return canceled
			}
			var cause sqlite.Error
			if attempt < 2 && rollbackErr == nil && errors.As(err, &cause) && cause.Code == sqlite.ErrBusy && cause.ExtendedCode == sqlite.ErrBusySnapshot {
				continue
			}
			return &transactionFailure{stage: "transaction_body", cause: err}
		}
		if canceled := ctx.Err(); canceled != nil {
			_ = tx.Rollback()
			return canceled
		}
		// A commit error has uncertain durability and is never a replay signal.
		if err := tx.Commit(); err != nil {
			_ = tx.Rollback()
			if canceled := ctx.Err(); canceled != nil {
				return canceled
			}
			return &transactionFailure{stage: "transaction_commit", cause: err}
		}
		return nil
	}
}
func (s *Store) Migrate(ctx context.Context) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, schema+archiveUpgrade+outboxSchema+forwardProvenanceSchema); err != nil {
			return err
		}
		var version string
		err := tx.QueryRowContext(ctx, `SELECT value FROM mcp_meta WHERE key='prelink_schema_version'`).Scan(&version)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if version == "1" {
			return nil
		}
		if version != "" {
			return fmt.Errorf("unsupported archive schema version")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_originals SELECT chat_jid,id FROM mcp_messages WHERE kind <> 'deleted'`); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT chat_jid,id,kind,text,media_mime,media_filename,media_size,media_seconds,quoted_id,raw,deleted,edited FROM mcp_messages WHERE edited OR deleted`)
		if err != nil {
			return err
		}
		type old struct {
			chat, id        string
			c               Content
			raw             []byte
			deleted, edited bool
		}
		var legacy []old
		for rows.Next() {
			var x old
			if err := rows.Scan(&x.chat, &x.id, &x.c.Kind, &x.c.Text, &x.c.Mime, &x.c.FileName, &x.c.Size, &x.c.Seconds, &x.c.QuotedID, &x.raw, &x.deleted, &x.edited); err != nil {
				rows.Close()
				return err
			}
			legacy = append(legacy, x)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, x := range legacy {
			payload, _ := json.Marshal(x.c)
			// A revoke is terminal; never copy old deleted media into hidden
			// mutation state while scrubbing only the visible message row.
			if x.deleted {
				payload = nil
				x.raw = nil
				x.edited = false
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_message_mutations(chat_jid,id,content,raw,deleted,legacy) VALUES(?,?,?,?,?,?)`, x.chat, x.id, string(payload), x.raw, x.deleted, x.edited); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_reaction_states(chat_jid,message_id,sender_jid,emoji,ms) SELECT chat_jid,message_id,sender_jid,emoji,timestamp*1000 FROM mcp_reactions`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mcp_messages SET text='',raw=NULL,media_mime='',media_filename='',media_size=0,media_seconds=0 WHERE deleted`); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO mcp_meta(key,value) VALUES('prelink_schema_version','1'),('order_epoch','0')`)
		return err
	})
}

type StoredMessage struct {
	ChatJID, ID, SenderJID string
	FromMe                 bool
	Timestamp              time.Time
	PushName               string
	Content
	Raw []byte
}
type IngestOutcome string

const (
	IngestInserted  IngestOutcome = "inserted"
	IngestUpdated   IngestOutcome = "updated"
	IngestDuplicate IngestOutcome = "duplicate"
	IngestIgnored   IngestOutcome = "ignored"
	IngestFailed    IngestOutcome = "failed"
)

type archiveInput struct {
	forwardProof forwardObservation
	live         bool
	legacy       bool
	kind         string
	m            StoredMessage
	ms           int64
	eventID      string
	emoji        string
}
type mutation struct {
	ms                     int64
	event, digest, content string
	raw                    []byte
	deleted, legacy        bool
}

func digestPayload(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func newer(ms int64, event, digest string, oldMS int64, oldEvent, oldDigest string) bool {
	if ms != oldMS {
		return ms > oldMS
	}
	if event != oldEvent {
		return event > oldEvent
	}
	return digest > oldDigest
}
func mutationTx(ctx context.Context, tx *sql.Tx, chat, id string) (mutation, bool, error) {
	var m mutation
	err := tx.QueryRowContext(ctx, `SELECT ms,event_id,digest,content,raw,deleted,legacy FROM mcp_message_mutations WHERE chat_jid=? AND id=?`, chat, id).Scan(&m.ms, &m.event, &m.digest, &m.content, &m.raw, &m.deleted, &m.legacy)
	if errors.Is(err, sql.ErrNoRows) {
		return m, false, nil
	}
	return m, err == nil, err
}
func putMutationTx(ctx context.Context, tx *sql.Tx, chat, id string, m mutation) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mcp_message_mutations(chat_jid,id,ms,event_id,digest,content,raw,deleted,legacy) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(chat_jid,id) DO UPDATE SET ms=excluded.ms,event_id=excluded.event_id,digest=excluded.digest,content=excluded.content,raw=excluded.raw,deleted=excluded.deleted,legacy=excluded.legacy`, chat, id, m.ms, m.event, m.digest, m.content, m.raw, m.deleted, m.legacy)
	return err
}
func touchTx(ctx context.Context, tx *sql.Tx, jid string, group bool, ts int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mcp_chats(jid,is_group,last_message_at) VALUES(?,?,?) ON CONFLICT(jid) DO UPDATE SET last_message_at=MAX(last_message_at,excluded.last_message_at)`, jid, group, ts)
	return err
}
func canonicalTx(ctx context.Context, tx *sql.Tx, jid string) (string, error) {
	var pn string
	err := tx.QueryRowContext(ctx, `SELECT pn FROM mcp_aliases WHERE lid=?`, jid).Scan(&pn)
	if errors.Is(err, sql.ErrNoRows) {
		return jid, nil
	}
	return pn, err
}
func saveMessageTx(ctx context.Context, tx *sql.Tx, m *StoredMessage, edited, deleted bool) error {
	if deleted {
		m.Text = ""
		m.Raw = nil
		m.Mime = ""
		m.FileName = ""
		m.Size = 0
		m.Seconds = 0
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO mcp_messages(chat_jid,id,sender_jid,from_me,timestamp,kind,text,push_name,media_mime,media_filename,media_size,media_seconds,quoted_id,raw,edited,deleted) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(chat_jid,id) DO UPDATE SET sender_jid=excluded.sender_jid,from_me=excluded.from_me,timestamp=excluded.timestamp,kind=excluded.kind,text=excluded.text,push_name=excluded.push_name,media_mime=excluded.media_mime,media_filename=excluded.media_filename,media_size=excluded.media_size,media_seconds=excluded.media_seconds,quoted_id=excluded.quoted_id,raw=excluded.raw,edited=excluded.edited,deleted=excluded.deleted`, m.ChatJID, m.ID, m.SenderJID, m.FromMe, m.Timestamp.Unix(), m.Kind, m.Text, m.PushName, m.Mime, m.FileName, m.Size, m.Seconds, m.QuotedID, m.Raw, edited, deleted)
	return err
}
func loadMessageTx(ctx context.Context, tx *sql.Tx, chat, id string) (StoredMessage, bool, bool, bool, error) {
	var m StoredMessage
	var ts int64
	var edited, deleted bool
	err := tx.QueryRowContext(ctx, `SELECT chat_jid,id,sender_jid,from_me,timestamp,kind,text,push_name,media_mime,media_filename,media_size,media_seconds,quoted_id,raw,edited,deleted FROM mcp_messages WHERE chat_jid=? AND id=?`, chat, id).Scan(&m.ChatJID, &m.ID, &m.SenderJID, &m.FromMe, &ts, &m.Kind, &m.Text, &m.PushName, &m.Mime, &m.FileName, &m.Size, &m.Seconds, &m.QuotedID, &m.Raw, &edited, &deleted)
	m.Timestamp = time.Unix(ts, 0)
	if errors.Is(err, sql.ErrNoRows) {
		return m, false, false, false, nil
	}
	return m, edited, deleted, err == nil, err
}
func applyMutation(m *StoredMessage, mu mutation, has bool) (bool, bool, error) {
	if !has {
		return false, false, nil
	}
	if mu.deleted {
		return mu.content != "", true, nil
	}
	if mu.content != "" {
		var c Content
		if err := json.Unmarshal([]byte(mu.content), &c); err != nil {
			return false, false, err
		}
		m.Content = c
		m.Raw = mu.raw
		return true, false, nil
	}
	return false, false, nil
}

func (s *Store) ingest(ctx context.Context, in archiveInput, history bool) (IngestOutcome, error) {
	if in.kind == "ignored" {
		return IngestIgnored, nil
	}
	if in.m.ID == "" {
		return IngestFailed, errors.New("malformed empty message target")
	}
	outcome := IngestDuplicate
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		// Canonicalization, tombstones and reducers mutate this copy only. A
		// replay must start from the supplied original and publish fresh output.
		in := in
		outcome = IngestDuplicate
		var err error
		in.m.ChatJID, err = canonicalTx(ctx, tx, in.m.ChatJID)
		if err != nil {
			return err
		}
		in.m.SenderJID, err = canonicalTx(ctx, tx, in.m.SenderJID)
		if err != nil {
			return err
		}
		if in.kind == "restricted_media_envelope" {
			return putForwardObservationTx(ctx, tx, in.m.ChatJID, in.m.ID, "")
		}
		if err := touchTx(ctx, tx, in.m.ChatJID, strings.HasSuffix(in.m.ChatJID, "@g.us"), in.m.Timestamp.Unix()); err != nil {
			return err
		}
		old, oldEdited, oldDeleted, exists, err := loadMessageTx(ctx, tx, in.m.ChatJID, in.m.ID)
		if err != nil {
			return err
		}
		mu, has, err := mutationTx(ctx, tx, in.m.ChatJID, in.m.ID)
		if err != nil {
			return err
		}
		switch in.kind {
		case "original":
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mcp_originals WHERE chat_jid=? AND id=?`, in.m.ChatJID, in.m.ID).Scan(&n); err != nil {
				return err
			}
			if !oldEdited && !oldDeleted && !(has && (mu.deleted || mu.content != "")) {
				if err := observeForwardOriginalTx(ctx, tx, in, old, n > 0); err != nil {
					return err
				}
			}
			if n > 0 {
				return nil
			}
			if exists && !old.Timestamp.Equal(in.m.Timestamp) {
				if err := bumpEpochTx(ctx, tx); err != nil {
					return err
				}
			}
			edited, deleted, err := applyMutation(&in.m, mu, has)
			if err != nil {
				return err
			}
			if err := saveMessageTx(ctx, tx, &in.m, edited, deleted || oldDeleted); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_originals(chat_jid,id) VALUES(?,?)`, in.m.ChatJID, in.m.ID); err != nil {
				return err
			}
			outcome = IngestInserted
			s.eventsMu.RLock()
			eventService := s.events
			s.eventsMu.RUnlock()
			if eventService != nil {
				if err := eventService.enqueueTx(ctx, tx, in); err != nil {
					return err
				}
			}
		case "edit":
			if in.ms <= 0 && !in.legacy {
				return errors.New("malformed mutation timestamp")
			}
			if has && mu.deleted {
				return nil
			}
			payload, err := json.Marshal(in.m.Content)
			if err != nil {
				return err
			}
			dig := digestPayload(append(append([]byte{}, payload...), in.m.Raw...))
			if has && ((!mu.legacy && in.legacy) || (!mu.legacy && !newer(in.ms, in.eventID, dig, mu.ms, mu.event, mu.digest)) || (mu.legacy && in.legacy && !newer(in.ms, in.eventID, dig, mu.ms, mu.event, mu.digest))) {
				return nil
			}
			mu = mutation{ms: in.ms, event: in.eventID, digest: dig, content: string(payload), raw: in.m.Raw, legacy: in.legacy}
			if err := putMutationTx(ctx, tx, in.m.ChatJID, in.m.ID, mu); err != nil {
				return err
			}
			if exists {
				edited, deleted, err := applyMutation(&old, mu, true)
				if err != nil {
					return err
				}
				if err := saveMessageTx(ctx, tx, &old, edited, deleted); err != nil {
					return err
				}
			}
			outcome = IngestUpdated
		case "delete":
			if has && mu.deleted {
				return nil
			}
			mu.deleted = true
			mu.content = ""
			mu.raw = nil
			mu.legacy = false
			if err := putMutationTx(ctx, tx, in.m.ChatJID, in.m.ID, mu); err != nil {
				return err
			}
			if !exists {
				old = in.m
				old.Kind = "deleted"
			}
			if err := saveMessageTx(ctx, tx, &old, oldEdited, true); err != nil {
				return err
			}
			outcome = IngestUpdated
		case "reaction":
			changed, err := reactionTx(ctx, tx, in.m.ChatJID, in.m.ID, in.m.SenderJID, in.emoji, in.ms, in.eventID)
			if err != nil {
				return err
			}
			if changed {
				outcome = IngestUpdated
			}
		default:
			return errors.New("unsupported archive operation")
		}
		if outcome == IngestInserted || outcome == IngestUpdated {
			tel, err := telemetryTx(ctx, tx)
			if err != nil {
				return err
			}
			tel.LastSuccessfulIngestAt = time.Now().UTC().Format(time.RFC3339Nano)
			if err := saveTelemetryTx(ctx, tx, tel); err != nil {
				return err
			}
			if history && outcome == IngestInserted {
				if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_history_counts(chat_jid,history_inserted) VALUES(?,1) ON CONFLICT(chat_jid) DO UPDATE SET history_inserted=history_inserted+1`, in.m.ChatJID); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return IngestFailed, err
	}
	s.invalidateNames()
	s.eventsMu.RLock()
	eventService := s.events
	s.eventsMu.RUnlock()
	if eventService != nil && outcome == IngestInserted {
		eventService.Wake()
	}
	return outcome, nil
}
func reactionTx(ctx context.Context, tx *sql.Tx, chat, id, sender, emoji string, ms int64, event string) (bool, error) {
	var oldEmoji, oldEvent, oldDigest string
	var oldMS int64
	err := tx.QueryRowContext(ctx, `SELECT emoji,ms,event_id,digest FROM mcp_reaction_states WHERE chat_jid=? AND message_id=? AND sender_jid=?`, chat, id, sender).Scan(&oldEmoji, &oldMS, &oldEvent, &oldDigest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	dig := digestPayload([]byte(emoji))
	if err == nil {
		if ms == oldMS && event == oldEvent && emoji != "" && oldEmoji == "" {
			return false, nil
		}
		if !(ms == oldMS && event == oldEvent && emoji == "" && oldEmoji != "") && !newer(ms, event, dig, oldMS, oldEvent, oldDigest) {
			return false, nil
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_reaction_states(chat_jid,message_id,sender_jid,emoji,ms,event_id,digest) VALUES(?,?,?,?,?,?,?) ON CONFLICT(chat_jid,message_id,sender_jid) DO UPDATE SET emoji=excluded.emoji,ms=excluded.ms,event_id=excluded.event_id,digest=excluded.digest`, chat, id, sender, emoji, ms, event, dig); err != nil {
		return false, err
	}
	if emoji == "" {
		_, err = tx.ExecContext(ctx, `DELETE FROM mcp_reactions WHERE chat_jid=? AND message_id=? AND sender_jid=?`, chat, id, sender)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO mcp_reactions(chat_jid,message_id,sender_jid,emoji,timestamp) VALUES(?,?,?,?,?) ON CONFLICT(chat_jid,message_id,sender_jid) DO UPDATE SET emoji=excluded.emoji,timestamp=excluded.timestamp`, chat, id, sender, emoji, ms/1000)
	}
	return true, err
}
func (s *Store) UpsertMessage(ctx context.Context, m *StoredMessage) error {
	_, err := s.ingest(ctx, archiveInput{kind: "original", m: *m}, false)
	return err
}
func (s *Store) MarkDeleted(ctx context.Context, chat, id, sender string, fromMe bool, ts time.Time) error {
	_, err := s.ingest(ctx, archiveInput{kind: "delete", m: StoredMessage{ChatJID: chat, ID: id, SenderJID: sender, FromMe: fromMe, Timestamp: ts}}, false)
	return err
}

// ApplyEdit is retained for compatibility with callers lacking protocol source
// metadata. Such edits are explicitly legacy/unversioned, never receipt-ordered;
// WA uses the versioned ingestion path instead.
func (s *Store) ApplyEdit(ctx context.Context, chat, id, text string) error {
	_, err := s.ingest(ctx, archiveInput{kind: "edit", legacy: true, m: StoredMessage{ChatJID: chat, ID: id, Timestamp: time.Unix(0, 0), Content: Content{Kind: "text", Text: text}}}, false)
	return err
}
func (s *Store) SetReaction(ctx context.Context, chat, id, sender, emoji string, ts time.Time) error {
	_, err := s.ingest(ctx, archiveInput{kind: "reaction", m: StoredMessage{ChatJID: chat, ID: id, SenderJID: sender, Timestamp: ts}, ms: ts.UnixMilli(), emoji: emoji}, false)
	return err
}
func (s *Store) TouchChat(ctx context.Context, jid string, group bool, ts time.Time) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		canonical, err := canonicalTx(ctx, tx, jid)
		if err != nil {
			return err
		}
		return touchTx(ctx, tx, canonical, group, ts.Unix())
	})
}
func (s *Store) SetChatName(ctx context.Context, jid string, group bool, name string) error {
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		canonical, err := canonicalTx(ctx, tx, jid)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO mcp_chats(jid,is_group,name) VALUES(?,?,?) ON CONFLICT(jid) DO UPDATE SET name=CASE WHEN excluded.name<>'' THEN excluded.name ELSE name END`, canonical, group, name)
		return err
	})
	if err == nil {
		s.invalidateNames()
	}
	return err
}
func (s *Store) SetChatState(ctx context.Context, jid string, unread uint32, archived bool) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		canonical, err := canonicalTx(ctx, tx, jid)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mcp_chats SET unread_count=?,archived=? WHERE jid=?`, unread, archived, canonical)
		return err
	})
}
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO mcp_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
		return err
	})
}

// ---------------------------------------------------------------------------
// Name resolution

// Names returns jid -> display name, built from the address book and push names that
// whatsmeow keeps, mirrored across phone-number and LID addresses, overlaid with chat names.
func (s *Store) Names(ctx context.Context) map[string]string {
	s.namesMu.Lock()
	defer s.namesMu.Unlock()
	if s.names != nil && time.Now().Before(s.namesExpires) {
		return s.names
	}
	names := make(map[string]string)
	lidToPN := make(map[string]string)
	if rows, err := s.db.QueryContext(ctx, `SELECT lid, pn FROM mcp_aliases`); err == nil {
		for rows.Next() {
			var lid, pn string
			if rows.Scan(&lid, &pn) == nil {
				lidToPN[lid] = pn
			}
		}
		rows.Close()
	}
	if rows, err := s.db.QueryContext(ctx, `
		SELECT their_jid, COALESCE(NULLIF(full_name, ''), NULLIF(first_name, ''),
			NULLIF(business_name, ''), NULLIF(push_name, ''), '')
		FROM whatsmeow_contacts`); err == nil {
		for rows.Next() {
			var jid, name string
			if rows.Scan(&jid, &name) == nil && name != "" {
				names[jid] = name
			}
		}
		rows.Close()
	}
	for lid, pn := range lidToPN {
		if n, ok := names[lid]; ok && names[pn] == "" {
			names[pn] = n
		} else if n, ok := names[pn]; ok && names[lid] == "" {
			names[lid] = n
		}
	}
	// Chat names (group subjects, history-sync display names) win for chats that have one,
	// except that a saved address-book name wins for direct chats.
	if rows, err := s.db.QueryContext(ctx, `SELECT jid, name, is_group FROM mcp_chats WHERE name <> ''`); err == nil {
		for rows.Next() {
			var jid, name string
			var isGroup bool
			if rows.Scan(&jid, &name, &isGroup) == nil && (isGroup || names[jid] == "") {
				names[jid] = name
			}
		}
		rows.Close()
	}
	// Last resort: the WhatsApp profile name people sent their messages with.
	if rows, err := s.db.QueryContext(ctx, `SELECT sender_jid, push_name, MAX(timestamp) FROM mcp_messages
		WHERE push_name <> '' AND NOT from_me GROUP BY sender_jid`); err == nil {
		for rows.Next() {
			var jid, name string
			var ts int64 // SQLite takes push_name from the row with MAX(timestamp): the latest one
			if rows.Scan(&jid, &name, &ts) == nil && names[jid] == "" {
				names[jid] = name
			}
		}
		rows.Close()
	}
	s.names = names
	s.namesExpires = time.Now().Add(30 * time.Second)
	return names
}

func (s *Store) invalidateNames() {
	s.namesMu.Lock()
	s.names = nil
	s.namesMu.Unlock()
}

// ---------------------------------------------------------------------------
// Reads

type ChatRow struct {
	JID           string
	Name          string
	IsGroup       bool
	LastMessageAt time.Time
	UnreadCount   int
	Archived      bool
	MessageCount  int
}

func (s *Store) Chats(ctx context.Context) ([]*ChatRow, error) {
	names := s.Names(ctx)
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.jid, c.name, c.is_group, c.last_message_at, c.unread_count, c.archived,
			(SELECT COUNT(*) FROM mcp_messages m WHERE m.chat_jid = c.jid)
		FROM mcp_chats c ORDER BY c.last_message_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ChatRow
	for rows.Next() {
		c := &ChatRow{}
		var ts int64
		if err := rows.Scan(&c.JID, &c.Name, &c.IsGroup, &ts, &c.UnreadCount, &c.Archived, &c.MessageCount); err != nil {
			return nil, err
		}
		c.LastMessageAt = unixOrZero(ts)
		if n := names[c.JID]; n != "" {
			c.Name = n
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Chat(ctx context.Context, jid string) (*ChatRow, error) {
	chats, err := s.Chats(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range chats {
		if c.JID == jid {
			return c, nil
		}
	}
	return nil, sql.ErrNoRows
}

type MessageRow struct {
	ChatJID   string
	ID        string
	SenderJID string
	FromMe    bool
	Timestamp time.Time
	Kind      string
	Text      string
	PushName  string
	Mime      string
	FileName  string
	Size      int64
	Seconds   int
	QuotedID  string
	Edited    bool
	Deleted   bool
	HasMedia  bool

	QuotedText   string
	QuotedSender string
	Reactions    []Reaction
}

type Reaction struct {
	SenderJID string
	Emoji     string
}

type MessageFilter struct {
	ChatJID   string
	SenderJID string
	Query     string
	Kind      string
	After     time.Time
	Before    time.Time
	FromMe    *bool
	Limit     int
	Offset    int
	Oldest    bool // take the oldest matching rows instead of the newest
	Cursor    string
	BeforeKey *MessageAnchor
	AfterKey  *MessageAnchor
}

const messageColumns = `m.chat_jid, m.id, m.sender_jid, m.from_me, m.timestamp, m.kind, m.text, m.push_name,
	m.media_mime, m.media_filename, m.media_size, m.media_seconds, m.quoted_id, m.edited, m.deleted,
	m.raw IS NOT NULL, COALESCE(q.text, ''), COALESCE(q.sender_jid, '')`

// WC-PRELINK-01 C-004/C-005: snapshot-consistent total order and opaque keyset cursor.
type MessageAnchor struct {
	Timestamp int64  `json:"timestamp"`
	ChatJID   string `json:"chat_jid"`
	ID        string `json:"id"`
}
type messageCursor struct {
	Version    int           `json:"v"`
	Direction  string        `json:"direction"`
	Anchor     MessageAnchor `json:"anchor"`
	FilterHash string        `json:"filter_hash"`
	OrderEpoch int64         `json:"order_epoch"`
}

func decodeMessageCursor(raw string) (messageCursor, error) {
	var c messageCursor
	if len(raw) > 8192 {
		return c, errors.New("cursor is too long")
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return c, errors.New("malformed cursor encoding")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || len(fields) != 5 {
		return c, errors.New("cursor is missing required fields")
	}
	for _, key := range []string{"v", "direction", "anchor", "filter_hash", "order_epoch"} {
		if len(fields[key]) == 0 || string(fields[key]) == "null" {
			return c, errors.New("cursor is missing required fields")
		}
	}
	var anchorFields map[string]json.RawMessage
	if err := json.Unmarshal(fields["anchor"], &anchorFields); err != nil || len(anchorFields) != 3 {
		return c, errors.New("cursor anchor is missing required fields")
	}
	for _, key := range []string{"timestamp", "chat_jid", "id"} {
		if len(anchorFields[key]) == 0 || string(anchorFields[key]) == "null" {
			return c, errors.New("cursor anchor is missing required fields")
		}
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&c); err != nil {
		return c, errors.New("malformed cursor payload")
	}
	if err = dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return c, errors.New("malformed cursor trailing data")
	}
	hash, err := hex.DecodeString(c.FilterHash)
	if c.Version != 1 || (c.Direction != "older" && c.Direction != "newer") || c.Anchor.ChatJID == "" || c.Anchor.ID == "" || c.OrderEpoch < 0 || err != nil || len(hash) != sha256.Size {
		return c, errors.New("invalid cursor version or fields")
	}
	return c, nil
}
func cursorFilterHash(f MessageFilter) string {
	b, _ := json.Marshal(struct {
		Chat, Sender, Query, Kind, After, Before string
		FromMe                                   *bool
		Oldest                                   bool
	}{f.ChatJID, f.SenderJID, f.Query, f.Kind, f.After.UTC().Format(time.RFC3339Nano), f.Before.UTC().Format(time.RFC3339Nano), f.FromMe, f.Oldest})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (s *Store) MessagePage(ctx context.Context, f MessageFilter) ([]*MessageRow, bool, string, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, false, "", err
	}
	defer tx.Rollback()
	epoch, err := epochTx(ctx, tx)
	if err != nil {
		return nil, false, "", err
	}
	if f.ChatJID != "" {
		f.ChatJID, err = canonicalTx(ctx, tx, f.ChatJID)
		if err != nil {
			return nil, false, "", err
		}
	}
	if f.SenderJID != "" {
		f.SenderJID, err = canonicalTx(ctx, tx, f.SenderJID)
		if err != nil {
			return nil, false, "", err
		}
	}
	direction := "older"
	if f.Oldest {
		direction = "newer"
	}
	hash := cursorFilterHash(f)
	if f.Cursor != "" {
		if f.Offset != 0 {
			return nil, false, "", errors.New("offset cannot be combined with cursor")
		}
		c, err := decodeMessageCursor(f.Cursor)
		if err != nil {
			return nil, false, "", err
		}
		if c.OrderEpoch != epoch {
			return nil, false, "", errors.New("archive ordering changed; restart pagination")
		}
		if c.Direction != direction || c.FilterHash != hash {
			return nil, false, "", errors.New("cursor does not match this query scope")
		}
		if f.Oldest {
			f.AfterKey = &c.Anchor
		} else {
			f.BeforeKey = &c.Anchor
		}
	}
	msgs, more, err := s.messagesTx(ctx, tx, f)
	if err != nil {
		return nil, false, "", err
	}
	next := ""
	if more && len(msgs) > 0 {
		anchor := msgs[0]
		if f.Oldest {
			anchor = msgs[len(msgs)-1]
		}
		b, err := json.Marshal(messageCursor{1, direction, MessageAnchor{anchor.Timestamp.Unix(), anchor.ChatJID, anchor.ID}, hash, epoch})
		if err != nil {
			return nil, false, "", err
		}
		next = base64.RawURLEncoding.EncodeToString(b)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, "", err
	}
	return msgs, more, next, nil
}

// Messages preserves the archive's existing convenience API.
func (s *Store) Messages(ctx context.Context, f MessageFilter) ([]*MessageRow, bool, error) {
	m, more, _, err := s.MessagePage(ctx, f)
	return m, more, err
}
func (s *Store) messagesTx(ctx context.Context, tx *sql.Tx, f MessageFilter) ([]*MessageRow, bool, error) {
	var where []string
	var args []any
	if f.ChatJID != "" {
		where = append(where, "m.chat_jid = ?")
		args = append(args, f.ChatJID)
	} else {
		where = append(where, "m.chat_jid <> 'status@broadcast'")
	}
	if f.SenderJID != "" {
		where = append(where, "m.sender_jid = ?")
		args = append(args, f.SenderJID)
	}
	if f.Query != "" {
		where = append(where, `(m.text LIKE ? ESCAPE '\' OR m.media_filename LIKE ? ESCAPE '\')`)
		pat := "%" + likeEscape(f.Query) + "%"
		args = append(args, pat, pat)
	}
	if f.Kind != "" {
		where = append(where, "m.kind = ?")
		args = append(args, f.Kind)
	}
	if !f.After.IsZero() {
		where = append(where, "m.timestamp > ?")
		args = append(args, f.After.Unix())
	}
	if !f.Before.IsZero() {
		where = append(where, "m.timestamp < ?")
		args = append(args, f.Before.Unix())
	}
	if f.FromMe != nil {
		where = append(where, "m.from_me = ?")
		args = append(args, *f.FromMe)
	}
	for _, boundary := range []struct {
		key *MessageAnchor
		op  string
	}{{f.BeforeKey, "<"}, {f.AfterKey, ">"}} {
		if boundary.key != nil {
			where = append(where, "(m.timestamp,m.chat_jid COLLATE BINARY,m.id COLLATE BINARY) "+boundary.op+" (?,?,?)")
			args = append(args, boundary.key.Timestamp, boundary.key.ChatJID, boundary.key.ID)
		}
	}
	order := "DESC"
	if f.Oldest {
		order = "ASC"
	}
	q := `SELECT ` + messageColumns + ` FROM mcp_messages m LEFT JOIN mcp_messages q ON q.chat_jid=m.chat_jid AND q.id=m.quoted_id AND m.quoted_id<>'' WHERE ` + strings.Join(where, " AND ") + ` ORDER BY m.timestamp ` + order + `,m.chat_jid COLLATE BINARY ` + order + `,m.id COLLATE BINARY ` + order + ` LIMIT ? OFFSET ?`
	args = append(args, f.Limit+1, f.Offset)
	msgs, err := queryMessagesTx(ctx, tx, q, args...)
	if err != nil {
		return nil, false, err
	}
	more := len(msgs) > f.Limit
	if more {
		msgs = msgs[:f.Limit]
	}
	if !f.Oldest {
		reverse(msgs)
	}
	return msgs, more, attachReactionsTx(ctx, tx, msgs)
}
func readMessageTx(ctx context.Context, tx *sql.Tx, chat, id string) (*MessageRow, error) {
	msgs, err := queryMessagesTx(ctx, tx, `SELECT `+messageColumns+` FROM mcp_messages m LEFT JOIN mcp_messages q ON q.chat_jid=m.chat_jid AND q.id=m.quoted_id AND m.quoted_id<>'' WHERE m.chat_jid=? AND m.id=?`, chat, id)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, sql.ErrNoRows
	}
	if err := attachReactionsTx(ctx, tx, msgs); err != nil {
		return nil, err
	}
	return msgs[0], nil
}
func findMessageTx(ctx context.Context, tx *sql.Tx, chat, id string) (*MessageRow, error) {
	if chat != "" {
		canonical, err := canonicalTx(ctx, tx, chat)
		if err != nil {
			return nil, err
		}
		return readMessageTx(ctx, tx, canonical, id)
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT chat_jid FROM mcp_messages WHERE id=? ORDER BY chat_jid COLLATE BINARY LIMIT 2`, id)
	if err != nil {
		return nil, err
	}
	var chats []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			rows.Close()
			return nil, err
		}
		chats = append(chats, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(chats) == 0 {
		return nil, sql.ErrNoRows
	}
	if len(chats) > 1 {
		return nil, fmt.Errorf("message %s is ambiguous; pass chat as one of these JIDs: %s", id, strings.Join(chats, ", "))
	}
	return readMessageTx(ctx, tx, chats[0], id)
}
func (s *Store) Message(ctx context.Context, chat, id string) (*MessageRow, error) {
	return s.lookupMessage(ctx, chat, id)
}
func (s *Store) FindMessage(ctx context.Context, id string) (*MessageRow, error) {
	return s.lookupMessage(ctx, "", id)
}
func (s *Store) lookupMessage(ctx context.Context, chat, id string) (*MessageRow, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	m, err := findMessageTx(ctx, tx, chat, id)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return m, nil
}
func (s *Store) MessageContext(ctx context.Context, chat, id string, before, after int) (*MessageRow, []*MessageRow, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	target, err := findMessageTx(ctx, tx, chat, id)
	if err != nil {
		return nil, nil, err
	}
	key := &MessageAnchor{target.Timestamp.Unix(), target.ChatJID, target.ID}
	prev, _, err := s.messagesTx(ctx, tx, MessageFilter{ChatJID: target.ChatJID, BeforeKey: key, Limit: before})
	if err != nil {
		return nil, nil, err
	}
	next, _, err := s.messagesTx(ctx, tx, MessageFilter{ChatJID: target.ChatJID, AfterKey: key, Limit: after, Oldest: true})
	if err != nil {
		return nil, nil, err
	}
	all := append(append(prev, target), next...)
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return target, all, nil
}

func (s *Store) RawMessage(ctx context.Context, chat, id string) ([]byte, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT raw FROM mcp_messages WHERE chat_jid = ? AND id = ?`, chat, id).Scan(&raw)
	return raw, err
}

// OldestMessage returns the oldest stored message of a chat, the anchor for on-demand history requests.
func (s *Store) OldestMessage(ctx context.Context, chat string) (*MessageRow, error) {
	msgs, _, err := s.Messages(ctx, MessageFilter{ChatJID: chat, Limit: 1, Oldest: true})
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, sql.ErrNoRows
	}
	return msgs[0], nil
}

func (s *Store) CountMessages(ctx context.Context, chat string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mcp_messages WHERE chat_jid = ?`, chat).Scan(&n)
	return n, err
}

type Stats struct {
	Chats, Messages int
	Oldest, Newest  time.Time
	LastHistorySync string
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	var oldest, newest sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM mcp_chats), COUNT(*), MIN(timestamp), MAX(timestamp)
		FROM mcp_messages`).Scan(&st.Chats, &st.Messages, &oldest, &newest)
	if err != nil {
		return st, err
	}
	st.Oldest, st.Newest = unixOrZero(oldest.Int64), unixOrZero(newest.Int64)
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM mcp_meta WHERE key = 'last_history_sync'`).Scan(&st.LastHistorySync)
	return st, nil
}

func queryMessagesTx(ctx context.Context, reader *sql.Tx, q string, args ...any) ([]*MessageRow, error) {
	rows, err := reader.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*MessageRow
	for rows.Next() {
		m := &MessageRow{}
		var ts int64
		if err := rows.Scan(&m.ChatJID, &m.ID, &m.SenderJID, &m.FromMe, &ts, &m.Kind, &m.Text, &m.PushName,
			&m.Mime, &m.FileName, &m.Size, &m.Seconds, &m.QuotedID, &m.Edited, &m.Deleted, &m.HasMedia,
			&m.QuotedText, &m.QuotedSender); err != nil {
			return nil, err
		}
		m.Timestamp = time.Unix(ts, 0)
		out = append(out, m)
	}
	return out, rows.Err()
}

func attachReactionsTx(ctx context.Context, reader *sql.Tx, msgs []*MessageRow) error {
	if len(msgs) == 0 {
		return nil
	}
	byKey := make(map[[2]string]*MessageRow, len(msgs))
	var conds []string
	var args []any
	for _, m := range msgs {
		byKey[[2]string{m.ChatJID, m.ID}] = m
		conds = append(conds, "(chat_jid = ? AND message_id = ?)")
		args = append(args, m.ChatJID, m.ID)
	}
	// Chunk to stay well below SQLite's bound-parameter limit.
	for len(conds) > 0 {
		n := min(len(conds), 400)
		rows, err := reader.QueryContext(ctx, `SELECT chat_jid, message_id, sender_jid, emoji FROM mcp_reactions WHERE `+
			strings.Join(conds[:n], " OR ")+` ORDER BY timestamp`, args[:2*n]...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var chat, id string
			var r Reaction
			if err := rows.Scan(&chat, &id, &r.SenderJID, &r.Emoji); err != nil {
				rows.Close()
				return err
			}
			if m := byKey[[2]string{chat, id}]; m != nil {
				m.Reactions = append(m.Reactions, r)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		conds, args = conds[n:], args[2*n:]
	}
	return nil
}

var errNotInitialized = errors.New("message archive not initialized yet: run `whatsapp-mcp login` first")

// checkInitialized verifies the schema exists (relevant for read-only instances).
func (s *Store) checkInitialized(ctx context.Context) error {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('mcp_messages', 'whatsmeow_contacts')`).Scan(&n)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	if n < 2 {
		return errNotInitialized
	}
	var version string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM mcp_meta WHERE key='prelink_schema_version'`).Scan(&version); err != nil || version != "1" {
		return errors.New("archive upgrade required: start the connection-owning server before opening an archive reader")
	}
	return nil
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func unixOrZero(ts int64) time.Time {
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}

func reverse[T any](s []T) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// IngestTelemetry describes observed chunks; complete is processing success, never
// a claim that the phone supplied all history. Missing summary means unknown.
type IngestTelemetry struct {
	SchemaVersion            int    `json:"schema_version"`
	LastHistoryReceivedAt    string `json:"last_history_received_at,omitempty"`
	LastHistoryCompletedAt   string `json:"last_history_completed_at,omitempty"`
	LastSuccessfulIngestAt   string `json:"last_successful_ingest_at,omitempty"`
	LastHistorySyncType      string `json:"last_history_sync_type,omitempty"`
	LastHistoryStatus        string `json:"last_history_status,omitempty"`
	HistoryReceived          int64  `json:"history_received"`
	HistoryInserted          int64  `json:"history_inserted"`
	HistoryUpdated           int64  `json:"history_updated"`
	HistoryDuplicate         int64  `json:"history_duplicate"`
	HistoryIgnored           int64  `json:"history_ignored"`
	HistoryFailed            int64  `json:"history_failed"`
	HistoryParseFailed       int64  `json:"history_parse_failed"`
	HistoryMetadataFailed    int64  `json:"history_metadata_failed"`
	LastErrorCode            string `json:"last_error_code,omitempty"`
	LastErrorAt              string `json:"last_error_at,omitempty"`
	LastGroupDiscoveryAt     string `json:"last_group_discovery_at,omitempty"`
	LastGroupDiscoveryStatus string `json:"last_group_discovery_status,omitempty"`
	GroupDiscoveryFailed     int64  `json:"group_discovery_failed"`
}

const telemetryKey = "prelink_ingest_telemetry_v1"

func telemetryTx(ctx context.Context, tx *sql.Tx) (IngestTelemetry, error) {
	var t IngestTelemetry
	var raw string
	err := tx.QueryRowContext(ctx, `SELECT value FROM mcp_meta WHERE key=?`, telemetryKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		t.SchemaVersion = 1
		return t, nil
	}
	if err != nil {
		return t, err
	}
	err = json.Unmarshal([]byte(raw), &t)
	if err == nil && t.SchemaVersion != 1 {
		err = errors.New("unsupported ingest telemetry version")
	}
	return t, err
}
func saveTelemetryTx(ctx context.Context, tx *sql.Tx, t IngestTelemetry) error {
	t.SchemaVersion = 1
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mcp_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, telemetryKey, string(b))
	return err
}
func (s *Store) IngestTelemetry(ctx context.Context) (IngestTelemetry, error) {
	var t IngestTelemetry
	if s.telemetryUnhealthy.Load() {
		return t, errors.New("owner ingest diagnostics could not be persisted")
	}
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM mcp_meta WHERE key=?`, telemetryKey).Scan(&raw)
	if err != nil {
		return t, err
	}
	err = json.Unmarshal([]byte(raw), &t)
	if err == nil && t.SchemaVersion != 1 {
		err = errors.New("unsupported ingest telemetry version")
	}
	return t, err
}
func (s *Store) recordFailure(ctx context.Context, code string) error {
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		t, err := telemetryTx(ctx, tx)
		if err != nil {
			return err
		}
		t.LastErrorCode = code
		t.LastErrorAt = time.Now().UTC().Format(time.RFC3339Nano)
		return saveTelemetryTx(ctx, tx, t)
	})
	if err != nil {
		s.telemetryUnhealthy.Store(true)
	}
	return err
}
func (s *Store) historySummary(ctx context.Context, chunk IngestTelemetry, finished bool) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		t, err := telemetryTx(ctx, tx)
		if err != nil {
			return err
		}
		t.LastHistoryReceivedAt = chunk.LastHistoryReceivedAt
		t.LastHistoryCompletedAt = chunk.LastHistoryCompletedAt
		t.LastHistorySyncType = chunk.LastHistorySyncType
		t.LastHistoryStatus = chunk.LastHistoryStatus
		t.HistoryReceived = chunk.HistoryReceived
		t.HistoryInserted = chunk.HistoryInserted
		t.HistoryUpdated = chunk.HistoryUpdated
		t.HistoryDuplicate = chunk.HistoryDuplicate
		t.HistoryIgnored = chunk.HistoryIgnored
		t.HistoryFailed = chunk.HistoryFailed
		t.HistoryParseFailed = chunk.HistoryParseFailed
		t.HistoryMetadataFailed = chunk.HistoryMetadataFailed
		if chunk.LastErrorCode != "" {
			t.LastErrorCode = chunk.LastErrorCode
			t.LastErrorAt = chunk.LastHistoryCompletedAt
		}
		if err := saveTelemetryTx(ctx, tx, t); err != nil {
			return err
		}
		if finished {
			_, err = tx.ExecContext(ctx, `INSERT INTO mcp_meta(key,value) VALUES('last_history_sync',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, chunk.LastHistoryCompletedAt)
		}
		return err
	})
}
func (s *Store) groupSummary(ctx context.Context, status string, failed int64) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		t, err := telemetryTx(ctx, tx)
		if err != nil {
			return err
		}
		t.LastGroupDiscoveryAt = time.Now().UTC().Format(time.RFC3339Nano)
		t.LastGroupDiscoveryStatus = status
		t.GroupDiscoveryFailed += failed
		if failed > 0 {
			t.LastErrorCode = "group_discovery_failed"
			t.LastErrorAt = t.LastGroupDiscoveryAt
		}
		return saveTelemetryTx(ctx, tx, t)
	})
}
func epochTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT value FROM mcp_meta WHERE key='order_epoch'`).Scan(&raw); err != nil {
		return 0, err
	}
	return strconv.ParseInt(raw, 10, 64)
}
func bumpEpochTx(ctx context.Context, tx *sql.Tx) error {
	v, err := epochTx(ctx, tx)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE mcp_meta SET value=? WHERE key='order_epoch'`, strconv.FormatInt(v+1, 10))
	return err
}
func (s *Store) OrderEpoch(ctx context.Context) (int64, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM mcp_meta WHERE key='order_epoch'`).Scan(&raw)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(raw, 10, 64)
}
func (s *Store) CanonicalJID(ctx context.Context, jid types.JID) (types.JID, error) {
	jid = jid.ToNonAD()
	var pn string
	err := s.db.QueryRowContext(ctx, `SELECT pn FROM mcp_aliases WHERE lid=?`, jid.String()).Scan(&pn)
	if errors.Is(err, sql.ErrNoRows) {
		return jid, nil
	}
	if err != nil {
		return types.EmptyJID, err
	}
	return types.ParseJID(pn)
}
func (s *Store) OwnJID(ctx context.Context) (types.JID, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT jid FROM whatsmeow_device LIMIT 1`).Scan(&raw)
	if err != nil {
		return types.EmptyJID, err
	}
	jid, err := types.ParseJID(raw)
	return jid.ToNonAD(), err
}

type HistorySnapshot struct {
	HistoryInserted int64 `json:"history_inserted"`
	OrderEpoch      int64 `json:"order_epoch"`
}

func (s *Store) HistoryProgress(ctx context.Context, chat string) (HistorySnapshot, error) {
	var out HistorySnapshot
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	chat, err = canonicalTx(ctx, tx, chat)
	if err != nil {
		return out, err
	}
	out.OrderEpoch, err = epochTx(ctx, tx)
	if err != nil {
		return out, err
	}
	err = tx.QueryRowContext(ctx, `SELECT history_inserted FROM mcp_history_counts WHERE chat_jid=?`, chat).Scan(&out.HistoryInserted)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}

func chooseMutation(a mutation, hasA bool, b mutation, hasB bool) (mutation, bool) {
	if !hasA {
		return b, hasB
	}
	if !hasB {
		return a, true
	}
	if a.deleted || b.deleted {
		return mutation{deleted: true}, true
	}
	if a.legacy != b.legacy {
		if a.legacy {
			return b, true
		}
		return a, true
	}
	if newer(b.ms, b.event, b.digest, a.ms, a.event, a.digest) {
		return b, true
	}
	if a.legacy && b.content > a.content {
		return b, true
	}
	return a, true
}
func originalTx(ctx context.Context, tx *sql.Tx, chat, id string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mcp_originals WHERE chat_jid=? AND id=?`, chat, id).Scan(&n)
	return n > 0, err
}

// AcceptAlias only trusts protocol/store evidence supplied by WA. Every archive
// reference moves in one transaction; the upstream LID store is independently
// durable, so a failed pair can and must be retried even if it already exists there.
func (s *Store) AcceptAlias(ctx context.Context, lid, pn types.JID) error {
	lid = lid.ToNonAD()
	pn = pn.ToNonAD()
	if lid.Server != types.HiddenUserServer || pn.Server != types.DefaultUserServer || lid.User == "" || pn.User == "" {
		return errors.New("invalid verified alias pair")
	}
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		var accepted string
		err := tx.QueryRowContext(ctx, `SELECT pn FROM mcp_aliases WHERE lid=?`, lid.String()).Scan(&accepted)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			if accepted != pn.String() {
				return errors.New("identity_conflict: accepted LID mapping differs")
			}
			return nil
		}
		if err := s.mergeAliasTx(ctx, tx, lid.String(), pn.String()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_aliases(lid,pn) VALUES(?,?)`, lid.String(), pn.String()); err != nil {
			return err
		}
		return bumpEpochTx(ctx, tx)
	})
	if err != nil {
		_ = s.recordFailure(ctx, "identity_reconciliation_failed")
		return fmt.Errorf("archive identity reconciliation: %w", err)
	}
	s.invalidateNames()
	return nil
}
func (s *Store) mergeAliasTx(ctx context.Context, tx *sql.Tx, lid, pn string) error {
	// Merge pending and visible mutation state first, using the same reducer as ingest.
	rows, err := tx.QueryContext(ctx, `SELECT id FROM mcp_message_mutations WHERE chat_jid=? UNION SELECT id FROM mcp_messages WHERE chat_jid=?`, lid, lid)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		src, se, sd, sexists, err := loadMessageTx(ctx, tx, lid, id)
		if err != nil {
			return err
		}
		dst, de, dd, dexists, err := loadMessageTx(ctx, tx, pn, id)
		if err != nil {
			return err
		}
		sm, sh, err := mutationTx(ctx, tx, lid, id)
		if err != nil {
			return err
		}
		dm, dh, err := mutationTx(ctx, tx, pn, id)
		if err != nil {
			return err
		}
		mu, has := chooseMutation(dm, dh, sm, sh)
		so, err := originalTx(ctx, tx, lid, id)
		if err != nil {
			return err
		}
		do, err := originalTx(ctx, tx, pn, id)
		if err != nil {
			return err
		}
		if src.SenderJID == lid {
			src.SenderJID = pn
		}
		if dst.SenderJID == lid {
			dst.SenderJID = pn
		}
		if so && do && (src.SenderJID != dst.SenderJID || src.FromMe != dst.FromMe || !src.Timestamp.Equal(dst.Timestamp)) {
			return errors.New("identity_conflict: colliding immutable message identity")
		}
		if so && do {
			sourceHash, targetHash := forwardHashOf(src.Raw), forwardHashOf(dst.Raw)
			if sourceHash != "" && targetHash != "" && (sourceHash != targetHash || !sameForwardContent(src, dst)) {
				if err := putForwardObservationTx(ctx, tx, pn, id, ""); err != nil {
					return err
				}
			}
		}
		if has {
			if err := putMutationTx(ctx, tx, pn, id, mu); err != nil {
				return err
			}
		}
		if sexists || dexists {
			m := dst
			edited, deleted := de, dd
			if !dexists || (!do && so) {
				m = src
				edited, deleted = se, sd
			}
			m.ChatJID = pn
			if has {
				var err error
				edited, deleted, err = applyMutation(&m, mu, true)
				if err != nil {
					return err
				}
			}
			deleted = deleted || sd || dd
			if err := saveMessageTx(ctx, tx, &m, edited, deleted); err != nil {
				return err
			}
		}
		if so && !do {
			if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_originals(chat_jid,id) VALUES(?,?)`, pn, id); err != nil {
				return err
			}
		}
	}
	// Sender identities in groups and every other conversation move as well.
	if _, err := tx.ExecContext(ctx, `UPDATE mcp_messages SET sender_jid=? WHERE sender_jid=?`, pn, lid); err != nil {
		return err
	}
	// Reactions can exist before their original, and empty emoji states retain
	// removals so replay cannot resurrect a reaction after identity reconciliation.
	rr, err := tx.QueryContext(ctx, `SELECT chat_jid,message_id,sender_jid,emoji,ms,event_id FROM mcp_reaction_states WHERE chat_jid=? OR sender_jid=?`, lid, lid)
	if err != nil {
		return err
	}
	type reactionState struct {
		chat, id, sender, emoji string
		ms                      int64
		event                   string
	}
	var reactions []reactionState
	for rr.Next() {
		var x reactionState
		if err := rr.Scan(&x.chat, &x.id, &x.sender, &x.emoji, &x.ms, &x.event); err != nil {
			rr.Close()
			return err
		}
		reactions = append(reactions, x)
	}
	err = rr.Err()
	rr.Close()
	if err != nil {
		return err
	}
	for _, x := range reactions {
		chat, sender := x.chat, x.sender
		if chat == lid {
			chat = pn
		}
		if sender == lid {
			sender = pn
		}
		if _, err := reactionTx(ctx, tx, chat, x.id, sender, x.emoji, x.ms, x.event); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_reaction_states WHERE chat_jid=? OR sender_jid=?`, lid, lid); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_reactions WHERE chat_jid=? OR sender_jid=?`, lid, lid); err != nil {
		return err
	}
	// Chat metadata is a reduction, never a sum of duplicate unread snapshots.
	if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_chats(jid,name,is_group,last_message_at,unread_count,archived) SELECT ?,name,is_group,last_message_at,unread_count,archived FROM mcp_chats WHERE jid=? ON CONFLICT(jid) DO UPDATE SET name=CASE WHEN mcp_chats.name='' THEN excluded.name ELSE mcp_chats.name END,last_message_at=MAX(mcp_chats.last_message_at,excluded.last_message_at)`, pn, lid); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_history_counts(chat_jid,history_inserted) SELECT ?,history_inserted FROM mcp_history_counts WHERE chat_jid=? ON CONFLICT(chat_jid) DO UPDATE SET history_inserted=mcp_history_counts.history_inserted+excluded.history_inserted`, pn, lid); err != nil {
		return err
	}
	for _, table := range []string{"mcp_originals", "mcp_message_mutations", "mcp_messages", "mcp_history_counts"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE chat_jid=?`, lid); err != nil {
			return err
		}
	}
	if err := mergeForwardObservationsTx(ctx, tx, lid, pn); err != nil {
		return err
	}
	if err := reconcileEventAliasTx(ctx, tx, lid, pn); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM mcp_chats WHERE jid=?`, lid)
	return err
}
