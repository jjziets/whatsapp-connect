package main

// TRACEWEAVER: C-007 / TRACE-OWNERMSG-007 / VER-OWNERMSG-007.
import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const outboxSchema = `
CREATE TABLE IF NOT EXISTS mcp_outbox (
 request_id TEXT PRIMARY KEY,
 account_jid TEXT NOT NULL,
 payload TEXT NOT NULL,
 message_id TEXT NOT NULL UNIQUE,
 state TEXT NOT NULL CHECK(state IN ('dispatching','server_acknowledged','rejected','outcome_unknown')),
 outcome TEXT NOT NULL DEFAULT '',
 server_timestamp TEXT NOT NULL DEFAULT '',
 wire_chat TEXT NOT NULL DEFAULT '',
 wire_sender TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
INSERT OR IGNORE INTO mcp_meta(key,value) VALUES('outbox_schema_version','1');
`

// Reservation is committed before the network edge; transaction may replay SQL.
// Immutable request tombstones are never removed on expiry or restart.
func (s *Store) reserveMessage(ctx context.Context, p SendTextArgs, messageID string) (SendStatus, bool, error) {
	b, _ := json.Marshal(p)
	return s.reserveOutboxMessage(ctx, p.RequestID, p.AccountJID, string(b), messageID, func(tx *sql.Tx) error {
		if p.ReplyTo == nil {
			return nil
		}
		q := p.ReplyTo
		var text, author, kind string
		var fromMe, deleted, edited bool
		if err := tx.QueryRowContext(ctx, `SELECT text,sender_jid,from_me,kind,deleted,edited FROM mcp_messages WHERE chat_jid=? AND id=?`, p.ChatJID, q.MessageID).Scan(&text, &author, &fromMe, &kind, &deleted, &edited); err != nil {
			return err
		}
		if fromMe {
			author = p.AccountJID
		}
		if deleted || edited || kind != "text" || text != q.Text || author != q.AuthorJID || q.ChatJID != p.ChatJID {
			return errors.New("quote changed before reservation")
		}
		return nil
	})
}

func (s *Store) reserveOutboxMessage(ctx context.Context, requestID, accountJID, rawPayload, messageID string, check func(*sql.Tx) error) (SendStatus, bool, error) {
	won := false
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		won = false
		now := time.Now().UTC().Format(time.RFC3339Nano)
		res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO mcp_outbox(request_id,account_jid,payload,message_id,state,created_at,updated_at) VALUES(?,?,?,?,'dispatching',?,?)`, requestID, accountJID, rawPayload, messageID, now, now)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		won = n == 1
		var payload, account string
		if err := tx.QueryRowContext(ctx, `SELECT payload,account_jid FROM mcp_outbox WHERE request_id=?`, requestID).Scan(&payload, &account); err != nil {
			return err
		}
		if payload != rawPayload || account != accountJID {
			return errors.New("request_id conflicts with its immutable payload")
		}
		if won {
			return check(tx)
		}
		return nil
	})
	if err != nil {
		return SendStatus{}, false, errors.New("message reservation failed; nothing dispatched by this call")
	}
	out, err := s.sendStatus(ctx, requestID)
	return out, won, err
}

func (s *Store) settleMessage(ctx context.Context, out SendStatus) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE mcp_outbox SET state=?,outcome=?,server_timestamp=?,wire_chat=?,wire_sender=?,updated_at=? WHERE request_id=? AND state='dispatching'`, out.State, out.Outcome, out.ServerTimestamp, out.WireChat, out.WireSender, time.Now().UTC().Format(time.RFC3339Nano), out.RequestID)
		return err
	})
}

// Called only while acquiring the actual exclusive owner, never by MCP server
// construction, reader opens or additional sessions on a currently active owner.
func (s *Store) recoverMessageOutbox(ctx context.Context) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE mcp_outbox SET state='outcome_unknown',outcome='owner_restarted_after_reservation',updated_at=? WHERE state='dispatching'`, time.Now().UTC().Format(time.RFC3339Nano))
		return err
	})
}

func (s *Store) sendStatus(ctx context.Context, id string) (SendStatus, error) {
	out := SendStatus{RequestID: id, State: "unknown"}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='mcp_outbox'`).Scan(&exists); err != nil {
		return out, errors.New("send status unavailable")
	}
	if exists == 0 {
		return out, nil
	}
	var payload string
	err := s.db.QueryRowContext(ctx, `SELECT payload,state,message_id,outcome,server_timestamp,wire_chat,wire_sender FROM mcp_outbox WHERE request_id=?`, id).Scan(&payload, &out.State, &out.MessageID, &out.Outcome, &out.ServerTimestamp, &out.WireChat, &out.WireSender)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, errors.New("send status unavailable")
	}
	var tag struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal([]byte(payload), &tag) != nil {
		return SendStatus{}, errors.New("send status unavailable")
	}
	out.rawPayload = payload
	switch tag.Operation {
	case "":
		out.Payload = &SendTextArgs{}
		if json.Unmarshal([]byte(payload), out.Payload) != nil {
			return SendStatus{}, errors.New("send status unavailable")
		}
	case forwardMediaOperation:
		out.MediaPayload = &ForwardMediaArgs{}
		if json.Unmarshal([]byte(payload), out.MediaPayload) != nil {
			return SendStatus{}, errors.New("send status unavailable")
		}
	default:
		return SendStatus{}, errors.New("send status unavailable")
	}
	return out, nil
}

func (s *Store) existingOutboxMessage(ctx context.Context, requestID, rawPayload string) (SendStatus, error) {
	out, err := s.sendStatus(ctx, requestID)
	if err != nil {
		return out, err
	}
	if out.State != "unknown" && out.rawPayload != rawPayload {
		return SendStatus{}, errors.New("request_id conflicts with its immutable payload")
	}
	return out, nil
}
