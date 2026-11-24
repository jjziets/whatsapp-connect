//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"github.com/hansen/whatsapp-mcp/internal/securestore"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
)

// Retained encrypted reservation plus actual exclusive-owner reopen; replay must
// precede expiry/quote checks, and an orphan is never automatically dispatched.
func TestOwnerMessageEncryptedRestartAndExpiredReplay(t *testing.T) {
	a, f := messageApp(t)
	ctx := context.Background()
	p := previewMessage(t, a, "restart-reserved", alice.String(), "A1")
	p.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	p.PayloadDigest = messageDigest(p)
	s, won, e := a.store.reserveMessage(ctx, p, "SYNTHETIC-ORPHAN-ID")
	if e != nil || !won || s.State != "dispatching" {
		t.Fatalf("reserve %+v %v %v", s, won, e)
	}
	// Creating an MCP server for the same owner must not recover active calls.
	regressionClient(t, a)
	if s, _ = a.store.sendStatus(ctx, p.RequestID); s.State != "dispatching" {
		t.Fatalf("session creation recovered active request: %+v", s)
	}
	if _, e = a.store.db.Exec(`UPDATE mcp_messages SET text='quote changed after reservation' WHERE chat_jid=? AND id='A1'`, alice.String()); e != nil {
		t.Fatal(e)
	}
	if s = sendMessage(t, a, p); s.State != "dispatching" {
		t.Fatal(s)
	}
	dir := a.wa.dataDir
	if e = a.wa.drainAndClose(); e != nil {
		t.Fatal(e)
	}
	b, cleanup, e := openForServeWith(ctx, dir, zerolog.Nop(), ServeDependencies{ArchiveKeys: evArchiveKeys{}, Connect: func(context.Context, *WA) error { return nil }})
	if e != nil {
		t.Fatal(e)
	}
	defer cleanup()
	b.messageWrites = true
	b.wa.messageTransport = f
	if s = sendMessage(t, b, p); s.State != "outcome_unknown" || s.MessageID != "SYNTHETIC-ORPHAN-ID" {
		t.Fatalf("orphan recovery=%+v", s)
	}
	if f.calls.Load() != 0 {
		t.Fatal("reopened/expired request resent")
	}
	conflict := p
	conflict.AccountJID = bob.String()
	if _, _, e = b.sendText(ctx, nil, conflict); e == nil {
		t.Fatal("cross-account request accepted")
	}
}

// SQLite triggers exercise actual commit and archive errors, rather than mocking
// Store methods or inventing SDK failures that imply safe retry.
func TestOwnerMessageStorageFailuresNeverResend(t *testing.T) {
	for _, stage := range []string{"reservation-commit", "settlement-commit", "archive-write"} {
		t.Run(stage, func(t *testing.T) {
			a, f := messageApp(t)
			ctx := context.Background()
			p := previewMessage(t, a, "storage-failure", alice.String(), "")
			var ddl string
			switch stage {
			case "reservation-commit":
				ddl = `CREATE TABLE synthetic_parent(id INTEGER PRIMARY KEY); CREATE TABLE synthetic_fk(id INTEGER REFERENCES synthetic_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER synthetic_failure AFTER INSERT ON mcp_outbox BEGIN INSERT INTO synthetic_fk VALUES(1); END;`
			case "settlement-commit":
				ddl = `CREATE TABLE synthetic_parent(id INTEGER PRIMARY KEY); CREATE TABLE synthetic_fk(id INTEGER REFERENCES synthetic_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER synthetic_failure AFTER UPDATE ON mcp_outbox BEGIN INSERT INTO synthetic_fk VALUES(1); END;`
			case "archive-write":
				ddl = `CREATE TRIGGER synthetic_failure BEFORE INSERT ON mcp_messages WHEN NEW.from_me=1 BEGIN SELECT RAISE(ABORT,'synthetic archive unavailable'); END;`
			}
			if _, e := a.store.db.ExecContext(ctx, ddl); e != nil {
				t.Fatal(e)
			}
			_, s, e := a.sendText(ctx, nil, p)
			if stage == "reservation-commit" {
				if e == nil || f.calls.Load() != 0 {
					t.Fatalf("uncommitted reservation sent: %+v %v %d", s, e, f.calls.Load())
				}
				return
			}
			if e != nil || s.State != "outcome_unknown" || f.calls.Load() != 1 {
				t.Fatalf("false certain outcome %+v %v %d", s, e, f.calls.Load())
			}
			if _, e = a.store.db.ExecContext(ctx, `DROP TRIGGER synthetic_failure`); e != nil {
				t.Fatal(e)
			}
			sendMessage(t, a, p)
			if f.calls.Load() != 1 {
				t.Fatal("storage failure retried")
			}
			// An actual later echo is still accepted by the existing normalized producer.
			evt := textMsg(alice, a.wa.ownJID(), s.MessageID, time.Now(), p.Text)
			evt.Info.IsFromMe = true
			if e = a.wa.ingestMessage(ctx, evt); e != nil {
				t.Fatal(e)
			}
			m, e := a.store.Message(ctx, alice.String(), s.MessageID)
			if e != nil || !m.FromMe || m.Text != p.Text {
				t.Fatalf("later echo lost: %+v %v", m, e)
			}
		})
	}
}

func TestOwnerMessageReaderMissingOutboxPureStatus(t *testing.T) {
	a, _ := messageApp(t)
	if _, e := a.store.db.Exec(`DROP TABLE mcp_outbox`); e != nil {
		t.Fatal(e)
	}
	db, e := securestore.Open(dbPath(a.wa.dataDir), true, bytes.Repeat([]byte{0x42}, 32))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	b := &App{store: NewStore(db), mode: "archive-reader"}
	cs := regressionClient(t, b)
	var status SendStatus
	call(t, cs, "get_send_status", map[string]any{"request_id": "historical-absent"}, &status)
	if status.State != "unknown" {
		t.Fatal(status)
	}
	previewMessage(t, b, "pure-reader-preview", alice.String(), "A1")
	var exists int
	if e := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='mcp_outbox'`).Scan(&exists); e != nil || exists != 0 {
		t.Fatalf("reader status migrated schema: %d %v", exists, e)
	}

}

func TestOwnerMessageReservationAcrossApps(t *testing.T) {
	a, f := messageApp(t)
	p := previewMessage(t, a, "two-apps", alice.String(), "")
	b := *a
	start := make(chan struct{})
	release := make(chan struct{})
	f.send = func(ctx context.Context, j types.JID, m *waE2E.Message, e ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
		close(start)
		<-release
		return whatsmeow.SendResponse{ID: e[0].ID, Timestamp: time.Now(), Chat: j}, nil
	}
	done := make(chan struct{})
	go func() { defer close(done); sendMessage(t, a, p) }()
	<-start
	if s := sendMessage(t, &b, p); s.State != "dispatching" {
		t.Fatal(s)
	}
	conflict := p
	conflict.ExpiresAt = time.Now().Add(14 * time.Minute).UTC().Format(time.RFC3339Nano)
	if _, _, e := b.sendText(context.Background(), nil, conflict); e == nil {
		t.Fatal("expiry fingerprint conflict accepted")
	}
	close(release)
	<-done
	if f.calls.Load() != 1 {
		t.Fatal("duplicate application dispatch")
	}
}
