//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hansen/whatsapp-mcp/internal/securestore"
	sqlite "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
)

// Old deletion cleared raw/text but left media metadata. Upgrading that real
// prior state must not copy deleted metadata into a new hidden mutation payload.
func TestArchiveLegacyDeletedMediaScrub(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := securestore.Open(filepath.Join(dir, "deleted.db"), false, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, archivePriorSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO mcp_messages(chat_jid,id,sender_jid,timestamp,kind,text,media_mime,media_filename,media_size,edited,deleted) VALUES(?, 'legacy-deleted-media', ?, ?, 'document', '', 'application/pdf', 'deleted-private-file.pdf', 1024, 1, 1)`, alice.String(), alice.String(), t0.Unix()); err != nil {
		t.Fatal(err)
	}
	w, err := newWA(ctx, db, NewStore(db), dir, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	m := archiveMessage(t, w, alice, "legacy-deleted-media")
	if !m.Deleted || m.Text != "" || m.FileName != "" || m.Mime != "" || m.Size != 0 || m.HasMedia {
		t.Errorf("visible legacy tombstone retains deleted media: %+v", m)
	}
	var content string
	var raw []byte
	if err := db.QueryRowContext(ctx, `SELECT content,raw FROM mcp_message_mutations WHERE chat_jid=? AND id='legacy-deleted-media'`, alice.String()).Scan(&content, &raw); err != nil {
		t.Fatal(err)
	}
	if content != "" || len(raw) != 0 {
		t.Errorf("migration retained deleted content in mutation storage: content=%q raw_bytes=%d", content, len(raw))
	}
}

// A history caller can retain an old resolved LID while an asynchronous mapping
// commits. Each metadata write must resolve identity inside its own transaction.
func TestArchiveStaleAliasMetadataWrites(t *testing.T) {
	w, _ := archiveFixture(t)
	ctx := context.Background()
	archiveIngest(t, w, bobLID, bobLID, "stale-metadata-original", t0, archiveText("message"), false)
	if err := w.Client.Store.LIDs.PutLIDMapping(ctx, bobLID, bob); err != nil {
		t.Fatal(err)
	}
	if err := w.store.SetChatName(ctx, bobLID.String(), false, "Canonical contact"); err != nil {
		t.Fatal(err)
	}
	if err := w.store.TouchChat(ctx, bobLID.String(), false, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := w.store.SetChatState(ctx, bobLID.String(), 7, true); err != nil {
		t.Fatal(err)
	}
	chats, err := w.store.Chats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(chats) != 1 || chats[0].JID != bob.String() {
		t.Errorf("stale metadata caller recreated orphan LID conversation: %+v", chats)
	}
	c, err := w.store.Chat(ctx, bob.String())
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "Canonical contact" || c.UnreadCount != 7 || !c.Archived || !c.LastMessageAt.Equal(t0.Add(time.Minute)) || c.MessageCount != 1 {
		t.Errorf("metadata missed accepted canonical conversation: %+v", c)
	}
}

// C-003/C-006: a fresh full transaction must recover a real stale WAL snapshot.
// The second handle models the independently committing Whatsmeow SQL store.
func TestArchiveTransactionSnapshotReplay(t *testing.T) {
	w, path := archiveFixture(t)
	other, err := securestore.Open(path, false, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	attempts := 0
	var failed *sql.Tx
	err = w.store.transaction(ctx, func(tx *sql.Tx) error {
		attempts++
		if failed != nil {
			if _, e := failed.ExecContext(ctx, "SELECT 1"); !errors.Is(e, sql.ErrTxDone) {
				t.Fatal("previous attempt was not rolled back before replay")
			}
		}
		jid, e := canonicalTx(ctx, tx, alice.String())
		if e != nil {
			return e
		}
		if attempts == 1 {
			if _, e := other.ExecContext(ctx, "INSERT INTO mcp_meta(key,value) VALUES('snapshot-peer','committed')"); e != nil {
				return e
			}
			failed = tx
		}
		err := touchTx(ctx, tx, jid, false, t0.Unix())
		if attempts == 1 {
			var cause sqlite.Error
			if !errors.As(err, &cause) || cause.Code != sqlite.ErrBusy || cause.ExtendedCode != sqlite.ErrBusySnapshot {
				t.Fatalf("fixture did not create typed 5/517: %v", err)
			}
		}
		return err
	})
	if err != nil {
		t.Fatalf("stale snapshot must recover through full replay: attempts=%d err=%v", attempts, err)
	}
	if attempts != 2 {
		t.Fatalf("attempts=%d want 2", attempts)
	}
	var n int
	if e := w.store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mcp_chats WHERE jid=?", alice.String()).Scan(&n); e != nil || n != 1 {
		t.Fatalf("exactly one committed chat: n=%d err=%v", n, e)
	}
}

// One compact table protects bounded replay and the typed-error allowlist.
func TestArchiveTransactionRetryBoundary(t *testing.T) {
	domain := errors.New("identity conflict")
	for _, tc := range []struct {
		name  string
		cause error
		want  int
	}{
		{"snapshot-exhaustion", fmt.Errorf("wrapped: %w", sqlite.Error{Code: sqlite.ErrBusy, ExtendedCode: sqlite.ErrBusySnapshot}), 3},
		{"ordinary-busy", sqlite.Error{Code: sqlite.ErrBusy, ExtendedCode: sqlite.ErrNoExtended(sqlite.ErrBusy)}, 1},
		{"locked", sqlite.Error{Code: sqlite.ErrLocked, ExtendedCode: sqlite.ErrNoExtended(sqlite.ErrLocked)}, 1},
		{"constraint", sqlite.Error{Code: sqlite.ErrConstraint, ExtendedCode: sqlite.ErrConstraintUnique}, 1},
		{"domain", domain, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := archiveFixture(t)
			attempts := 0
			var previous *sql.Tx
			err := w.store.transaction(context.Background(), func(tx *sql.Tx) error {
				attempts++
				if previous != nil {
					if _, e := previous.Exec("SELECT 1"); !errors.Is(e, sql.ErrTxDone) {
						t.Fatal("retry started before rollback")
					}
				}
				previous = tx
				if _, e := tx.Exec("INSERT INTO mcp_meta(key,value) VALUES('rollback-probe','never-commit')"); e != nil {
					return e
				}
				return tc.cause
			})
			if !errors.Is(err, tc.cause) || attempts != tc.want {
				t.Errorf("err=%v attempts=%d want original error/%d", err, attempts, tc.want)
			}
			var n int
			if e := w.store.db.QueryRow("SELECT COUNT(*) FROM mcp_meta WHERE key='rollback-probe'").Scan(&n); e != nil || n != 0 {
				t.Fatalf("partial transaction persisted n=%d err=%v", n, e)
			}
		})
	}
	t.Run("canceled-between-attempts", func(t *testing.T) {
		w, _ := archiveFixture(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		attempts := 0
		err := w.store.transaction(ctx, func(tx *sql.Tx) error {
			attempts++
			cancel()
			return sqlite.Error{Code: sqlite.ErrBusy, ExtendedCode: sqlite.ErrBusySnapshot}
		})
		if !errors.Is(err, context.Canceled) || attempts != 1 {
			t.Fatalf("cancellation must win: err=%v attempts=%d", err, attempts)
		}
	})
	t.Run("canceled-before-start", func(t *testing.T) {
		w, _ := archiveFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		attempts := 0
		err := w.store.transaction(ctx, func(*sql.Tx) error { attempts++; return nil })
		if !errors.Is(err, context.Canceled) || attempts != 0 {
			t.Fatalf("canceled context admitted body: err=%v attempts=%d", err, attempts)
		}
	})
	t.Run("already-finished-transaction-is-not-replayed", func(t *testing.T) {
		w, _ := archiveFixture(t)
		attempts := 0
		cause := sqlite.Error{Code: sqlite.ErrBusy, ExtendedCode: sqlite.ErrBusySnapshot}
		err := w.store.transaction(context.Background(), func(tx *sql.Tx) error {
			attempts++
			if _, e := tx.Exec("INSERT INTO mcp_meta(key,value) VALUES('commit-probe','committed')"); e != nil {
				return e
			}
			if e := tx.Commit(); e != nil {
				return e
			}
			return cause
		})
		if err == nil || attempts != 1 {
			t.Fatalf("unconfirmed rollback must forbid replay: err=%v attempts=%d", err, attempts)
		}
		var n int
		if e := w.store.db.QueryRow("SELECT COUNT(*) FROM mcp_meta WHERE key='commit-probe'").Scan(&n); e != nil || n != 1 {
			t.Fatalf("committed boundary changed n=%d err=%v", n, e)
		}
	})
}
