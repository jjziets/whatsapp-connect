package main

// REQ-WC-007/008: native credential references, never command/env/SQL key bytes.
import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"
)

func (s *EventService) accessID() string {
	h := sha256.Sum256([]byte("wc-events-access-v1" + s.cfg.ProfileID))
	return "sub_" + hex.EncodeToString(h[:])
}

// Native owner access keys are always exactly 32 bytes. Webhook signing keys
// have their own separate protocol bounds. Never call native providers while
// holding a SQL transaction; callers fence metadata/generation separately.
func (s *EventService) readAccessCredential(ctx context.Context, ref string) ([]byte, error) {
	key, err := s.cfg.Secrets.Get(ctx, ref)
	if err != nil || len(key) != 32 {
		return nil, errors.New("events access credential unavailable")
	}
	return key, nil
}
func (s *EventService) Access(ctx context.Context, op string) (EventAccessStatus, error) {
	out := EventAccessStatus{OwnerID: s.cfg.OwnerID, ProfileID: s.cfg.ProfileID}
	finish, err := s.admit()
	if err != nil {
		return out, err
	}
	defer finish()
	var ref, state, owner string
	var generation int64
	err = s.cfg.Store.db.QueryRowContext(ctx, `SELECT key_ref,state,generation,owner_id FROM mcp_event_access WHERE profile_id=?`, s.cfg.ProfileID).Scan(&ref, &state, &generation, &owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, errors.New("access metadata unavailable")
	}
	if err == nil && owner != s.cfg.OwnerID {
		return out, errors.New("owner mismatch")
	}
	out.Enabled = state == "active"
	switch op {
	case "status":
		if out.Enabled {
			if _, err := s.readAccessCredential(ctx, ref); err != nil {
				out.Enabled = false
				return out, errors.New("events access credential unavailable")
			}
		}
		return out, nil
	case "copy":
		if !out.Enabled {
			return out, errors.New("events access disabled")
		}
		key, err := s.readAccessCredential(ctx, ref)
		if err != nil {
			return out, errors.New("events access credential unavailable")
		}
		copyFn := s.cfg.Clipboard
		if copyFn == nil {
			copyFn = func(token string) error {
				cmd := exec.CommandContext(ctx, "/usr/bin/pbcopy")
				cmd.Stdin = strings.NewReader(token)
				return cmd.Run()
			}
		}
		if err := copyFn(base64.RawURLEncoding.EncodeToString(key)); err != nil {
			return out, errors.New("clipboard copy failed")
		}
		return out, nil
	case "init", "rotate":
		if op == "init" && out.Enabled {
			return out, nil
		}
		if op == "rotate" && !out.Enabled {
			return out, errors.New("events access disabled")
		}
		s.secretMu.Lock()
		defer s.secretMu.Unlock()
		key := make([]byte, 32)
		s.randomMu.Lock()
		_, err := io.ReadFull(s.cfg.Random, key)
		s.randomMu.Unlock()
		if err != nil {
			return out, errors.New("access entropy unavailable")
		}
		newRef, err := s.stageKey(ctx, s.accessID(), key)
		if err != nil {
			return out, errors.New("access credential unavailable")
		}
		err = s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
			var current int64
			e := tx.QueryRowContext(ctx, `SELECT generation FROM mcp_event_access WHERE profile_id=?`, s.cfg.ProfileID).Scan(&current)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if current != generation {
				return errors.New("access changed")
			}
			_, e = tx.ExecContext(ctx, `INSERT INTO mcp_event_access(profile_id,owner_id,key_ref,generation,state,updated_at) VALUES(?,?,?,?,'active',?) ON CONFLICT(profile_id) DO UPDATE SET key_ref=excluded.key_ref,generation=excluded.generation,state='active',updated_at=excluded.updated_at`, s.cfg.ProfileID, s.cfg.OwnerID, newRef, generation+1, s.cfg.Now().UnixMilli())
			if e != nil {
				return e
			}
			_, e = tx.ExecContext(ctx, `DELETE FROM mcp_event_staged_keys WHERE ref=?`, newRef)
			return e
		})
		if err != nil {
			_ = s.cleanupKey(context.Background(), newRef)
			return out, errors.New("access activation failed")
		}
		if ref != "" {
			_ = s.cfg.Secrets.Delete(context.Background(), ref)
		}
		out.Enabled = true
		return out, nil
	case "revoke":
		err = s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
			if _, e := tx.ExecContext(ctx, `UPDATE mcp_event_access SET state='revoked',generation=generation+1,updated_at=? WHERE profile_id=? AND owner_id=?`, s.cfg.Now().UnixMilli(), s.cfg.ProfileID, s.cfg.OwnerID); e != nil {
				return e
			}
			if _, e := tx.ExecContext(ctx, `UPDATE mcp_event_subscriptions SET state='revoked',generation=generation+1,last_error_code='access_revoked',updated_at=? WHERE profile_id=? AND principal_id=?`, s.cfg.Now().UnixMilli(), s.cfg.ProfileID, s.cfg.OwnerID); e != nil {
				return e
			}
			_, e := tx.ExecContext(ctx, `UPDATE mcp_event_deliveries SET state='canceled',last_error_code='access_revoked' WHERE state IN ('pending','leased') AND subscription_id IN (SELECT id FROM mcp_event_subscriptions WHERE profile_id=? AND principal_id=?)`, s.cfg.ProfileID, s.cfg.OwnerID)
			return e
		})
		if err != nil {
			return out, errors.New("access revocation failed")
		}
		if ref != "" {
			_ = s.cfg.Secrets.Delete(context.Background(), ref)
		}
		out.Enabled = false
		s.Wake()
		return out, nil
	default:
		return out, errors.New("unknown events-access operation")
	}
}
func (s *EventService) authorized(ctx context.Context, header string) bool {
	// Malformed/missing credentials must not trigger native Keychain work.
	if len(header) != 50 || !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(header, "Bearer "))
	if err != nil || len(decoded) != 32 {
		return false
	}
	var ref string
	err = s.cfg.Store.db.QueryRowContext(ctx, `SELECT key_ref FROM mcp_event_access WHERE profile_id=? AND owner_id=? AND state='active'`, s.cfg.ProfileID, s.cfg.OwnerID).Scan(&ref)
	if err != nil {
		return false
	}
	key, err := s.readAccessCredential(ctx, ref)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header), []byte("Bearer "+base64.RawURLEncoding.EncodeToString(key))) == 1
}
func dispatchEventsAccess(ctx context.Context, args []string, app *App, cfg EventConfig, out, stderr io.Writer) error {
	if app == nil || app.authority == nil || !app.authority.active() {
		return errors.New("events-access requires owner profile lock")
	}
	if len(args) != 1 {
		return errors.New("events-access requires init|status|rotate|revoke|copy")
	}
	cfg.Store = app.store
	cfg.WA = app.wa
	cfg.Owner = true
	cfg.Transport = "http"
	s, err := NewEventService(cfg)
	if err != nil {
		return err
	}
	defer s.Close(context.Background())
	status, err := s.Access(ctx, args[0])
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(status)
}

// Caller holds secretMu across native staging and the DB reference swap. Native
// calls always complete before the SQL transaction begins. Staged refs survive a
// crash for own-profile startup GC; failed cleanup remains an explicit gap.
func (s *EventService) stageKey(ctx context.Context, id string, key []byte) (string, error) {
	ref, err := s.cfg.Secrets.PutVersion(ctx, id, key)
	if err != nil {
		return "", err
	}
	err = s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `INSERT INTO mcp_event_staged_keys(ref,created_at) VALUES(?,?)`, ref, s.cfg.Now().UnixMilli())
		return e
	})
	if err != nil {
		_ = s.cfg.Secrets.Delete(context.Background(), ref)
		return "", errors.New("credential staging failed")
	}
	return ref, nil
}
func (s *EventService) cleanupKey(ctx context.Context, ref string) error {
	if err := s.cfg.Secrets.Delete(ctx, ref); err != nil {
		_ = s.cfg.Store.recordFailure(ctx, "events_key_cleanup_failed")
		return errors.New("credential cleanup unavailable")
	}
	return s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM mcp_event_staged_keys WHERE ref=?`, ref)
		return err
	})
}
