package main

// REQ-WC-004/007/008: runServe's real owner-lock composition, not caller assertions.
import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"github.com/hansen/whatsapp-mcp/internal/securestore"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

type eventOwnerAuthority struct{ held atomic.Bool }

func (a *eventOwnerAuthority) active() bool { return a != nil && a.held.Load() }

// Process-local worker state only: no native credential lookup or inference
// about host subscriptions, Dot completion or user notification.
func (a *App) eventsRuntimeStatus() string {
	if a.wa == nil || !a.authority.active() {
		return "unknown"
	}
	a.store.eventsMu.RLock()
	s := a.store.events
	a.store.eventsMu.RUnlock()
	if s == nil {
		return "disabled"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.workerError != "" {
		return "failed"
	}
	if s.closing {
		return "disabled"
	}
	if !s.started {
		return "unconfigured"
	}
	return "running"
}

type ServeDependencies struct {
	ArchiveKeys securestore.KeyStore
	Connect     func(context.Context, *WA) error
}

func openForServeWith(ctx context.Context, dataDir string, log zerolog.Logger, deps ServeDependencies) (*App, func(), error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, nil, err
	}
	keys := deps.ArchiveKeys
	if keys == nil {
		keys = securestore.NewNativeKeyStore()
	}
	lock, lockErr := acquireLock(dataDir)
	if lockErr != nil {
		db, err := securestore.OpenProfile(dbPath(dataDir), true, false, keys)
		if err != nil {
			return nil, nil, err
		}
		st := NewStore(db)
		if err := st.checkInitialized(ctx); err != nil {
			db.Close()
			return nil, nil, err
		}
		var once sync.Once
		return &App{store: st, mode: "read-only (another instance is connected)"}, func() { once.Do(func() { db.Close() }) }, nil
	}
	db, err := securestore.OpenProfile(dbPath(dataDir), false, false, keys)
	if err != nil {
		lock.Close()
		return nil, nil, err
	}
	st := NewStore(db)
	wa, err := newWA(ctx, db, st, dataDir, log)
	if err != nil {
		db.Close()
		lock.Close()
		return nil, nil, err
	}
	if err := st.recoverMessageOutbox(ctx); err != nil {
		wa.drainAndClose()
		lock.Close()
		return nil, nil, errors.New("recover message outbox failed")
	}
	authority := &eventOwnerAuthority{}
	authority.held.Store(true)
	app := &App{store: st, wa: wa, mode: "connected", authority: authority}
	if err := initSchoolWatchlist(ctx, app); err != nil {
		authority.held.Store(false)
		wa.drainAndClose()
		lock.Close()
		return nil, nil, err
	}
	wa.startSyncProgress()
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			authority.held.Store(false)
			if err := wa.drainAndClose(); err != nil {
				log.Error().Str("code", "archive_close_failed").Msg("archive cleanup failed")
			}
			lock.Close()
		})
	}
	if wa.Client.Store.ID == nil {
		app.mode = "not linked"
	} else {
		connect := deps.Connect
		if connect == nil {
			connect = func(context.Context, *WA) error { return wa.Client.Connect() }
		}
		if err := connect(ctx, wa); err != nil {
			log.Warn().Str("code", "initial_connect_failed").Msg("serving persisted archive")
		}
	}
	return app, cleanup, nil
}

type EventRuntime struct {
	Server  *mcp.Server
	Handler http.Handler
	Service *EventService
	cleanup func()
	mu      sync.Mutex
	closed  bool
	err     error
}

func (r *EventRuntime) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.err
	}
	if r.Service != nil {
		if err := r.Service.Close(ctx); err != nil {
			return err
		}
	}
	if r.cleanup != nil {
		r.cleanup()
	}
	r.closed = true
	return nil
}
func composeEventServe(ctx context.Context, app *App, cleanup func(), cfg EventConfig) (*EventRuntime, error) {
	if app == nil || app.store == nil {
		return nil, errors.New("missing archive app")
	}
	server := newMCPServer(app)
	runtime := &EventRuntime{Server: server, cleanup: cleanup}
	runtime.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	if !cfg.Enabled {
		return runtime, nil
	}
	if cfg.Transport != "http" || app.wa == nil || !app.authority.active() {
		return nil, errors.New("explicit Events mode requires the active HTTP owner")
	}
	cfg.Store = app.store
	cfg.WA = app.wa
	cfg.Owner = true
	s, err := NewEventService(cfg)
	if err != nil {
		return nil, err
	}
	if err := s.Register(server); err != nil {
		s.Close(context.Background())
		return nil, err
	}
	handler, err := s.HTTPHandler(server)
	if err != nil {
		s.Close(context.Background())
		return nil, err
	}
	runtime.Service = s
	runtime.Handler = handler
	if err := s.Start(ctx); err != nil {
		s.Close(context.Background())
		return nil, err
	}
	return runtime, nil
}
func defaultEventConfig(dataDir, transport string, enabled bool) (EventConfig, error) {
	path, err := filepath.EvalSymlinks(dbPath(dataDir))
	if err != nil {
		return EventConfig{}, err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return EventConfig{}, err
	}
	profile := sha256.Sum256([]byte(path))
	id := fmt.Sprintf("%x", profile)
	return EventConfig{ProfileID: id, OwnerID: "owner_" + id, Transport: transport, Enabled: enabled}, nil
}
func revokeStoredEvents(ctx context.Context, st *Store) error {
	return st.transaction(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mcp_event_access'`).Scan(&n); err != nil || n == 0 {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE mcp_event_access SET state='revoked',generation=generation+1; UPDATE mcp_event_subscriptions SET state='revoked',generation=generation+1,last_error_code='logged_out'; UPDATE mcp_event_deliveries SET state='canceled',last_error_code='logged_out' WHERE state IN ('pending','leased')`)
		return err
	})
}
