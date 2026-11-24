package main

// Manual C-006/C-008/C-009: purpose-authenticated transport on the existing owner.
// Optional native Events share this owner; credential provisioning is explicit.
import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const ownerHTTPKeyService = "com.oxiom.whatsapp-connect.owner-http"
const ownerHTTPHeader = "X-WhatsApp-Owner-Authorization"

// Internal dependency boundaries only; the CLI always uses native lookup and a
// fixed nonzero port. Injected keys permit port zero for synthetic local tests.
type OwnerHTTPDependencies struct {
	// Nil retains the default owner HTTP mode. Identity is always revalidated
	// against the active owner's canonical profile before using this config.
	Events     *EventConfig
	ReadKey    func() ([]byte, error)
	BeforeBind func()
	OnReady    func(string, *mcp.Server)
}

type OwnerHTTPRuntime struct {
	Server    *mcp.Server
	Service   *EventService
	srv       *http.Server
	listener  net.Listener
	cancel    context.CancelFunc
	done      chan struct{}
	serveErr  error
	closeOnce sync.Once
	mu        sync.Mutex
	closing   bool
	active    sync.WaitGroup
}

func validateOwnerHTTPMode(transport string, events bool) error {
	if transport != "stdio" || events {
		return errors.New("owner HTTP requires stdio with Events disabled")
	}
	return nil
}
func validateOwnerHTTPAddr(addr string, ephemeral bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" || port == "" {
		return errors.New("owner HTTP requires 127.0.0.1 and a valid fixed port")
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return errors.New("invalid owner HTTP port")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 || n == 0 && !ephemeral {
		return errors.New("invalid owner HTTP port")
	}
	return nil
}
func ownerHTTPAccount(path string) (string, error) {
	canonical, err := ownerHTTPCanonicalDBPath(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(canonical))), nil
}

func ownerHTTPAuthorize(key []byte, next http.Handler) http.Handler {
	// Copy the startup key so an injected provider cannot mutate authentication.
	want := append([]byte(nil), key...)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values(ownerHTTPHeader)
		if len(want) != 32 || len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		encoded := strings.TrimPrefix(values[0], "Bearer ")
		raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != encoded || subtle.ConstantTimeCompare(raw, want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// startOwnerHTTP binds synchronously only after owner and exact-purpose key
// checks. All paths (including discovery and errors) authenticate, and this
// dedicated origin never redirects or serves files.
func startOwnerHTTP(parent context.Context, app *App, addr string, deps OwnerHTTPDependencies) (*OwnerHTTPRuntime, error) {
	if err := validateOwnerHTTPAddr(addr, deps.ReadKey != nil); err != nil {
		return nil, err
	}
	if app == nil || app.store == nil || app.wa == nil || !app.authority.active() {
		return nil, errors.New("owner HTTP requires the active WhatsApp owner")
	}
	var service *EventService
	if deps.Events != nil {
		canonical, err := defaultEventConfig(app.wa.dataDir, "http", true)
		if err != nil || app.store != app.wa.store || deps.Events.ProfileID != canonical.ProfileID || deps.Events.OwnerID != canonical.OwnerID || deps.Events.Transport != "http" || !deps.Events.Enabled {
			return nil, errors.New("owner HTTP Events require the canonical active owner profile")
		}
		cfg := *deps.Events
		cfg.Store, cfg.WA, cfg.Owner = app.store, app.wa, true
		service, err = NewEventService(cfg)
		if err != nil {
			return nil, fmt.Errorf("owner HTTP Events unconfigured: %w", err)
		}
		ready, err := service.Access(parent, "status")
		if err != nil || !ready.Enabled {
			_ = service.Close(context.Background())
			return nil, errors.New("owner HTTP Events unconfigured: active events-access grant and native credential required")
		}
	}
	// Every failure before successful transfer to rt must release producer
	// ownership, including absent tunnel key, canceled parent and bind failure.
	transferred := false
	defer func() {
		if service != nil && !transferred {
			_ = service.Close(context.Background())
		}
	}()
	read := deps.ReadKey
	if read == nil {
		account, err := ownerHTTPAccount(dbPath(app.wa.dataDir))
		if err != nil {
			return nil, err
		}
		read = func() ([]byte, error) { return readOwnerHTTPKey(account) }
	}
	key, err := read()
	if err != nil || len(key) != 32 {
		return nil, errors.New("owner HTTP credential unavailable or invalid")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	if deps.BeforeBind != nil {
		deps.BeforeBind()
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, errors.New("owner HTTP listener unavailable")
	}
	ctx, cancel := context.WithCancel(parent)
	rt := &OwnerHTTPRuntime{Server: newMCPServer(app), Service: service, listener: listener, cancel: cancel, done: make(chan struct{})}
	if service != nil {
		if err := service.Register(rt.Server); err != nil {
			listener.Close()
			cancel()
			return nil, err
		}
		if err := service.Start(ctx); err != nil {
			listener.Close()
			cancel()
			return nil, err
		}
	}
	// The SDK detaches long-lived session contexts from HTTP requests. Link every
	// actual receiving handler to the owner lifetime, then drain those handlers
	// before storage cleanup. WA media/history retain their existing admission.
	rt.Server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(call context.Context, method string, req mcp.Request) (mcp.Result, error) {
			rt.mu.Lock()
			if rt.closing || ctx.Err() != nil {
				rt.mu.Unlock()
				return nil, errors.New("owner HTTP is closing")
			}
			rt.active.Add(1)
			rt.mu.Unlock()
			defer rt.active.Done()
			linked, done := context.WithCancel(call)
			stop := context.AfterFunc(ctx, done)
			defer func() { stop(); done() }()
			return next(linked, method, req)
		}
	})
	var handler http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return rt.Server }, &mcp.StreamableHTTPOptions{Stateless: true, PropagateRequestCancellation: true})
	if service != nil {
		handler = ownerHTTPEventsAdapter(service, handler)
	}
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
	rt.srv = &http.Server{Handler: ownerHTTPAuthorize(key, routes), ReadHeaderTimeout: 10 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	if deps.OnReady != nil {
		deps.OnReady(rt.URL(), rt.Server)
	}
	go func() {
		err := rt.srv.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			rt.serveErr = errors.New("owner HTTP listener stopped unexpectedly")
			cancel()
		}
		close(rt.done)
	}()
	go func() { <-ctx.Done(); _ = rt.Close(context.Background()) }()
	transferred = true
	return rt, nil
}

// This adapter is private to the already-authenticated owner route. It only
// supplies SDK principal metadata; it does not replace or weaken owner-header
// authentication, EventService grants, or worker credential checks. Incoming
// Authorization is irrelevant on this purpose-authenticated tunnel.
func ownerHTTPEventsAdapter(service *EventService, next http.Handler) http.Handler {
	principal := auth.RequireBearerToken(func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		return &auth.TokenInfo{UserID: service.cfg.OwnerID}, nil
	}, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finish, err := service.admit()
		if err != nil {
			http.Error(w, "events closing", http.StatusServiceUnavailable)
			return
		}
		defer finish()
		copy := r.Clone(r.Context())
		copy.Header.Set("Authorization", "Bearer internal-owner-http-principal")
		principal.ServeHTTP(w, copy)
	})
}
func (r *OwnerHTTPRuntime) URL() string { return "http://" + r.listener.Addr().String() + "/mcp" }
func (r *OwnerHTTPRuntime) Close(context.Context) error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closing = true
		r.mu.Unlock()
		r.cancel()
		shutdown, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		if err := r.srv.Shutdown(shutdown); err != nil {
			_ = r.srv.Close()
		}
		cancel()
		<-r.done
		// No active.Add can race this Wait after closing=true. Closing the actual
		// SDK sessions releases their SSE streams and drains their own dispatchers.
		r.active.Wait()
		for session := range r.Server.Sessions() {
			_ = session.Close()
		}
		if r.Service != nil {
			_ = r.Service.Close(context.Background())
		}
	})
	return r.serveErr
}

// Production and synthetic SDK IOTransport use the same EOF cleanup ordering.
func serveOwnedStdio(parent context.Context, app *App, cleanup func(), transport mcp.Transport, addr string, deps OwnerHTTPDependencies) error {
	ctx, cancel := context.WithCancel(parent)
	defer cleanup()
	defer cancel()
	server := newMCPServer(app)
	if addr != "" {
		rt, err := startOwnerHTTP(ctx, app, addr, deps)
		if err != nil {
			return err
		}
		defer rt.Close(context.Background())
		// HTTP Events and control tools must never be registered on stdio.
		// A listener failure is fatal to the entire stdio invocation.
		go func() {
			select {
			case <-rt.done:
				cancel()
			case <-ctx.Done():
			}
		}()
		err = server.Run(ctx, transport)
		return errors.Join(err, rt.Close(context.Background()))
	}
	return server.Run(ctx, transport)
}
