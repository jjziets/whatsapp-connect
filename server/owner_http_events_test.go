//go:build libsqlite3

package main

// VER-OHE-01..05: real SDK HTTP/IOTransport and real encrypted owner lock,
// synthetic native credentials, callback transport and WhatsApp originals only.
import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hansen/whatsapp-mcp/internal/eventdelivery"
	"github.com/hansen/whatsapp-mcp/internal/eventsecrets"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mau.fi/whatsmeow/types"
)

// BDEF-01: exercise the real command dispatcher; every case must stop before
// opening this deliberately absent profile or consulting any native key.
func TestOwnerHTTPEventsCLIHelper(t *testing.T) {
	if os.Getenv("WC_OHE_CLI_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0], "serve"}, os.Args[i+1:]...)
			main()
			return
		}
	}
	t.Fatal("missing subprocess args")
}

func TestOwnerHTTPEventsCLIOptInAndInvalidModes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags []string
		want  string
	}{
		{"requires-side-listener", nil, "requires --owner-http-addr"},
		{"rejects-primary-http", []string{"--transport", "http", "--owner-http-addr", "127.0.0.1:9000"}, "requires stdio"},
		{"rejects-primary-events", []string{"--events", "--owner-http-addr", "127.0.0.1:9000"}, "Events disabled"},
		{"side-events-keeps-real-writes", []string{"--enable-message-writes", "--owner-http-addr", "127.0.0.1:0"}, "invalid owner HTTP port"},
		{"side-events-keeps-inert-qualification", []string{"--message-confirmation-test", "--owner-http-addr", "127.0.0.1:0"}, "invalid owner HTTP port"},
		{"real-inert-exclusive", []string{"--enable-message-writes", "--message-confirmation-test", "--owner-http-addr", "127.0.0.1:9000"}, "mutually exclusive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := filepath.Join(t.TempDir(), "must-remain-absent")
			args := []string{"-test.run=^TestOwnerHTTPEventsCLIHelper$", "--", "--data-dir", profile, "--owner-http-events"}
			args = append(args, tc.flags...)
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "WC_OHE_CLI_HELPER=1")
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("CLI did not enforce %s before profile work: err=%v output=%s", tc.want, err, out)
			}
			if _, err := os.Stat(profile); !os.IsNotExist(err) {
				t.Fatal("invalid mode touched profile before validation")
			}
		})
	}
}

func oheFixture(t *testing.T, provision bool) (*App, func(), *evHarness, OwnerHTTPDependencies, string) {
	t.Helper()
	app, cleanup, dir := evOwnedApp(t)
	cfg, err := defaultEventConfig(dir, "http", true)
	if err != nil {
		t.Fatal(err)
	}
	clock := &evClock{t: time.Now()}
	keys := &evKeys{profile: cfg.ProfileID, keys: map[string][]byte{}}
	sender := &evSender{store: app.store, receipt: eventdelivery.Receipt{StatusCode: 200}, committed: true}
	cfg.Secrets, cfg.Sender, cfg.Now = keys, sender, clock.Now
	h := &evHarness{w: app.wa, cfg: cfg, keys: keys, sender: sender, clock: clock}
	if provision {
		s, err := NewEventService(EventConfig{Store: app.store, WA: app.wa, Owner: true, Transport: "http", ProfileID: cfg.ProfileID, OwnerID: cfg.OwnerID, Secrets: keys, Sender: sender, Now: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Access(context.Background(), "init"); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	key := bytes.Repeat([]byte{0x74}, 32)
	return app, cleanup, h, OwnerHTTPDependencies{Events: &cfg, ReadKey: func() ([]byte, error) { return key, nil }}, "Bearer " + base64.RawURLEncoding.EncodeToString(key)
}

func oheStart(t *testing.T, app *App, h *evHarness, deps OwnerHTTPDependencies) *OwnerHTTPRuntime {
	t.Helper()
	rt, err := startOwnerHTTP(context.Background(), app, "127.0.0.1:0", deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close(context.Background()) })
	h.s = rt.Service
	return rt
}

func oheRPC(url, token, method string, params map[string]any) c4Wire {
	r := c4Request(context.Background(), url, token, c4Version, method, params)
	// Owner tunnel deliberately supplies no Events bearer or OAuth credential.
	r.Header.Del("Authorization")
	return c4Do(r)
}

func oheSub(t *testing.T, url, token string, chats ...string) string {
	t.Helper()
	r := evReq(chats[0], "")
	r.Arguments, _ = json.Marshal(EventFilter{ChatJIDs: chats})
	raw, _ := json.Marshal(r)
	var p map[string]any
	_ = json.Unmarshal(raw, &p)
	p["_meta"] = c4Meta()
	got := oheRPC(url, token, "events/subscribe", p)
	if !c4Success(t, got) {
		t.FailNow()
	}
	return spObject(t, got.message, "result")["id"].(string)
}

func TestOwnerHTTPEventsDiscoveryAndDefaultIsolation(t *testing.T) {
	app, _, h, deps, token := oheFixture(t, true)
	rt := oheStart(t, app, h, deps)
	for _, method := range []string{"initialize", "server/discover"} {
		t.Run(method, func(t *testing.T) {
			p := c4Params("")
			if method == "initialize" {
				p = map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "synthetic-ohe", "version": "1"}}
			}
			got := oheRPC(rt.URL(), token, method, p)
			if method == "initialize" {
				got = c4Do(c4Request(context.Background(), rt.URL(), token, "2025-11-25", method, p))
			}
			if !c4Success(t, got) {
				return
			}
			caps := spObject(t, spObject(t, got.message, "result"), "capabilities")
			if caps["events"] == nil {
				t.Fatalf("opted-in owner HTTP %s does not advertise native Events: %s", method, got.body)
			}
		})
	}
	if rt.Service == nil {
		t.Fatal("opted-in owner HTTP has no EventService")
	}
	c4Success(t, oheRPC(rt.URL(), token, "events/list", c4Params("")))
	c4Success(t, oheRPC(rt.URL(), token, "tools/call", c4Params("whatsapp_status")))
	// Separate default owner listeners must not acquire the existing producer.
	deps.Events = nil
	plain := oheStart(t, app, &evHarness{}, deps)
	if plain.Service != nil {
		t.Fatal("default owner HTTP unexpectedly enabled Events")
	}
	if c4Code(oheRPC(plain.URL(), token, "events/list", c4Params(""))) != -32601 {
		t.Fatal("Events method leaked into default server")
	}
}

func TestOwnerHTTPEventsUnconfiguredFailsBeforeBind(t *testing.T) {
	for _, state := range []string{"missing-grant", "revoked", "missing-key", "denied-key", "foreign-owner", "foreign-profile", "reader"} {
		t.Run(state, func(t *testing.T) {
			app, _, h, deps, _ := oheFixture(t, state != "missing-grant")
			switch state {
			case "revoked":
				_, err := app.store.db.Exec(`UPDATE mcp_event_access SET state='revoked'`)
				if err != nil {
					t.Fatal(err)
				}
			case "missing-key":
				h.keys.keys = map[string][]byte{}
			case "denied-key":
				h.keys.getErr = eventsecrets.ErrDenied
			case "foreign-owner":
				deps.Events.OwnerID = "foreign-owner"
			case "foreign-profile":
				deps.Events.ProfileID = strings.Repeat("b", 64)
			case "reader":
				app = &App{store: app.store, mode: "read-only"}
			}
			puts := h.keys.n
			bound := false
			deps.BeforeBind = func() { bound = true }
			rt, err := startOwnerHTTP(context.Background(), app, "127.0.0.1:0", deps)
			if rt != nil {
				_ = rt.Close(context.Background())
			}
			if err == nil {
				t.Errorf("%s silently exposed owner HTTP instead of explicit Events-unconfigured failure", state)
			}
			if bound {
				t.Error("unconfigured Events reached listener binding")
			}
			if h.keys.n != puts {
				t.Error("failed startup provisioned native credentials")
			}
		})
	}
}

func TestOwnerHTTPEventsAuthLivePointerAndRevocation(t *testing.T) {
	app, _, h, deps, token := oheFixture(t, true)
	rt := oheStart(t, app, h, deps)
	if rt.Service == nil {
		t.Fatal("opted-in side listener lacks live Events producer")
	}
	second := types.NewJID("120363000000002", types.GroupServer)
	id := oheSub(t, rt.URL(), token, group.String(), second.String())
	for _, values := range [][]string{nil, {"Bearer wrong"}, {token, token}, {token + "="}, {token + ", " + token}} {
		req := c4Request(context.Background(), rt.URL(), token, c4Version, "events/list", c4Params(""))
		req.Header.Del(ownerHTTPHeader)
		for _, value := range values {
			req.Header.Add(ownerHTTPHeader, value)
		}
		req.Header.Set("Mcp-Session-Id", "previously-authenticated-session")
		if got := c4Do(req); got.status != 401 {
			t.Fatalf("invalid owner header admitted Events: status=%d", got.status)
		}
	}
	for _, chat := range []types.JID{group, second} {
		evLive(h, chat, alice, "selected-"+chat.User, h.clock.Now())
	}
	evLive(h, alice, alice, "personal-dm-negative", h.clock.Now())
	evLive(h, types.NewJID("120363000000003", types.GroupServer), alice, "other-group-negative", h.clock.Now())
	outgoing := textMsg(group, alice, "outgoing-negative", h.clock.Now(), "outgoing")
	outgoing.Info.IsFromMe = true
	app.wa.handleEvent(outgoing)
	app.wa.ingestHistory(context.Background(), archiveChunk(group, archiveWeb(group, alice, "history-negative", h.clock.Now(), archiveText("history"))))
	evWait(t, "two exact group callback receipts", func() bool { return len(h.sender.requests()) == 2 })
	if n := evCount(t, h, "mcp_event_outbox"); n != 2 {
		t.Fatalf("pointer outbox count=%d; DM/history/unselected leaked", n)
	}
	for _, q := range h.sender.requests() {
		if strings.Contains(string(q.Body), "UNTRUSTED") || strings.Contains(string(q.Body), "private/media") {
			t.Fatal("callback leaked message body/path")
		}
		if len(q.Secrets) != 1 || !strings.HasPrefix(q.Secrets[0], "whsec_") {
			t.Fatal("callback missing native signing material")
		}
	}
	monitors := oheRPC(rt.URL(), token, "tools/call", c4Params("list_message_monitors"))
	if !c4Success(t, monitors) {
		return
	}
	if strings.Contains(monitors.body, "callback.example") || strings.Contains(monitors.body, "whsec_") {
		t.Fatal("monitor status leaked endpoint or key")
	}
	if !strings.Contains(monitors.body, group.String()) || !strings.Contains(monitors.body, second.String()) {
		t.Error("monitor status does not disclose exact nonsecret target JIDs for reconciliation")
	}
	before := evMon(t, h, id)
	if before.SummaryCompleted != nil || before.UserNotified != nil {
		t.Fatal("callback receipt incorrectly asserted Dot completion or user push")
	}
	if _, err := rt.Service.Access(context.Background(), "rotate"); err != nil {
		t.Fatal(err)
	}
	if got := oheSub(t, rt.URL(), token, group.String(), second.String()); got != id {
		t.Fatal("Events access rotation changed stable monitor identity")
	}
	if _, err := rt.Service.Access(context.Background(), "revoke"); err != nil {
		t.Fatal(err)
	}
	if got := oheRPC(rt.URL(), token, "events/list", c4Params("")); got.message["error"] == nil {
		t.Fatal("revoked access still lists Events")
	}
	// Ordinary authenticated archive access remains available after Events revoke.
	c4Success(t, oheRPC(rt.URL(), token, "tools/call", c4Params("whatsapp_status")))
	evLive(h, group, alice, "after-revoke", h.clock.Now())
	if _, err := rt.Service.DispatchOnce(context.Background()); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(h.sender.requests()) != 2 {
		t.Fatal("revoked Events delivered another callback")
	}
}

func TestOwnerHTTPEventsStdioIsolationAndEOFDrain(t *testing.T) {
	app, cleanup, h, deps, token := oheFixture(t, true)
	app.messageWrites = true // Synthetic registry proof; no sender is invoked.
	input, controller := io.Pipe()
	output, writer := io.Pipe()
	defer input.Close()
	defer controller.Close()
	defer output.Close()
	defer writer.Close()
	ready := make(chan *mcp.Server, 1)
	urls := make(chan string, 1)
	deps.OnReady = func(url string, server *mcp.Server) { urls <- url; ready <- server }
	finished, cleaned := make(chan error, 1), make(chan bool, 1)
	go func() {
		finished <- serveOwnedStdio(context.Background(), app, func() {
			app.store.eventsMu.RLock()
			service := app.store.events
			app.store.eventsMu.RUnlock()
			cleaned <- service == nil
			cleanup()
		}, &mcp.IOTransport{Reader: input, Writer: writer}, "127.0.0.1:0", deps)
	}()
	var url string
	select {
	case url = <-urls:
	case err := <-finished:
		t.Fatalf("startup failed: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("side startup timeout")
	}
	<-ready
	reader := bufio.NewReader(output)
	for i, method := range []string{"initialize", "tools/list", "events/list"} {
		params := map[string]any{}
		if method == "initialize" {
			params = map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "synthetic-stdio", "version": "1"}}
		}
		raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": i + 1, "method": method, "params": params})
		if _, err := fmt.Fprintln(controller, string(raw)); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(line, &out); err != nil {
			t.Fatal(err)
		}
		if method == "initialize" && strings.Contains(string(line), `"events"`) {
			t.Error("HTTP Events capabilities leaked to concurrent stdio")
		}
		if method == "tools/list" {
			if strings.Contains(string(line), "message_monitor") {
				t.Error("HTTP monitor tools leaked to concurrent stdio")
			}
			if !strings.Contains(string(line), "send_text") {
				t.Error("side Events disabled current confirmed-send tool")
			}
		}
		if method == "events/list" && out["error"] == nil {
			t.Error("HTTP Events methods leaked to concurrent stdio")
		}
	}
	// Admission through actual HTTP proves controller EOF shuts the EventService.
	id := oheSub(t, url, token, group.String())
	if id == "" {
		t.Fatal("empty monitor identity")
	}
	callbackEntered, releaseCallback := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-releaseCallback:
		default:
			close(releaseCallback)
		}
	}()
	h.sender.mu.Lock()
	h.sender.enter = func(eventdelivery.Request) func() { close(callbackEntered); <-releaseCallback; return nil }
	h.sender.mu.Unlock()
	evLive(h, group, alice, "blocked-callback-at-eof", h.clock.Now())
	spAwait(t, callbackEntered)
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
		t.Fatal("stdio EOF returned while callback still admitted")
	case <-time.After(30 * time.Millisecond):
	}
	close(releaseCallback)
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("stdio EOF did not drain side Events")
	}
	if !<-cleaned {
		t.Fatal("owner archive cleanup preceded EventService drain")
	}
	if _, err := app.store.db.Exec("SELECT 1"); err == nil {
		t.Fatal("stdio EOF left archive open")
	}
	if got := oheRPC(url, token, "tools/list", c4Params("")); got.status == http.StatusOK {
		t.Fatal("side listener survived stdio EOF")
	}
}

func TestOwnerHTTPEventsSDKPrincipalAndRequestCancellation(t *testing.T) {
	app, _, h, deps, token := oheFixture(t, true)
	deps.OnReady = func(_ string, server *mcp.Server) {
		mcp.AddTool(server, &mcp.Tool{Name: "fixture_principal"}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]string, error) {
			id := ""
			if req.Extra != nil && req.Extra.TokenInfo != nil {
				id = req.Extra.TokenInfo.UserID
			}
			return nil, map[string]string{"principal": id}, nil
		})
	}
	rt := oheStart(t, app, h, deps)
	if rt.Service == nil {
		t.Fatal("missing side Events service")
	}
	principal := oheRPC(rt.URL(), token, "tools/call", c4Params("fixture_principal"))
	if c4Success(t, principal) {
		got := spObject(t, spObject(t, principal.message, "result"), "structuredContent")["principal"]
		if got != h.cfg.OwnerID {
			t.Fatalf("SDK principal=%v want stable canonical owner=%s", got, h.cfg.OwnerID)
		}
	}
	entered, canceled := make(chan struct{}), make(chan struct{})
	h.sender.verifyHook = func(ctx context.Context, _, _, _ string) error {
		close(entered)
		<-ctx.Done()
		close(canceled)
		return ctx.Err()
	}
	raw, _ := json.Marshal(evReq(group.String(), ""))
	var p map[string]any
	_ = json.Unmarshal(raw, &p)
	p["_meta"] = c4Meta()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := c4Request(ctx, rt.URL(), token, c4Version, "events/subscribe", p)
	req.Header.Del("Authorization")
	done := make(chan c4Wire, 1)
	go func() { done <- c4Do(req) }()
	spAwait(t, entered)
	cancel()
	spAwait(t, canceled)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled client did not return")
	}
	if n := evCount(t, h, "mcp_event_subscriptions"); n != 0 {
		t.Fatal("canceled verification activated subscription")
	}
	c4Success(t, oheRPC(rt.URL(), token, "tools/call", c4Params("whatsapp_status")))
}

// Repair definition R1 / REQ-WC-007: the native Events access credential is
// distinct from webhook signing credentials (which support different lengths).
type oheNativeReads struct {
	eventsecrets.EventSecretProvider
	reads     atomic.Int64
	mu        sync.Mutex
	beforeGet func(string)
}

func (p *oheNativeReads) Get(ctx context.Context, ref string) ([]byte, error) {
	p.reads.Add(1)
	p.mu.Lock()
	hook := p.beforeGet
	p.mu.Unlock()
	if hook != nil {
		hook(ref)
	}
	return p.EventSecretProvider.Get(ctx, ref)
}
func oheAccessRef(t *testing.T, h *evHarness) string {
	t.Helper()
	var ref string
	if err := h.w.store.db.QueryRow(`SELECT key_ref FROM mcp_event_access WHERE profile_id=?`, h.cfg.ProfileID).Scan(&ref); err != nil {
		t.Fatal(err)
	}
	return ref
}
func oheBreakAccess(h *evHarness, ref, state string) {
	h.keys.mu.Lock()
	defer h.keys.mu.Unlock()
	switch state {
	case "missing":
		delete(h.keys.keys, ref)
	case "denied":
		h.keys.getErr = eventsecrets.ErrDenied
	case "short":
		h.keys.keys[ref] = bytes.Repeat([]byte{0x74}, 24)
	case "long":
		h.keys.keys[ref] = bytes.Repeat([]byte{0x74}, 33)
	}
}
func oheRejected(got c4Wire) bool {
	if got.message["error"] != nil {
		return true
	}
	result, _ := got.message["result"].(map[string]any)
	return result["isError"] == true
}

func TestOwnerHTTPEventsNativeAccessMalformedStartupR1(t *testing.T) {
	for _, state := range []string{"short", "long"} {
		t.Run(state, func(t *testing.T) {
			app, _, h, deps, _ := oheFixture(t, true)
			oheBreakAccess(h, oheAccessRef(t, h), state)
			bound := false
			deps.BeforeBind = func() { bound = true }
			puts := h.keys.n
			rt, err := startOwnerHTTP(context.Background(), app, "127.0.0.1:0", deps)
			if rt != nil {
				_ = rt.Close(context.Background())
			}
			if err == nil || bound {
				t.Errorf("malformed %s native access key admitted startup: err=%v bound=%v", state, err, bound)
			}
			if h.keys.n != puts {
				t.Fatal("malformed startup provisioned a credential")
			}
		})
	}
}

func TestOwnerHTTPEventsNativeAccessLostAfterStartupR1(t *testing.T) {
	for _, state := range []string{"missing", "denied", "short", "long"} {
		t.Run(state, func(t *testing.T) {
			app, _, h, deps, token := oheFixture(t, true)
			reads := &oheNativeReads{EventSecretProvider: h.keys}
			deps.Events.Secrets = reads
			rt := oheStart(t, app, h, deps)
			id := oheSub(t, rt.URL(), token, group.String())
			var beforeGeneration int64
			var beforeState string
			if err := app.store.db.QueryRow(`SELECT generation,state FROM mcp_event_subscriptions WHERE id=?`, id).Scan(&beforeGeneration, &beforeState); err != nil {
				t.Fatal(err)
			}
			puts := h.keys.n
			oheBreakAccess(h, oheAccessRef(t, h), state)
			beforeReads := reads.reads.Load()
			for _, name := range []string{"whatsapp_status", "list_chats", "list_school_groups"} {
				c4Success(t, oheRPC(rt.URL(), token, "tools/call", c4Params(name)))
			}
			if reads.reads.Load() != beforeReads {
				t.Error("ordinary archive/status/desired-list calls read native Events key")
			}
			if ready, err := rt.Service.Access(context.Background(), "status"); err == nil || ready.Enabled {
				t.Error("native access status treats unavailable or malformed credential as ready")
			}
			if got := oheRPC(rt.URL(), token, "events/list", c4Params("")); !oheRejected(got) {
				t.Error("unavailable/malformed native key still admits events/list")
			}
			raw, _ := json.Marshal(evReq(group.String(), ""))
			var p map[string]any
			_ = json.Unmarshal(raw, &p)
			p["_meta"] = c4Meta()
			if got := oheRPC(rt.URL(), token, "events/subscribe", p); !oheRejected(got) {
				t.Error("unavailable/malformed native key still admits callback challenge/subscription")
			}
			for _, name := range []string{"list_message_monitors", "pause_message_monitor", "resume_message_monitor", "stop_message_monitor"} {
				p := c4Params(name)
				p["arguments"] = map[string]any{"id": id}
				if name == "list_message_monitors" {
					p["arguments"] = map[string]any{}
				}
				if got := oheRPC(rt.URL(), token, "tools/call", p); !oheRejected(got) {
					t.Errorf("unavailable/malformed native key still admits %s", name)
				}
			}
			if got := oheRPC(rt.URL(), token, "events/unsubscribe", p); !oheRejected(got) {
				t.Error("unavailable/malformed native key still admits events/unsubscribe")
			}
			var afterGeneration int64
			var afterState string
			if err := app.store.db.QueryRow(`SELECT generation,state FROM mcp_event_subscriptions WHERE id=?`, id).Scan(&afterGeneration, &afterState); err != nil {
				t.Fatal(err)
			}
			if afterGeneration != beforeGeneration || afterState != beforeState {
				t.Errorf("invalid key mutated subscription: before=%d/%s after=%d/%s", beforeGeneration, beforeState, afterGeneration, afterState)
			}
			h.sender.mu.Lock()
			verifies := len(h.sender.verifyCalls)
			h.sender.mu.Unlock()
			if verifies != 1 || h.keys.n != puts {
				t.Errorf("invalid key caused callback challenge/native writes: challenges=%d puts=%d want=%d", verifies, h.keys.n, puts)
			}
		})
	}
}

func TestOwnerHTTPEventsNativeAccessQueuedWorkerR1(t *testing.T) {
	for _, state := range []string{"missing", "short", "long"} {
		t.Run(state, func(t *testing.T) {
			app, _, h, deps, token := oheFixture(t, true)
			reads := &oheNativeReads{EventSecretProvider: h.keys}
			deps.Events.Secrets = reads
			rt := oheStart(t, app, h, deps)
			_ = oheSub(t, rt.URL(), token, group.String())
			ref := oheAccessRef(t, h)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			reads.mu.Lock()
			reads.beforeGet = func(want string) {
				if want == ref {
					once.Do(func() { close(entered); <-release })
				}
			}
			reads.mu.Unlock()
			evLive(h, group, alice, "queued-access-"+state, h.clock.Now())
			spAwait(t, entered)
			oheBreakAccess(h, ref, state)
			close(release)
			evWait(t, "queued worker terminal attempt", func() bool {
				var n int
				_ = app.store.db.QueryRow(`SELECT count(*) FROM mcp_event_deliveries WHERE state!='leased' AND attempt_count>0`).Scan(&n)
				return n == 1
			})
			if len(h.sender.requests()) != 0 {
				t.Error("queued worker dispatched callback with unavailable/malformed native access key")
			}
		})
	}
}

// R2 retains the deterministic late-loss counterexample and covers both
// blocking external boundaries. These tests do not imply atomic revocation
// across native credentials and SQL after the last successful native check.
type oheStageKeysR2 struct {
	eventsecrets.EventSecretProvider
	mu       sync.Mutex
	afterPut func()
}

func (p *oheStageKeysR2) PutVersion(ctx context.Context, id string, key []byte) (string, error) {
	ref, err := p.EventSecretProvider.PutVersion(ctx, id, key)
	p.mu.Lock()
	hook := p.afterPut
	p.mu.Unlock()
	if err == nil && hook != nil {
		hook()
	}
	return ref, err
}

type oheSubscriptionR2 struct {
	State, Key, Old                          string
	Generation, Expires, Activated, Rotation int64
}

func oheSnapshotR2(t *testing.T, h *evHarness, id string) oheSubscriptionR2 {
	t.Helper()
	var out oheSubscriptionR2
	err := h.w.store.db.QueryRow(`SELECT state,key_ref,old_key_ref,generation,expires_at,activated_at,rotation_until FROM mcp_event_subscriptions WHERE id=?`, id).Scan(&out.State, &out.Key, &out.Old, &out.Generation, &out.Expires, &out.Activated, &out.Rotation)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	return out
}
func TestOwnerHTTPEventsNativeAccessLateLossR2(t *testing.T) {
	for _, boundary := range []string{"verification", "staging"} {
		for _, state := range []string{"missing", "denied", "short", "long", "grant-generation", "grant-reference"} {
			for _, refresh := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/refresh=%t", boundary, state, refresh), func(t *testing.T) {
					app, _, h, deps, token := oheFixture(t, true)
					keys := &oheStageKeysR2{EventSecretProvider: h.keys}
					deps.Events.Secrets = keys
					rt := oheStart(t, app, h, deps)
					request := evReq(group.String(), "")
					id := ""
					if refresh {
						id = oheSub(t, rt.URL(), token, group.String())
					}
					before := oheSnapshotR2(t, h, id)
					accessRef := oheAccessRef(t, h)
					callbackKeys := map[string][]byte{}
					h.keys.mu.Lock()
					puts := h.keys.n
					for ref, key := range h.keys.keys {
						if ref != accessRef {
							callbackKeys[ref] = append([]byte(nil), key...)
						}
					}
					h.keys.mu.Unlock()
					var boundaryErr error
					breakAccess := func() {
						switch state {
						case "grant-generation":
							_, boundaryErr = app.store.db.Exec(`UPDATE mcp_event_access SET generation=generation+1 WHERE profile_id=?`, h.cfg.ProfileID)
						case "grant-reference":
							// Keep a valid native value available under a different ref,
							// even with unchanged generation: the original ref is pinned.
							newRef := accessRef + "-changed"
							h.keys.mu.Lock()
							h.keys.keys[newRef] = bytes.Repeat([]byte{0x74}, 32)
							h.keys.mu.Unlock()
							_, boundaryErr = app.store.db.Exec(`UPDATE mcp_event_access SET key_ref=? WHERE profile_id=?`, newRef, h.cfg.ProfileID)
						default:
							oheBreakAccess(h, accessRef, state)
						}
					}
					if boundary == "verification" {
						h.sender.mu.Lock()
						h.sender.verifyHook = func(context.Context, string, string, string) error { breakAccess(); return boundaryErr }
						h.sender.mu.Unlock()
					} else {
						keys.mu.Lock()
						keys.afterPut = breakAccess
						keys.mu.Unlock()
					}
					// A changed callback key proves failed refresh cannot replace the
					// prior callback credential or generation.
					request.Delivery.Secret = "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
					raw, _ := json.Marshal(request)
					var p map[string]any
					_ = json.Unmarshal(raw, &p)
					p["_meta"] = c4Meta()
					got := oheRPC(rt.URL(), token, "events/subscribe", p)
					if boundaryErr != nil {
						t.Fatal(boundaryErr)
					}
					if !oheRejected(got) {
						t.Error("native access changed at late boundary but subscribe returned success")
					}
					if refresh {
						if after := oheSnapshotR2(t, h, id); after != before {
							t.Errorf("failed refresh replaced prior subscription: before=%+v after=%+v", before, after)
						}
					} else if n := evCount(t, h, "mcp_event_subscriptions"); n != 0 {
						t.Errorf("late access loss activated %d subscriptions", n)
					}
					if n := evCount(t, h, "mcp_event_staged_keys"); n != 0 {
						t.Errorf("failed activation retained %d staged SQL key references", n)
					}
					h.keys.mu.Lock()
					defer h.keys.mu.Unlock()
					wantPuts := puts
					if boundary == "staging" {
						wantPuts++
					}
					if h.keys.n != wantPuts {
						t.Errorf("late verification loss reached callback key staging: puts=%d want=%d", h.keys.n, wantPuts)
					}
					for ref, key := range h.keys.keys {
						if ref == accessRef || ref == accessRef+"-changed" {
							continue
						}
						if original, ok := callbackKeys[ref]; !ok || !bytes.Equal(key, original) {
							t.Error("failed activation retained or replaced native callback key")
						}
					}
					for ref, key := range callbackKeys {
						if !bytes.Equal(h.keys.keys[ref], key) {
							t.Error("failed refresh deleted prior native callback key")
						}
					}
				})
			}
		}
	}
}
