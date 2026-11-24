//go:build libsqlite3

package main

// C4: same owner, real SDK HTTP wire, synthetic credentials/profile/provider.
// No online-account override or native credential operation is used.
import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const c4Version = "2026-07-28"

type c4Wire struct {
	status  int
	headers http.Header
	message map[string]any
	body    string
	err     error
}

func c4Meta() map[string]any {
	return map[string]any{"io.modelcontextprotocol/protocolVersion": c4Version, "io.modelcontextprotocol/clientCapabilities": map[string]any{}, "io.modelcontextprotocol/clientInfo": map[string]any{"name": "synthetic-c4", "version": "1"}}
}
func c4Params(name string) map[string]any {
	p := map[string]any{"_meta": c4Meta()}
	if name != "" {
		p["name"] = name
		p["arguments"] = map[string]any{}
	}
	return p
}
func c4Request(ctx context.Context, url, token, version, method string, params map[string]any) *http.Request {
	q := map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
	if !strings.HasPrefix(method, "notifications/") {
		q["id"] = 1
	}
	raw, _ := json.Marshal(q)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(raw))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(ownerHTTPHeader, token)
	req.Header.Set("Authorization", "Bearer unrelated-synthetic")
	if version != "" {
		req.Header.Set("MCP-Protocol-Version", version)
	}
	req.Header.Set("Mcp-Method", method)
	if name, ok := params["name"].(string); ok {
		req.Header.Set("Mcp-Name", name)
	}
	return req
}
func c4Do(req *http.Request) c4Wire {
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return c4Wire{err: err}
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	out := c4Wire{status: response.StatusCode, headers: response.Header.Clone(), body: string(raw), err: err}
	if len(raw) == 0 {
		return out
	}
	if strings.Contains(response.Header.Get("Content-Type"), "text/event-stream") {
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "data: ") {
				var message map[string]any
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &message) == nil && message["id"] != nil {
					out.message = message
				}
			}
		}
	} else if strings.Contains(response.Header.Get("Content-Type"), "application/json") {
		out.err = json.Unmarshal(raw, &out.message)
	}
	return out
}
func c4RPC(ctx context.Context, url, token, method string, params map[string]any) c4Wire {
	return c4Do(c4Request(ctx, url, token, c4Version, method, params))
}
func c4Code(result c4Wire) float64 {
	if e, ok := result.message["error"].(map[string]any); ok {
		if code, ok := e["code"].(float64); ok {
			return code
		}
	}
	return 0
}
func c4Success(t *testing.T, result c4Wire) bool {
	t.Helper()
	if result.err != nil || result.status != 200 || result.message == nil || result.message["result"] == nil || result.message["error"] != nil {
		t.Errorf("modern wire failed: status=%d code=%v err=%v body=%s", result.status, c4Code(result), result.err, result.body)
		return false
	}
	if result.headers.Get("Mcp-Session-Id") != "" {
		t.Error("stateless owner minted HTTP session")
	}
	return true
}
func c4Media(t *testing.T, result c4Wire) map[string]any {
	t.Helper()
	return spObject(t, spObject(t, spObject(t, spObject(t, result.message, "result"), "structuredContent"), "sync_progress"), "media")
}

func TestOwnerHTTPProtocolC4(t *testing.T) {
	app, _, _ := evOwnedApp(t)
	archiveIngest(t, app.wa, group, alice, "C4-CONTEXT", t0, archiveText("synthetic protocol fixture"), false)
	key := bytes.Repeat([]byte{0x42}, 32)
	token := "Bearer " + base64.RawURLEncoding.EncodeToString(key)
	rt, err := startOwnerHTTP(context.Background(), app, "127.0.0.1:0", OwnerHTTPDependencies{ReadKey: func() ([]byte, error) { return key, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	url := rt.URL()
	if rt.Service != nil {
		t.Fatal("C4 created Events service")
	}
	t.Run("modern-no-initialize", func(t *testing.T) {
		c4Success(t, c4RPC(context.Background(), url, token, "tools/call", c4Params("whatsapp_status")))
		chat := c4Params("get_chat")
		chat["arguments"] = map[string]any{"chat": group.String()}
		c4Success(t, c4RPC(context.Background(), url, token, "tools/call", chat))
		tools := c4RPC(context.Background(), url, token, "tools/list", c4Params(""))
		if c4Success(t, tools) {
			list := spObject(t, tools.message, "result")["tools"].([]any)
			names := []string{}
			for _, item := range list {
				names = append(names, item.(map[string]any)["name"].(string))
			}
			sort.Strings(names)
			want := []string{"download_media", "get_chat", "get_message_context", "get_send_status", "list_chats", "list_messages", "list_school_groups", "update_school_groups", "prepare_media_forward", "prepare_message", "request_older_history", "search_contacts", "search_messages", "whatsapp_status"}
			sort.Strings(want)
			if strings.Join(names, ",") != strings.Join(want, ",") {
				t.Fatalf("tool registry changed: %v", names)
			}
		}
		discover := c4RPC(context.Background(), url, token, "server/discover", c4Params(""))
		if c4Success(t, discover) {
			result := spObject(t, discover.message, "result")
			if !strings.Contains(fmt.Sprint(result["supportedVersions"]), c4Version) {
				t.Errorf("modern version not advertised: %v", result)
			}
			if strings.Contains(fmt.Sprint(result), "message_monitor") {
				t.Fatal("Events advertised")
			}
		}
	})
	t.Run("purpose-auth-before-SDK", func(t *testing.T) {
		for _, values := range [][]string{nil, {"Bearer wrong"}, {token, token}, {token + ", " + token}, {token + "="}, {"Basic bad"}} {
			req := c4Request(context.Background(), url, token, c4Version, "tools/call", c4Params("whatsapp_status"))
			req.Header.Del(ownerHTTPHeader)
			for _, v := range values {
				req.Header.Add(ownerHTTPHeader, v)
			}
			got := c4Do(req)
			if got.status != 401 {
				t.Fatalf("reserved auth admitted before SDK: %d", got.status)
			}
		}
		for _, path := range []string{"/mcp", "/", "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"} {
			for _, method := range []string{"POST", "GET", "DELETE"} {
				req := c4Request(context.Background(), strings.TrimSuffix(url, "/mcp")+path, "Bearer wrong", c4Version, "tools/call", c4Params("whatsapp_status"))
				req.Method = method
				got := c4Do(req)
				if got.status != 401 || got.headers.Get("Location") != "" {
					t.Fatalf("unprotected/redirected route: %s %s %d", method, path, got.status)
				}
			}
		}
	})
	t.Run("SDK-metadata-validation", func(t *testing.T) {
		for _, which := range []string{"version-mismatch", "missing-version", "missing-capabilities", "method-mismatch", "name-mismatch", "future-version"} {
			t.Run(which, func(t *testing.T) {
				params := c4Params("whatsapp_status")
				meta := params["_meta"].(map[string]any)
				version := c4Version
				want := -32020.0
				switch which {
				case "version-mismatch":
					meta["io.modelcontextprotocol/protocolVersion"] = "2025-11-25"
				case "missing-version":
					delete(meta, "io.modelcontextprotocol/protocolVersion")
					want = -32602
				case "missing-capabilities":
					delete(meta, "io.modelcontextprotocol/clientCapabilities")
					want = -32602
				case "future-version":
					version = "2099-01-01"
					meta["io.modelcontextprotocol/protocolVersion"] = version
					want = -32022
				}
				req := c4Request(context.Background(), url, token, version, "tools/call", params)
				if which == "method-mismatch" {
					req.Header.Set("Mcp-Method", "tools/list")
				}
				if which == "name-mismatch" {
					req.Header.Set("Mcp-Name", "wrong_tool")
				}
				got := c4Do(req)
				if got.err != nil || got.status != 400 || c4Code(got) != want {
					t.Errorf("invalid protocol metadata: status=%d code=%v want=%v err=%v body=%s", got.status, c4Code(got), want, got.err, got.body)
				}
				if which == "future-version" && c4Code(got) == want {
					data := spObject(t, spObject(t, got.message, "error"), "data")
					if data["requested"] != version || !strings.Contains(fmt.Sprint(data["supported"]), c4Version) {
						t.Errorf("future version rewritten or modern support absent: %v", data)
					}
				}
			})
		}
	})
	t.Run("no-standalone-stream-or-session", func(t *testing.T) {
		for _, method := range []string{"GET", "DELETE"} {
			req := c4Request(context.Background(), url, token, c4Version, "tools/list", c4Params(""))
			req.Method = method
			req.Header.Set("Mcp-Session-Id", "irrelevant-synthetic")
			got := c4Do(req)
			if got.status != 405 || got.headers.Get("Allow") != "POST" || got.headers.Get("Mcp-Session-Id") != "" || got.headers.Get("Location") != "" {
				t.Errorf("C4 standalone method/session contract: %s status=%d headers=%v", method, got.status, got.headers)
			}
		}
	})
	t.Run("legacy-POST-compatibility", func(t *testing.T) {
		for _, version := range []string{"2025-03-26", "2025-11-25"} {
			t.Run(version, func(t *testing.T) {
				init := c4Do(c4Request(context.Background(), url, token, version, "initialize", map[string]any{"protocolVersion": version, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "synthetic-legacy", "version": "1"}}))
				if init.status != 200 || init.err != nil {
					t.Fatalf("legacy initialize: %+v", init)
				}
				if init.headers.Get("Mcp-Session-Id") != "" {
					t.Error("legacy stateless POST minted persistent session")
				}
				notify := c4Do(c4Request(context.Background(), url, token, version, "notifications/initialized", map[string]any{}))
				if notify.status != 202 {
					t.Errorf("legacy initialized: %d", notify.status)
				}
				tools := c4Do(c4Request(context.Background(), url, token, version, "tools/list", map[string]any{}))
				if tools.status != 200 || tools.message["error"] != nil {
					t.Errorf("legacy POST tools: %+v", tools)
				}
				done := make(chan c4Wire, 2)
				for _, name := range []string{"whatsapp_status", "get_chat"} {
					go func(name string) {
						args := map[string]any{}
						if name == "get_chat" {
							args["chat"] = group.String()
						}
						done <- c4Do(c4Request(context.Background(), url, token, version, "tools/call", map[string]any{"name": name, "arguments": args}))
					}(name)
				}
				for range 2 {
					got := <-done
					if got.status != 200 || got.err != nil || got.message["error"] != nil {
						t.Errorf("concurrent legacy POST: %+v", got)
					}
				}
			})
		}
	})
}

func TestOwnerHTTPModernRequestLifetimeC4(t *testing.T) {
	for _, trigger := range []string{"client_disconnect", "root_cancel"} {
		t.Run(trigger, func(t *testing.T) {
			app, _, _ := evOwnedApp(t)
			message, _, wire := spMediaRef(t, app.wa, "document", "C4-DISCONNECT")
			paused, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			providerCanceled := make(chan struct{})
			var providerCancelOnce sync.Once
			spInstallMedia(t, app.wa, &http.Client{Transport: spRoundTrip(func(req *http.Request) (*http.Response, error) {
				context.AfterFunc(req.Context(), func() { providerCancelOnce.Do(func() { close(providerCanceled) }) })
				response := spResponse(req, nil, -1)
				response.Body = &spGateBody{ctx: req.Context(), data: wire, paused: paused, release: release}
				return response, nil
			})})
			ownerCtx, stopOwner := context.WithCancel(context.Background())
			defer stopOwner()
			key := bytes.Repeat([]byte{0x42}, 32)
			token := "Bearer " + base64.RawURLEncoding.EncodeToString(key)
			rt, err := startOwnerHTTP(ownerCtx, app, "127.0.0.1:0", OwnerHTTPDependencies{ReadKey: func() ([]byte, error) { return key, nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer rt.Close(context.Background())
			finished := make(chan error, 1)
			mcp.AddTool(rt.Server, &mcp.Tool{Name: "fixture_c4_download"}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]any, error) {
				_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: "c4-progress", Progress: 0, Total: 1})
				_, _, err := app.wa.DownloadMedia(ctx, message)
				finished <- err
				return nil, map[string]any{}, err
			})
			requestCtx, disconnect := context.WithCancel(context.Background())
			defer disconnect()
			params := c4Params("fixture_c4_download")
			params["_meta"].(map[string]any)["progressToken"] = "c4-progress"
			headers := make(chan *http.Response, 1)
			streamDone := make(chan error, 1)
			go func() {
				response, err := (&http.Client{Timeout: 5 * time.Second}).Do(c4Request(requestCtx, rt.URL(), token, c4Version, "tools/call", params))
				if err != nil {
					streamDone <- err
					return
				}
				headers <- response
				_, err = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				streamDone <- err
			}()
			spAwait(t, paused)
			var response *http.Response
			select {
			case response = <-headers:
			case err := <-streamDone:
				t.Fatalf("POST SSE failed before admission: %v", err)
			case <-time.After(time.Second):
				t.Fatal("POST did not establish request-scoped SSE")
			}
			if response.StatusCode != 200 || !strings.Contains(response.Header.Get("Content-Type"), "text/event-stream") || response.Header.Get("Mcp-Session-Id") != "" {
				t.Fatalf("modern POST stream: status=%d headers=%v", response.StatusCode, response.Header)
			}
			spFlush(t, app.wa)
			status := c4RPC(context.Background(), rt.URL(), token, "tools/call", c4Params("whatsapp_status"))
			if !c4Success(t, status) {
				return
			}
			media := c4Media(t, status)
			spWant(t, media, "active_count", float64(1))
			jobs := media["jobs"].([]any)
			spWant(t, jobs[0].(map[string]any), "phase", "downloading")
			if trigger == "client_disconnect" {
				disconnect()
				response.Body.Close()
			} else {
				stopOwner()
			}
			select {
			case err := <-finished:
				if err == nil {
					t.Error("cancelled provider transfer succeeded")
				}
			case <-time.After(1200 * time.Millisecond):
				t.Error("HTTP disconnect did not cancel admitted media work while owner stayed alive")
				stopOwner()
				select {
				case <-finished:
				case <-time.After(2 * time.Second):
					t.Fatal("owner cleanup could not drain media after failed disconnect assertion")
				}
				return
			}
			select {
			case <-providerCanceled:
			case <-time.After(time.Second):
				t.Error("actual provider request context survived cancellation")
			}
			select {
			case <-streamDone:
			case <-time.After(time.Second):
				t.Error("POST SSE survived cancellation")
			}
			path := filepath.Join(app.wa.dataDir, "media", safeName(message.ChatJID), safeName(message.ID)+extensionFor(message))
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Error("partial media published as completed artifact")
			}
			if _, err := app.store.db.Exec("SELECT 1"); err != nil {
				t.Fatal("request/listener cancellation closed owner DB before cleanup", err)
			}
			if trigger == "client_disconnect" {
				after := c4RPC(context.Background(), rt.URL(), token, "tools/call", c4Params("whatsapp_status"))
				if c4Success(t, after) {
					media := c4Media(t, after)
					spWant(t, media, "active_count", float64(0))
					jobs := media["jobs"].([]any)
					spWant(t, jobs[0].(map[string]any), "phase", "cancelled")
				}
				if ownerCtx.Err() != nil {
					t.Fatal("one request cancellation stopped the owner")
				}
			}
		})
	}
}

func TestOwnerHTTPModernStdioEOFC4(t *testing.T) {
	app, cleanup, _ := evOwnedApp(t)
	w := app.wa
	message, _, wire := spMediaRef(t, w, "document", "OWNER-STDIO-EOF")
	paused, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(release)
	spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(r *http.Request) (*http.Response, error) {
		response := spResponse(r, nil, -1)
		response.Body = &spGateBody{ctx: r.Context(), data: wire, paused: paused, release: release}
		return response, nil
	})})
	input, controller := io.Pipe()
	defer input.Close()
	defer controller.Close()
	ready, returned, cleaned := make(chan string, 1), make(chan error, 1), make(chan bool, 1)
	key := bytes.Repeat([]byte{0x42}, 32)
	token := "Bearer " + base64.RawURLEncoding.EncodeToString(key)
	lifecycleCleanup := func() {
		select {
		case <-finished:
			cleaned <- true
		default:
			cleaned <- false
		}
		cleanup()
	}
	go func() {
		returned <- serveOwnedStdio(context.Background(), app, lifecycleCleanup, &mcp.IOTransport{Reader: input, Writer: ohDiscardCloser{}}, "127.0.0.1:0", OwnerHTTPDependencies{
			ReadKey: func() ([]byte, error) { return key, nil },
			OnReady: func(url string, server *mcp.Server) {
				mcp.AddTool(server, &mcp.Tool{Name: "fixture_owner_download"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]any, error) {
					defer close(finished)
					_, _, e := app.wa.DownloadMedia(ctx, message)
					return nil, map[string]any{}, e
				})
				ready <- url
			},
		})
	}()
	var url string
	select {
	case url = <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("stdio lifecycle did not bind side listener")
	}

	transfer := make(chan c4Wire, 1)
	go func() {
		transfer <- c4RPC(context.Background(), url, token, "tools/call", c4Params("fixture_owner_download"))
	}()
	spAwait(t, paused)
	// Authoritative controller EOF is the sole lifecycle shutdown trigger.
	if e := controller.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("stdio EOF did not finish side listener drain and owner cleanup")
	}
	select {
	case drained := <-cleaned:
		if !drained {
			t.Fatal("owner cleanup ran before HTTP admitted operation finished")
		}
	default:
		t.Fatal("stdio EOF skipped owner cleanup")
	}
	select {
	case <-finished:
	default:
		t.Fatal("HTTP transfer survived stdio EOF")
	}
	if _, e := app.store.db.Exec("SELECT 1"); e == nil {
		t.Fatal("stdio lifecycle returned before DB cleanup")
	}
	late := c4RPC(context.Background(), url, token, "tools/list", c4Params(""))
	if late.err == nil && late.status == 200 {
		t.Fatal("side HTTP accepted after controller EOF")
	}
}
