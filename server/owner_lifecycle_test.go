//go:build libsqlite3

package main

// SAME App proof using frozen B public JSON and provider fixtures. No private B
// types. The fixture tool bypasses only online account availability, never media
// DownloadAny/decrypt/HTTP or the owner listener's admission/cancellation path.
import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type ohDiscardCloser struct{}

func (ohDiscardCloser) Write(p []byte) (int, error) { return len(p), nil }
func (ohDiscardCloser) Close() error                { return nil }

type ohWire struct {
	out     map[string]any
	session string
	status  int
	err     error
}

func ohRPC(ctx context.Context, url, token, session, method string, id any, params any) ohWire {
	q := map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
	if id != nil {
		q["id"] = id
	}
	raw, _ := json.Marshal(q)
	r, e := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(raw))
	if e != nil {
		return ohWire{err: e}
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("X-WhatsApp-Owner-Authorization", token)
	if session != "" {
		r.Header.Set("Mcp-Session-Id", session)
		r.Header.Set("MCP-Protocol-Version", "2025-03-26")
	}
	resp, e := (&http.Client{Timeout: 3 * time.Second}).Do(r)
	if e != nil {
		return ohWire{err: e}
	}
	defer resp.Body.Close()
	raw, e = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := ohWire{session: resp.Header.Get("Mcp-Session-Id"), status: resp.StatusCode, err: e}
	if len(raw) > 0 && resp.StatusCode == 200 {
		if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.HasPrefix(line, "data: ") {
					raw = []byte(strings.TrimPrefix(line, "data: "))
					break
				}
			}
		}
		out.err = json.Unmarshal(raw, &out.out)
	}
	return out
}
func TestOwnerHTTPSameAppLifetime(t *testing.T) {
	for _, cancelTransfer := range []bool{false, true} {
		t.Run(fmt.Sprint("cancel=", cancelTransfer), func(t *testing.T) {
			app, cleanup, _ := evOwnedApp(t)
			w := app.wa
			_, plain, wire := spMediaRef(t, w, "document", "OWNER-HTTP-FIXTURE")
			message := archiveMessage(t, w, group, "OWNER-HTTP-FIXTURE")
			paused, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(r *http.Request) (*http.Response, error) {
				resp := spResponse(r, nil, -1)
				resp.Body = &spGateBody{ctx: r.Context(), data: wire, paused: paused, release: release}
				return resp, nil
			})})
			root, cancel := context.WithCancel(context.Background())
			defer cancel()
			key := bytes.Repeat([]byte{0x42}, 32)
			token := "Bearer " + base64.RawURLEncoding.EncodeToString(key)
			rt, err := startOwnerHTTP(root, app, "127.0.0.1:0", OwnerHTTPDependencies{ReadKey: func() ([]byte, error) { return key, nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer rt.Close(context.Background())
			if rt.Service != nil {
				t.Fatal("owner side listener created Events service")
			}
			mcp.AddTool(rt.Server, &mcp.Tool{Name: "fixture_owner_download"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]any, error) {
				defer close(finished)
				_, data, e := app.wa.DownloadMedia(ctx, message)
				if e != nil {
					return nil, nil, e
				}
				return nil, map[string]any{"plaintext_size": len(data)}, nil
			})
			url := rt.URL()
			init := ohRPC(root, url, token, "", "initialize", 1, map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "synthetic-owner-lifetime", "version": "1"}})
			if init.err != nil || init.status != 200 {
				t.Fatalf("initialize: %+v", init)
			}
			session := init.session
			ohRPC(root, url, token, session, "notifications/initialized", nil, map[string]any{})
			tools := ohRPC(root, url, token, session, "tools/list", 2, map[string]any{})
			if tools.err != nil || strings.Contains(fmt.Sprint(tools.out), "message_monitor") {
				t.Fatal("Events leaked", tools)
			}
			transfer := make(chan ohWire, 1)
			go func() {
				transfer <- ohRPC(context.Background(), url, token, session, "tools/call", 3, map[string]any{"name": "fixture_owner_download", "arguments": map[string]any{}})
			}()
			spAwait(t, paused)
			// Flush is the frozen B interface seam, not an internal progress type.
			spFlush(t, w)
			ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
			status := ohRPC(ctx, url, token, session, "tools/call", 4, map[string]any{"name": "whatsapp_status", "arguments": map[string]any{}})
			done()
			if status.err != nil || status.status != 200 {
				t.Fatalf("status blocked by transfer: %+v", status)
			}
			result := spObject(t, status.out, "result")
			progress := spObject(t, spObject(t, result, "structuredContent"), "sync_progress")
			media := spObject(t, progress, "media")
			spWant(t, media, "active_count", float64(1))
			jobs := media["jobs"].([]any)
			spWant(t, jobs[0].(map[string]any), "phase", "downloading")
			chat := ohRPC(context.Background(), url, token, session, "tools/call", 5, map[string]any{"name": "get_chat", "arguments": map[string]any{"chat": group.String()}})
			if chat.err != nil || chat.out["error"] != nil {
				t.Fatal("same store get_chat failed", chat)
			}
			if cancelTransfer {
				// C4 retires standalone GET sessions; request-scoped POST SSE and
				// its cancellation are exercised by TestOwnerHTTPModernRequestLifetimeC4.
				for _, method := range []string{"GET", "DELETE"} {
					req, _ := http.NewRequest(method, url, nil)
					req.Header.Set("Accept", "text/event-stream")
					req.Header.Set("Mcp-Session-Id", session)
					req.Header.Set("MCP-Protocol-Version", "2025-03-26")
					req.Header.Set(ownerHTTPHeader, token)
					response, e := (&http.Client{Timeout: 3 * time.Second}).Do(req)
					if e != nil {
						t.Fatal(e)
					}
					response.Body.Close()
					if response.StatusCode != 405 || response.Header.Get("Allow") != "POST" || response.Header.Get("Location") != "" {
						t.Fatalf("retired standalone method: %s status=%d headers=%v", method, response.StatusCode, response.Header)
					}
				}
				closed := make(chan error, 1)
				go func() { cancel(); closed <- rt.Close(context.Background()) }()
				select {
				case e := <-closed:
					if e != nil {
						t.Fatal(e)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("HTTP shutdown hung with admitted transfer")
				}
				select {
				case <-finished:
				default:
					t.Fatal("runtime close returned before admitted operation drained")
				}
				if _, e := app.store.db.Exec("SELECT 1"); e != nil {
					t.Fatal("listener closed owner DB before owner cleanup", e)
				}
				cleanup()
				if _, e := app.store.db.Exec("SELECT 1"); e == nil {
					t.Fatal("owner cleanup left DB open")
				}
				late := ohRPC(context.Background(), url, token, session, "tools/list", 6, map[string]any{})
				if late.err == nil && late.status == 200 {
					t.Fatal("listener accepted after close")
				}
			} else {
				close(release)
				spAwait(t, finished)
				select {
				case got := <-transfer:
					if got.err != nil || got.out["error"] != nil {
						t.Fatal(got)
					}
					size := spObject(t, spObject(t, got.out, "result"), "structuredContent")["plaintext_size"]
					if size != float64(len(plain)) {
						t.Fatalf("decrypt result size=%v", size)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("transfer failed to complete")
				}
			}
		})
	}
	// The same production application-level stdio lifecycle helper used by
	// runServe takes StdioTransport there and the SDK IOTransport here. EOF,
	// not explicit sideRuntime.Close/root cancellation, drives this shutdown.
	t.Run("stdio-eof", func(t *testing.T) {
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
		init := ohRPC(context.Background(), url, token, "", "initialize", 20, map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "synthetic-stdio-eof", "version": "1"}})
		if init.err != nil || init.status != 200 {
			t.Fatal(init)
		}
		session := init.session
		ohRPC(context.Background(), url, token, session, "notifications/initialized", nil, map[string]any{})
		transfer := make(chan ohWire, 1)
		go func() {
			transfer <- ohRPC(context.Background(), url, token, session, "tools/call", 21, map[string]any{"name": "fixture_owner_download", "arguments": map[string]any{}})
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
		late := ohRPC(context.Background(), url, token, session, "tools/list", 22, map[string]any{})
		if late.err == nil && late.status == 200 {
			t.Fatal("side HTTP accepted after controller EOF")
		}
	})
	// Real occupied bind: fatal start error, not an unauthenticated fallback.
	app, _, _ := evOwnedApp(t)
	occupied, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer occupied.Close()
	if rt, e := startOwnerHTTP(context.Background(), app, occupied.Addr().String(), OwnerHTTPDependencies{ReadKey: func() ([]byte, error) { return bytes.Repeat([]byte{0x42}, 32), nil }}); e == nil {
		if rt != nil {
			rt.Close(context.Background())
		}
		t.Fatal("bind failure did not fail startup")
	}
}
