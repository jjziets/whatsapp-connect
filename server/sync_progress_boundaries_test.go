//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"go.mau.fi/whatsmeow/proto/waE2E"
	"google.golang.org/protobuf/proto"
)

// Test-only access to the pinned provider's effective client. Guard exact field
// type before reading. This never changes provider code or production access.
func spProviderHTTP(t *testing.T, w *WA) *http.Client {
	t.Helper()
	if w.Client == nil {
		t.Fatal("nil provider client")
	}
	f := reflect.ValueOf(w.Client).Elem().FieldByName("mediaHTTP")
	if !f.IsValid() || f.Type() != reflect.TypeOf((*http.Client)(nil)) {
		t.Fatal("pinned provider mediaHTTP layout changed")
	}
	c := reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Interface().(*http.Client)
	if c == nil {
		t.Fatal("nil effective media client")
	}
	return c
}

// SP-13 retained policy regression: pinned provider clones http.DefaultTransport
// with no client timeout. Wrapping must preserve effective Proxy/TLS/transport
// settings. An observational wrapper can expose Unwrap, without private fields.
func TestSyncProgressDefaultProxyTLSPolicy(t *testing.T) {
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	base := old.(*http.Transport).Clone()
	proxy := func(*http.Request) (*url.URL, error) { return url.Parse("http://CANARY_PROXY.invalid:8080") }
	base.Proxy = proxy
	base.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "CANARY_TLS.invalid"}
	base.TLSHandshakeTimeout = 7 * time.Second
	base.ResponseHeaderTimeout = 11 * time.Second
	base.MaxIdleConns = 13
	http.DefaultTransport = base
	w, _ := archiveFixture(t)
	client := spProviderHTTP(t, w)
	if client.Timeout != 0 {
		t.Fatal("default media client timeout changed")
	}
	transport := client.Transport
	for i := 0; i < 4; i++ {
		wrapper, ok := transport.(interface{ Unwrap() http.RoundTripper })
		if !ok {
			break
		}
		transport = wrapper.Unwrap()
	}
	actual, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("effective default transport not preserved: %T", transport)
	}
	if actual == base {
		t.Error("effective media transport must clone mutable default policy")
	}
	if actual.Proxy == nil || reflect.ValueOf(actual.Proxy).Pointer() != reflect.ValueOf(proxy).Pointer() {
		t.Error("proxy function dropped")
	}
	if actual.TLSClientConfig == nil || actual.TLSClientConfig.MinVersion != tls.VersionTLS13 || actual.TLSClientConfig.ServerName != "CANARY_TLS.invalid" {
		t.Error("effective TLS policy dropped")
	}
	if actual.TLSHandshakeTimeout != 7*time.Second || actual.ResponseHeaderTimeout != 11*time.Second || actual.MaxIdleConns != 13 {
		t.Error("effective transport limits dropped")
	}
}

// SP-13: an actual provider history-media request without an operation token
// must not create an attachment job or attribute its bytes to another job.
func TestSyncProgressTokenlessHistoryExcluded(t *testing.T) {
	w, _ := archiveFixture(t)
	blob := []byte("synthetic-history-download-body")
	hash := sha256.Sum256(blob)
	spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(r *http.Request) (*http.Response, error) { return spResponse(r, blob, int64(len(blob))), nil })})
	notification := &waE2E.HistorySyncNotification{DirectPath: proto.String("/CANARY_HISTORY?fixture=1"), FileSHA256: hash[:]}
	got, err := w.Client.Download(context.Background(), notification)
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("actual provider history fixture: %v", err)
	}
	media := spObject(t, spObject(t, spStatus(t, &App{store: w.store, wa: w, mode: "fixture"}), "sync_progress"), "media")
	spWant(t, media, "active_count", float64(0))
	jobs, ok := media["jobs"].([]any)
	if !ok || len(jobs) != 0 {
		t.Errorf("tokenless history attributed to attachment jobs: %v", media)
	}
}

// SP-03/05/06: deterministic tick/drain handshake observes real committed
// history counters at 1Hz. Repeated in-flight ticks at the same time cannot
// rewrite the snapshot. Terminal remains immediate; a stopped publisher cannot
// write after DB/owner release, even if another tick becomes ready.
func TestSyncProgressCoalescingHeartbeatStopHandshake(t *testing.T) {
	app, cleanup, dir := evOwnedApp(t)
	w := app.wa
	reader := spReader(t, dbPath(dir))
	control, ok := any(w).(interface {
		setProgressTestClock(func() time.Time, <-chan time.Time)
		flushSyncProgress(context.Context) error
	})
	if !ok {
		t.Fatal("MISSING INERT SEAM: progress clock/flush")
	}
	observer, ok := any(w).(interface{ setHistoryCheckpoint(func()) })
	if !ok {
		t.Fatal("MISSING INERT SEAM: history checkpoint")
	}
	now := time.Now().UTC()
	var mu sync.Mutex
	ticks := make(chan time.Time, 8)
	control.setProgressTestClock(func() time.Time { mu.Lock(); defer mu.Unlock(); return now }, ticks)
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		at := now
		mu.Unlock()
		ticks <- at
		if err := control.flushSyncProgress(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	var checkpoint atomic.Int32
	reached := make(chan struct{}, 2)
	resume := make(chan struct{}, 2)
	defer close(resume)
	observer.setHistoryCheckpoint(func() {
		if checkpoint.Add(1) <= 2 {
			reached <- struct{}{}
			<-resume
		}
	})
	done := make(chan struct{})
	go func() {
		w.ingestHistory(context.Background(), archiveChunk(group, archiveWeb(group, alice, "SP-COAL-1", t0, archiveText("one")), archiveWeb(group, alice, "SP-COAL-2", t0, archiveText("two")), archiveWeb(group, alice, "SP-COAL-3", t0, archiveText("three"))))
		close(done)
	}()
	spAwait(t, reached)
	advance(time.Second)
	snapshot := spMeta(t, reader.store, "sync_progress_v1")
	firstRevision := snapshot["revision"].(float64)
	counts := spObject(t, spObject(t, snapshot, "history"), "processing")
	spWant(t, counts, "processed_messages", float64(1))
	resume <- struct{}{}
	spAwait(t, reached)
	advance(0)
	advance(0)
	if current := spMeta(t, reader.store, "sync_progress_v1")["revision"]; current != firstRevision {
		t.Error("in-flight publication exceeded 1Hz")
	}
	advance(time.Second)
	snapshot = spMeta(t, reader.store, "sync_progress_v1")
	if snapshot["revision"].(float64) <= firstRevision {
		t.Error("eligible progress tick lost")
	}
	counts = spObject(t, spObject(t, snapshot, "history"), "processing")
	spWant(t, counts, "processed_messages", float64(2))
	resume <- struct{}{}
	spAwait(t, done)
	if err := control.flushSyncProgress(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot = spMeta(t, reader.store, "sync_progress_v1")
	history := spObject(t, snapshot, "history")
	spWant(t, history, "phase", "idle")
	spWant(t, spObject(t, history, "processing"), "processed_messages", float64(3))
	revision := snapshot["revision"].(float64)
	advance(5 * time.Second)
	snapshot = spMeta(t, reader.store, "sync_progress_v1")
	if snapshot["revision"].(float64) <= revision {
		t.Error("idle owner heartbeat did not advance")
	}
	cleanup()
	stopped := spMeta(t, reader.store, "sync_progress_v1")
	spWant(t, spObject(t, stopped, "owner"), "stopped", true)
	mu.Lock()
	now = now.Add(5 * time.Second)
	at := now
	mu.Unlock()
	ticks <- at
	_ = control.flushSyncProgress(context.Background())
	if got := spMeta(t, reader.store, "sync_progress_v1")["revision"]; got != stopped["revision"] {
		t.Error("stopped publisher wrote after owner cleanup")
	}
}
