//go:build libsqlite3

package main

// Actual pinned-provider fixture. All bytes, keys, hosts and references are
// synthetic. No socket is opened; DownloadAny still does decrypt/hash checking.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/util/hkdfutil"
	"google.golang.org/protobuf/proto"
)

type spRoundTrip func(*http.Request) (*http.Response, error)

func (f spRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Pinned DownloadAny needs cached media-host metadata before reaching HTTP.
// There is no exported setter. Seed that private cache only, before concurrent
// work; do not replace DownloadAny, edit dependency code, or query a real server.
func spSeedProviderHost(t *testing.T, w *WA, hostnames ...string) {
	t.Helper()
	if w.Client == nil {
		t.Fatal("nil pinned provider client")
	}
	f := reflect.ValueOf(w.Client).Elem().FieldByName("mediaConnCache")
	if !f.IsValid() || f.Type() != reflect.TypeOf((*whatsmeow.MediaConn)(nil)) {
		t.Fatal("pinned provider mediaConnCache layout changed")
	}
	if len(hostnames) == 0 {
		hostnames = []string{"CANARY_MEDIA.invalid"}
	}
	hosts := make([]whatsmeow.MediaConnHost, 0, len(hostnames))
	for _, hostname := range hostnames {
		hosts = append(hosts, whatsmeow.MediaConnHost{Hostname: hostname})
	}
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(reflect.ValueOf(&whatsmeow.MediaConn{FetchedAt: time.Now(), TTL: 3600, Hosts: hosts}))
}
func spInstallMedia(t *testing.T, w *WA, client *http.Client, hostnames ...string) {
	t.Helper()
	spSeedProviderHost(t, w, hostnames...)
	// This production seam must preserve the effective client configuration and
	// wrap its transport. Baseline fallback uses the supported provider setter,
	// so stream/integrity assertions execute rather than reporting compile RED.
	if h, ok := any(w).(interface{ setMediaHTTPClient(*http.Client) }); ok {
		h.setMediaHTTPClient(client)
	} else {
		w.Client.SetMediaHTTPClient(client)
	}
}
func spFlush(t *testing.T, w *WA) {
	t.Helper()
	if f, ok := any(w).(interface{ flushSyncProgress(context.Context) error }); ok {
		if err := f.flushSyncProgress(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}
func spMediaJob(t *testing.T, w *WA) map[string]any {
	t.Helper()
	spFlush(t, w)
	m := spObject(t, spObject(t, spStatus(t, &App{store: w.store, wa: w, mode: "test"}), "sync_progress"), "media")
	jobs, ok := m["jobs"].([]any)
	if !ok || len(jobs) == 0 {
		t.Fatalf("missing observed media job: %v", m)
	}
	return jobs[0].(map[string]any)
}
func spEncrypted(t *testing.T, kind, id string) (*waE2E.Message, []byte, []byte) {
	t.Helper()
	plain := append([]byte("synthetic "+kind+" fixture: "), bytes.Repeat([]byte{0x6b}, 149)...)
	key := bytes.Repeat([]byte{0x31}, 32)
	info := map[string]whatsmeow.MediaType{"image": whatsmeow.MediaImage, "audio": whatsmeow.MediaAudio, "document": whatsmeow.MediaDocument}[kind]
	expanded := hkdfutil.SHA256(key, nil, []byte(info), 112)
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(padding)}, padding)...)
	block, err := aes.NewCipher(expanded[16:48])
	if err != nil {
		t.Fatal(err)
	}
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, expanded[:16]).CryptBlocks(encrypted, padded)
	mac := hmac.New(sha256.New, expanded[48:80])
	mac.Write(expanded[:16])
	mac.Write(encrypted)
	wire := append(encrypted, mac.Sum(nil)[:10]...)
	hash := sha256.Sum256(plain)
	encHash := sha256.Sum256(wire)
	path := proto.String("/CANARY_PRIVATE_PATH?fixture=" + id)
	mime := proto.String(map[string]string{"image": "image/jpeg", "audio": "audio/ogg", "document": "application/pdf"}[kind])
	size := proto.Uint64(uint64(len(plain)))
	msg := &waE2E.Message{}
	switch kind {
	case "image":
		msg.ImageMessage = &waE2E.ImageMessage{DirectPath: path, MediaKey: key, FileSHA256: hash[:], FileEncSHA256: encHash[:], FileLength: size, Mimetype: mime}
	case "audio":
		msg.AudioMessage = &waE2E.AudioMessage{DirectPath: path, MediaKey: key, FileSHA256: hash[:], FileEncSHA256: encHash[:], FileLength: size, Mimetype: mime, PTT: proto.Bool(true)}
	case "document":
		msg.DocumentMessage = &waE2E.DocumentMessage{DirectPath: path, MediaKey: key, FileSHA256: hash[:], FileEncSHA256: encHash[:], FileLength: size, Mimetype: mime, FileName: proto.String("CANARY_PRIVATE_FILENAME.pdf")}
	default:
		t.Fatal("unknown fixture kind")
	}
	return msg, plain, wire
}
func spMediaRef(t *testing.T, w *WA, kind, id string) (*MessageRow, []byte, []byte) {
	t.Helper()
	msg, plain, wire := spEncrypted(t, kind, id)
	archiveIngest(t, w, group, alice, id, t0, msg, false)
	return archiveMessage(t, w, group, id), plain, wire
}
func spResponse(req *http.Request, data []byte, length int64) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: length, Body: io.NopCloser(bytes.NewReader(data)), Request: req}
}

// Gate occurs after the first actual Read returned bytes and before a second
// Read can reach EOF. Assertions are made while this barrier remains closed.
type spGateBody struct {
	ctx     context.Context
	data    []byte
	sent    bool
	paused  chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (b *spGateBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		n := copy(p, b.data[:16])
		b.data = b.data[n:]
		return n, nil
	}
	b.once.Do(func() { close(b.paused) })
	select {
	case <-b.release:
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	}
	if len(b.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}
func (*spGateBody) Close() error { return nil }
func spAwait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("fixture boundary not reached")
	}
}

type spDownloadResult struct {
	path string
	data []byte
	err  error
}

func spStartDownload(w *WA, ctx context.Context, m *MessageRow) <-chan spDownloadResult {
	ch := make(chan spDownloadResult, 1)
	go func() { p, b, e := w.DownloadMedia(ctx, m); ch <- spDownloadResult{p, b, e} }()
	return ch
}
func spResult(t *testing.T, ch <-chan spDownloadResult) spDownloadResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("download did not terminate")
		return spDownloadResult{}
	}
}

// SP-04/13: real image/audio/PDF cipher bodies, before-EOF progress, unknown
// HTTP lengths, and the completed plaintext boundary. Wire size differs from
// archive plaintext size, making accidental denominator reuse observable.
func TestSyncProgressPinnedProviderStreaming(t *testing.T) {
	for _, kind := range []string{"image", "audio", "document"} {
		t.Run(kind, func(t *testing.T) {
			w, _ := archiveFixture(t)
			m, plain, wire := spMediaRef(t, w, kind, "SP-STREAM")
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			paused := make(chan struct{})
			spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(r *http.Request) (*http.Response, error) {
				resp := spResponse(r, nil, -1)
				resp.Body = &spGateBody{ctx: r.Context(), data: wire, paused: paused, release: release}
				return resp, nil
			})})
			done := spStartDownload(w, context.Background(), m)
			spAwait(t, paused)
			func() {
				defer unblock()
				job := spMediaJob(t, w)
				spWant(t, job, "phase", "downloading")
				spWant(t, job, "per_attempt_bytes", float64(16))
				spWant(t, job, "cumulative_received_bytes", float64(16))
				spWant(t, job, "expected_attempt_bytes", nil)
				spWant(t, job, "completed_plaintext_bytes", nil)
			}()
			got := spResult(t, done)
			if got.err != nil || !bytes.Equal(got.data, plain) {
				t.Fatalf("provider result mismatch: %v", got.err)
			}
			saved, err := os.ReadFile(got.path)
			if err != nil || !bytes.Equal(saved, plain) {
				t.Fatal("complete before valid final save")
			}
			job := spMediaJob(t, w)
			spWant(t, job, "phase", "complete")
			spWant(t, job, "completed_plaintext_bytes", float64(len(plain)))
			spWant(t, job, "cumulative_received_bytes", float64(len(wire)))
		})
	}
}

type spNetworkFailure struct{}

func (spNetworkFailure) Error() string   { return "CANARY_PRIVATE_NETWORK_ERROR" }
func (spNetworkFailure) Timeout() bool   { return true }
func (spNetworkFailure) Temporary() bool { return true }

type spFailBody struct{ sent bool }

func (b *spFailBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, []byte("failed-attempt")), nil
	}
	return 0, spNetworkFailure{}
}
func (*spFailBody) Close() error { return nil }

// SP-04/06/13: retry attempts are produced by the actual pinned provider, not
// manually simulated counter calls. One retry waits its pinned 1-second delay.
func TestSyncProgressPinnedRetryIntegrityCancel(t *testing.T) {
	t.Run("retry", func(t *testing.T) {
		w, _ := archiveFixture(t)
		m, plain, wire := spMediaRef(t, w, "image", "SP-RETRY")
		var attempts atomic.Int32
		paused := make(chan struct{})
		release := make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		defer unblock()
		spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(r *http.Request) (*http.Response, error) {
			if attempts.Add(1) == 1 {
				resp := spResponse(r, nil, -1)
				resp.Body = &spFailBody{}
				return resp, nil
			}
			resp := spResponse(r, nil, int64(len(wire)+9))
			resp.Body = &spGateBody{ctx: r.Context(), data: wire, paused: paused, release: release}
			return resp, nil
		})})
		done := spStartDownload(w, context.Background(), m)
		spAwait(t, paused)
		job := spMediaJob(t, w)
		spWant(t, job, "current_attempt", float64(2))
		spWant(t, job, "per_attempt_bytes", float64(16))
		spWant(t, job, "cumulative_received_bytes", float64(len("failed-attempt")+16))
		// Release before waiting; close once here and replace deferred ownership.
		unblock()
		got := spResult(t, done)
		if got.err != nil || !bytes.Equal(got.data, plain) {
			t.Fatalf("retry result %v", got.err)
		}
		job = spMediaJob(t, w)
		spWant(t, job, "phase", "complete")
		spWant(t, job, "expected_attempt_bytes", nil)
		spWant(t, job, "cumulative_received_bytes", float64(len("failed-attempt")+len(wire)))
	})
	for _, scenario := range []string{"corrupt", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			w, _ := archiveFixture(t)
			m, _, wire := spMediaRef(t, w, "audio", "SP-NEGATIVE")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			paused := make(chan struct{})
			release := make(chan struct{})
			defer close(release)
			spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(r *http.Request) (*http.Response, error) {
				if scenario == "corrupt" {
					wire = append([]byte{}, wire...)
					wire[0] ^= 1
					return spResponse(r, wire, int64(len(wire))), nil
				}
				resp := spResponse(r, nil, -1)
				resp.Body = &spGateBody{ctx: r.Context(), data: wire, paused: paused, release: release}
				return resp, nil
			})})
			done := spStartDownload(w, ctx, m)
			if scenario == "cancel" {
				spAwait(t, paused)
				cancel()
			}
			got := spResult(t, done)
			if got.err == nil {
				t.Fatal("invalid/canceled provider operation succeeded")
			}
			path := filepath.Join(w.dataDir, "media", safeName(m.ChatJID), safeName(m.ID)+extensionFor(m))
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed operation published final cache")
			}
			job := spMediaJob(t, w)
			phase := "failed"
			if scenario == "cancel" {
				phase = "cancelled"
			}
			spWant(t, job, "phase", phase)
			spWant(t, job, "completed_plaintext_bytes", nil)
		})
	}
}

// B-REVIEW-02: a saver writes half the bytes and blocks, then fails. A
// simultaneous request for the same reference must never return that partial
// data as a cache hit. Retry must publish only a fully saved valid attachment.
func TestSyncProgressAtomicSaveRetrySameReference(t *testing.T) {
	w, _ := archiveFixture(t)
	m, plain, wire := spMediaRef(t, w, "document", "SP-ATOMIC")
	spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(r *http.Request) (*http.Response, error) { return spResponse(r, wire, int64(len(wire))), nil })})
	seam, ok := any(w).(interface {
		setMediaSaveForTest(func(string, []byte) error)
	})
	if !ok {
		t.Fatal("MISSING INERT SEAM: setMediaSaveForTest; this is not behavioral RED")
	}
	paused := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var writes atomic.Int32
	seam.setMediaSaveForTest(func(path string, data []byte) error {
		if writes.Add(1) == 1 {
			if err := os.WriteFile(path, data[:len(data)/2], 0600); err != nil {
				return err
			}
			close(paused)
			<-release
			return errors.New("CANARY_PRIVATE_SAVE_FAILURE")
		}
		return os.WriteFile(path, data, 0600)
	})
	first := spStartDownload(w, context.Background(), m)
	spAwait(t, paused)
	second := spStartDownload(w, context.Background(), m)
	final := filepath.Join(w.dataDir, "media", safeName(m.ChatJID), safeName(m.ID)+extensionFor(m))
	if data, err := os.ReadFile(final); err == nil && !bytes.Equal(data, plain) {
		t.Error("partial final cache visible before atomic save")
	}
	unblock()
	a, b := spResult(t, first), spResult(t, second)
	if a.err == nil {
		t.Error("injected failed save succeeded")
	}
	if b.err == nil && !bytes.Equal(b.data, plain) {
		t.Error("concurrent same-reference accepted partial cache")
	}
	_, got, err := w.DownloadMedia(context.Background(), m)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("retry accepted incomplete cache: %v", err)
	}
	job := spMediaJob(t, w)
	spWant(t, job, "phase", "complete")
	spWant(t, job, "completed_plaintext_bytes", float64(len(plain)))
}

// SP-10/11: reference states are evidence-backed and disjoint, scoped to one
// chat. Successful cached download still provides no read/extraction evidence.
func TestSyncProgressCoverageDisjointObservedReferences(t *testing.T) {
	w, _ := archiveFixture(t)
	cached, plain, _ := spMediaRef(t, w, "document", "SP-COVER-CACHED")
	failed, _, _ := spMediaRef(t, w, "audio", "SP-COVER-FAILED")
	spMediaRef(t, w, "image", "SP-COVER-UNCHECKED")
	path := filepath.Join(w.dataDir, "media", safeName(cached.ChatJID), safeName(cached.ID)+extensionFor(cached))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, plain, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.DownloadMedia(context.Background(), cached); err != nil {
		t.Fatal(err)
	}
	spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(r *http.Request) (*http.Response, error) {
		resp := spResponse(r, nil, 0)
		resp.StatusCode = http.StatusNotFound
		return resp, nil
	})})
	if _, _, err := w.DownloadMedia(context.Background(), failed); err == nil {
		t.Fatal("fixture unavailable media unexpectedly downloaded")
	}
	cov := spCoverage(t, &App{store: w.store, mode: "reader"}, group.String())
	attachments := spObject(t, cov, "attachments")
	for key, want := range map[string]any{"reference_count": float64(3), "cached_downloaded_count": float64(1), "unavailable_failed_count": float64(1), "not_checked_count": float64(1), "read_status": "unknown"} {
		spWant(t, attachments, key, want)
	}
}

// SP-08: bounded public diagnostics retain accurate omitted accounting. No
// attachment reference, error string, path or synthetic media key is exposed.
func TestSyncProgressMediaBoundAndPrivacy(t *testing.T) {
	w, _ := archiveFixture(t)
	for i := 0; i < 10; i++ {
		id := string(rune('A'+i)) + "-CANARY_REFERENCE"
		m, plain, _ := spMediaRef(t, w, "image", id)
		path := filepath.Join(w.dataDir, "media", safeName(m.ChatJID), safeName(m.ID)+extensionFor(m))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, plain, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := w.DownloadMedia(context.Background(), m); err != nil {
			t.Fatal(err)
		}
	}
	p := spObject(t, spStatus(t, &App{store: w.store, wa: w, mode: "fixture"}), "sync_progress")
	media := spObject(t, p, "media")
	jobs, ok := media["jobs"].([]any)
	if !ok || len(jobs) > 8 {
		t.Fatalf("unbounded diagnostic jobs: %v", media)
	}
	spWant(t, media, "active_count", float64(0))
	spWant(t, media, "omitted_count", float64(2))
	raw, _ := json.Marshal(p)
	for _, private := range []string{"CANARY_", group.String(), w.dataDir} {
		if bytes.Contains(raw, []byte(private)) {
			t.Errorf("private diagnostic value %q", private)
		}
	}
}

// SP-13: wrapping must preserve caller timeout/redirect policy and pass through
// the effective sentinel transport. A redirect is rejected before another
// destination can be contacted. It does not require a network socket.
func TestSyncProgressMediaEffectiveClientPolicy(t *testing.T) {
	w, _ := archiveFixture(t)
	m, _, _ := spMediaRef(t, w, "image", "SP-POLICY")
	var calls, redirects atomic.Int32
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		redirects.Add(1)
		return context.Canceled
	}, Transport: spRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 2*time.Second {
			t.Error("media wrapper dropped client timeout")
		}
		resp := spResponse(r, nil, 0)
		resp.StatusCode = 302
		resp.Header.Set("Location", "https://CANARY_OTHER.invalid/private")
		return resp, nil
	})}
	spInstallMedia(t, w, client)
	if _, _, err := w.DownloadMedia(context.Background(), m); err == nil {
		t.Fatal("redirect policy bypassed")
	}
	if calls.Load() != 1 || redirects.Load() != 1 {
		t.Errorf("effective policy not retained: transport=%d redirect=%d", calls.Load(), redirects.Load())
	}
}
