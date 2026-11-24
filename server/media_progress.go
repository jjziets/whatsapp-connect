package main

// WC-SYNC-PROGRESS-B-01: C-003/C-006/C-008; actual pinned-provider wire
// observation. DownloadAny retains integrity/decryption; atomic save publishes.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.mau.fi/whatsmeow/proto/waE2E"
	"google.golang.org/protobuf/proto"
)

type ProgressMediaJob struct {
	OperationID     string  `json:"operation_id"`
	Kind            string  `json:"kind"`
	Phase           string  `json:"phase"`
	CacheHit        *bool   `json:"cache_hit"`
	CurrentAttempt  *int    `json:"current_attempt"`
	PerAttemptBytes *int64  `json:"per_attempt_bytes"`
	CumulativeBytes int64   `json:"cumulative_received_bytes"`
	ExpectedBytes   *int64  `json:"expected_attempt_bytes"`
	PlaintextBytes  *int64  `json:"completed_plaintext_bytes"`
	StartedAt       string  `json:"started_at"`
	UpdatedAt       string  `json:"updated_at"`
	ErrorCode       *string `json:"error_code"`
}

func mediaActive(phase string) bool {
	return oneOf(phase, "checking_cache", "downloading", "verifying", "saving")
}
func sanitizeMediaJob(j *ProgressMediaJob) {
	if !strings.HasPrefix(j.OperationID, "op_") || len(j.OperationID) != 35 {
		j.OperationID = ""
	} else if _, e := hex.DecodeString(strings.TrimPrefix(j.OperationID, "op_")); e != nil {
		j.OperationID = ""
	}
	if !oneOf(j.Kind, "image", "audio", "document", "video", "other") {
		j.Kind = "other"
	}
	if !oneOf(j.Phase, "checking_cache", "downloading", "verifying", "saving", "complete", "failed", "cancelled", "interrupted") {
		j.Phase = "interrupted"
	}
	if j.ErrorCode != nil && !oneOf(*j.ErrorCode, "cancelled", "download_failed", "media_unavailable", "integrity_failed", "save_failed", "archive_media_unavailable") {
		j.ErrorCode = nil
	}
	if progressTimestamp(&j.StartedAt) == nil {
		j.StartedAt = ""
	}
	if progressTimestamp(&j.UpdatedAt) == nil {
		j.UpdatedAt = ""
	}
}

type mediaProgressToken struct {
	owner *WA
	job   *ProgressMediaJob
}
type mediaProgressKey struct{}
type mediaProgressTransport struct {
	base  http.RoundTripper
	owner *WA
}

func (t *mediaProgressTransport) Unwrap() http.RoundTripper { return t.base }
func (w *WA) setMediaHTTPClient(base *http.Client) {
	client := *base
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = &mediaProgressTransport{base: transport, owner: w}
	w.Client.SetMediaHTTPClient(&client)
}
func (t *mediaProgressTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if budget, ok := req.Context().Value(forwardHTTPKey{}).(*forwardHTTPBudget); ok && budget.owner == t.owner {
		return budget.roundTrip(t.base, req)
	}
	token, ok := req.Context().Value(mediaProgressKey{}).(*mediaProgressToken)
	if !ok || token.owner != t.owner {
		return t.base.RoundTrip(req)
	}
	p := t.owner.progress
	p.mu.Lock()
	attempt := 1
	if token.job.CurrentAttempt != nil {
		attempt = *token.job.CurrentAttempt + 1
	}
	zero := int64(0)
	token.job.CurrentAttempt = &attempt
	token.job.PerAttemptBytes = &zero
	token.job.ExpectedBytes = nil
	token.job.Phase = "downloading"
	token.job.UpdatedAt = *progressTime(p.now())
	p.dirty = true
	p.mu.Unlock()
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	if resp.StatusCode == http.StatusOK {
		p.mu.Lock()
		if resp.ContentLength >= 0 {
			size := resp.ContentLength
			token.job.ExpectedBytes = &size
		}
		p.mu.Unlock()
		resp.Body = &mediaProgressBody{ReadCloser: resp.Body, token: token}
	}
	return resp, nil
}

type mediaProgressBody struct {
	io.ReadCloser
	token *mediaProgressToken
}

func (b *mediaProgressBody) Read(data []byte) (int, error) {
	n, err := b.ReadCloser.Read(data)
	p := b.token.owner.progress
	p.mu.Lock()
	j := b.token.job
	if j.PerAttemptBytes != nil {
		*j.PerAttemptBytes += int64(n)
	}
	j.CumulativeBytes += int64(n)
	j.UpdatedAt = *progressTime(p.now())
	if err == io.EOF {
		j.Phase = "verifying"
		if j.ExpectedBytes != nil && (j.PerAttemptBytes == nil || *j.ExpectedBytes != *j.PerAttemptBytes) {
			j.ExpectedBytes = nil
		}
	}
	p.dirty = true
	p.mu.Unlock()
	return n, err
}
func (w *WA) mediaStart(kind string) *ProgressMediaJob {
	if kind == "voice" {
		kind = "audio"
	}
	if !oneOf(kind, "image", "audio", "document", "video") {
		kind = "other"
	}
	p := w.progress
	p.mu.Lock()
	now := *progressTime(p.now())
	j := &ProgressMediaJob{OperationID: opaqueProgressID("op_"), Kind: kind, Phase: "checking_cache", StartedAt: now, UpdatedAt: now}
	p.jobs = append(p.jobs, j)
	p.activeMedia++
	if len(p.jobs) > 8 {
		drop := 0
		for i, old := range p.jobs {
			if !mediaActive(old.Phase) {
				drop = i
				break
			}
		}
		p.jobs = append(p.jobs[:drop], p.jobs[drop+1:]...)
		p.omitted++
	}
	p.dirty = true
	p.mu.Unlock()
	_ = w.publishSyncProgress(context.Background(), true)
	return j
}
func (w *WA) mediaPhase(job *ProgressMediaJob, phase string) {
	p := w.progress
	p.mu.Lock()
	job.Phase = phase
	job.UpdatedAt = *progressTime(p.now())
	p.dirty = true
	p.mu.Unlock()
}
func (w *WA) setMediaFinishForTest(f func()) { w.mediaFinishForTest = f }

func (w *WA) mediaFinish(job *ProgressMediaJob, m *MessageRow, cache bool, size int, err error, code string) {
	if w.mediaFinishForTest != nil {
		w.mediaFinishForTest()
	}
	p := w.progress
	p.mu.Lock()
	if mediaActive(job.Phase) {
		p.activeMedia--
	}
	job.UpdatedAt = *progressTime(p.now())
	job.CacheHit = progressBool(cache)
	if err == nil {
		job.Phase = "complete"
		n := int64(size)
		job.PlaintextBytes = &n
	} else {
		job.Phase = "failed"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			job.Phase = "cancelled"
			code = "cancelled"
		}
		job.ErrorCode = progressString(code)
	}
	p.dirty = true
	p.mu.Unlock()
	// Terminal persistence outlives only the canceled request, with a fixed bound.
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	if err == nil || job.Phase == "failed" {
		state := "cached"
		if err != nil {
			state = "failed"
		}
		_ = w.store.writeProgress(ctx, map[string]string{mediaReferenceKey(m.ChatJID, m.ID): state})
	}
	_ = w.publishSyncProgress(ctx, true)
}
func mediaReferenceKey(chat, id string) string { return "sync_progress_media_v1:" + chat + "\x1f" + id }

// Unlike admitWork for received history, media admission preserves request
// cancellation. Shutdown cancels admitted downloads before draining the DB.
func (w *WA) admitMedia(ctx context.Context) (context.Context, func(), bool) {
	w.lifecycleMu.Lock()
	if w.closing {
		w.lifecycleMu.Unlock()
		return ctx, nil, false
	}
	if w.lifecycleCond == nil {
		w.lifecycleCond = sync.NewCond(&w.lifecycleMu)
	}
	w.activeWork++
	ctx, cancel := context.WithCancel(ctx)
	id := opaqueProgressID("admission_")
	w.mediaCancels[id] = cancel
	w.lifecycleMu.Unlock()
	return ctx, func() {
		cancel()
		w.lifecycleMu.Lock()
		delete(w.mediaCancels, id)
		w.activeWork--
		w.lifecycleCond.Broadcast()
		w.lifecycleMu.Unlock()
	}, true
}
func (w *WA) downloadMediaProgress(ctx context.Context, m *MessageRow) (path string, data []byte, err error) {
	ctx, finish, ok := w.admitMedia(ctx)
	if !ok {
		return "", nil, errArchiveClosing
	}
	defer finish()
	job := w.mediaStart(m.Kind)
	cache := false
	code := "download_failed"
	digest := sha256.Sum256([]byte(m.ChatJID + "\x00" + m.ID))
	lock := w.progress.mediaLocks[int(digest[0])%len(w.progress.mediaLocks)]
	locked := false
	// Reference-state persistence is part of the same-reference critical section;
	// a delayed failed attempt cannot overwrite the next successful retry.
	defer func() {
		if locked {
			defer func() { <-lock }()
		}
		w.mediaFinish(job, m, cache, len(data), err, code)
	}()
	select {
	case lock <- struct{}{}:
	case <-ctx.Done():
		return "", nil, ctx.Err()
	}
	locked = true
	if err = ctx.Err(); err != nil {
		return "", nil, err
	}
	dir := filepath.Join(w.dataDir, "media", safeName(m.ChatJID))
	path = filepath.Join(dir, safeName(m.ID)+extensionFor(m))
	if data, err = os.ReadFile(path); err == nil {
		cache = true
		return path, data, nil
	}
	raw, e := w.store.RawMessage(ctx, m.ChatJID, m.ID)
	if e != nil || len(raw) == 0 {
		code = "archive_media_unavailable"
		return "", nil, errors.New("message has no downloadable media")
	}
	var msg waE2E.Message
	if e = proto.Unmarshal(raw, &msg); e != nil {
		code = "archive_media_unavailable"
		return "", nil, errors.New("stored media unavailable")
	}
	ctx = context.WithValue(ctx, mediaProgressKey{}, &mediaProgressToken{owner: w, job: job})
	w.mediaPhase(job, "downloading")
	data, err = w.Client.DownloadAny(ctx, &msg)
	if err != nil {
		return "", nil, err
	}
	if err = ctx.Err(); err != nil {
		return "", nil, err
	}
	w.mediaPhase(job, "saving")
	code = "save_failed"
	if err = os.MkdirAll(dir, 0700); err != nil {
		return "", nil, err
	}
	temp, e := os.CreateTemp(dir, ".download-*")
	if e != nil {
		return "", nil, e
	}
	temporary := temp.Name()
	defer os.Remove(temporary)
	if err = temp.Close(); err != nil {
		return "", nil, err
	}
	write := func(p string, b []byte) error { return os.WriteFile(p, b, 0600) }
	if w.mediaSaveForTest != nil {
		write = w.mediaSaveForTest
	}
	if err = write(temporary, data); err != nil {
		return "", nil, err
	}
	f, e := os.OpenFile(temporary, os.O_RDWR, 0600)
	if e != nil {
		return "", nil, e
	}
	err = f.Sync()
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", nil, err
	}
	if err = ctx.Err(); err != nil {
		return "", nil, err
	}
	if err = os.Rename(temporary, path); err != nil {
		return "", nil, err
	}
	return path, data, nil
}
