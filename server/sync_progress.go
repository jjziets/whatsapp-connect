package main

// WC-SYNC-PROGRESS-B-01: C-003/C-006/C-008; manual C-ID/Go trace evidence.
// Versioned observations share the encrypted archive. They never assert phone
// completeness, and publication belongs to the existing owner lifetime.
import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"go.mau.fi/whatsmeow/proto/waHistorySync"
)

const progressKey = "sync_progress_v1"
const progressChatKey = "sync_progress_chat_v1:"

type ProgressOwner struct {
	Role        string  `json:"role"`
	Freshness   string  `json:"freshness"`
	HeartbeatAt *string `json:"heartbeat_at"`
	Connected   *bool   `json:"connected"`
	Stopped     bool    `json:"stopped,omitempty"`
}
type ProgressCounts struct {
	Scope        string `json:"scope"`
	ActiveChunks int    `json:"active_chunks"`
	Total        *int64 `json:"observed_total_messages"`
	Processed    *int64 `json:"processed_messages"`
	Inserted     *int64 `json:"inserted"`
	Updated      *int64 `json:"updated"`
	Duplicate    *int64 `json:"duplicate"`
	Ignored      *int64 `json:"ignored"`
	Failed       *int64 `json:"failed"`
}
type ProgressHistory struct {
	Phase                  string         `json:"phase"`
	CallableHere           bool           `json:"callable_here"`
	AvailabilityCode       *string        `json:"availability_code"`
	ProviderPercent        *uint32        `json:"provider_reported_percent"`
	SyncType               *string        `json:"sync_type"`
	ChunkOrder             *uint32        `json:"chunk_order"`
	ProviderScope          string         `json:"provider_scope"`
	ReceivedAt             *string        `json:"received_at"`
	Processing             ProgressCounts `json:"processing"`
	LastChunkReceivedAt    *string        `json:"last_chunk_received_at"`
	LastChunkCompletedAt   *string        `json:"last_chunk_completed_at"`
	LastSuccessfulIngestAt *string        `json:"last_successful_ingest_at"`
}
type ProgressMedia struct {
	CallableHere          bool               `json:"callable_here"`
	AvailabilityCode      *string            `json:"availability_code"`
	AutomaticBulkDownload bool               `json:"automatic_bulk_download"`
	ActiveCount           int                `json:"active_count"`
	OmittedCount          int                `json:"omitted_count"`
	Jobs                  []ProgressMediaJob `json:"jobs"`
}
type SyncProgress struct {
	SchemaVersion int             `json:"schema_version"`
	Revision      *uint64         `json:"revision"`
	ObservedAt    *string         `json:"observed_at"`
	Owner         ProgressOwner   `json:"owner"`
	History       ProgressHistory `json:"history"`
	Media         ProgressMedia   `json:"media"`
	SessionID     string          `json:"session_id,omitempty"`
}
type chatProgress struct {
	SchemaVersion  int     `json:"schema_version"`
	SessionID      string  `json:"session_id"`
	ObservedAt     *string `json:"observed_at"`
	Processing     *bool   `json:"currently_processing"`
	LastObserved   *string `json:"last_observed_history_at"`
	LastSuccessful *string `json:"last_successful_ingest_at"`
	LastErrorAt    *string `json:"last_error_at"`
	LastErrorCode  *string `json:"last_error_code"`
	active         int
}
type historyChunkProgress struct{ total, processed, inserted, updated, duplicate, ignored, failed int64 }

func (c historyChunkProgress) output(active int) ProgressCounts {
	return ProgressCounts{Scope: "latest_completed_chunk_or_concurrent_active_aggregate", ActiveChunks: active, Total: &c.total, Processed: &c.processed, Inserted: &c.inserted, Updated: &c.updated, Duplicate: &c.duplicate, Ignored: &c.ignored, Failed: &c.failed}
}

type syncProgressState struct {
	mu                                 sync.Mutex
	gate                               chan struct{}
	wake                               chan struct{}
	stop                               chan struct{}
	done                               chan struct{}
	owned, stopped, dirty, unavailable bool
	now                                func() time.Time
	ticks                              <-chan time.Time
	lastWrite, lastHeartbeat           time.Time
	revision                           uint64
	snapshot                           SyncProgress
	chats                              map[string]*chatProgress
	dirtyChats                         map[string]chatProgress
	chunks                             map[string]*historyChunkProgress
	jobs                               []*ProgressMediaJob
	omitted                            int
	activeMedia                        int
	mediaLocks                         [64]chan struct{}
}

func opaqueProgressID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure progress entropy unavailable")
	}
	return prefix + hex.EncodeToString(b[:])
}
func progressTime(t time.Time) *string { s := t.UTC().Format(time.RFC3339Nano); return &s }
func progressString(s string) *string  { return &s }
func progressBool(v bool) *bool        { return &v }
func unknownProgress() SyncProgress {
	return SyncProgress{SchemaVersion: 1, Owner: ProgressOwner{Role: "archive_reader", Freshness: "unknown"}, History: ProgressHistory{Phase: "unknown", ProviderScope: "latest_provider_chunk_type", Processing: ProgressCounts{Scope: "latest_completed_chunk_or_concurrent_active_aggregate"}}, Media: ProgressMedia{Jobs: []ProgressMediaJob{}}}
}
func newSyncProgress() *syncProgressState {
	p := &syncProgressState{gate: make(chan struct{}, 1), wake: make(chan struct{}, 1), snapshot: unknownProgress(), now: time.Now, chats: map[string]*chatProgress{}, dirtyChats: map[string]chatProgress{}, chunks: map[string]*historyChunkProgress{}}
	p.snapshot.SessionID = opaqueProgressID("session_")
	for i := range p.mediaLocks {
		p.mediaLocks[i] = make(chan struct{}, 1)
	}
	return p
}

// Inert observers are installed before the operations they observe. Clock
// replacement itself is synchronized with a running publisher.
func (w *WA) setHistoryCheckpoint(f func())                    { w.historyCheckpoint = f }
func (w *WA) setMediaSaveForTest(f func(string, []byte) error) { w.mediaSaveForTest = f }
func (w *WA) setProgressTestClock(now func() time.Time, ticks <-chan time.Time) {
	p := w.progress
	p.mu.Lock()
	p.now = now
	p.ticks = ticks
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}
func (w *WA) flushSyncProgress(ctx context.Context) error { return w.publishSyncProgress(ctx, false) }
func (w *WA) startSyncProgress() {
	p := w.progress
	p.mu.Lock()
	p.owned = true
	p.stop = make(chan struct{})
	p.done = make(chan struct{})
	p.snapshot.History.Phase = "waiting_for_history"
	p.dirty = true
	p.mu.Unlock()
	// Preserve monotonically increasing revisions across owner sessions.
	var raw string
	if err := w.store.db.QueryRow(`SELECT value FROM mcp_meta WHERE key=?`, progressKey).Scan(&raw); err == nil && len(raw) <= 65536 {
		var previous SyncProgress
		if json.Unmarshal([]byte(raw), &previous) == nil && previous.SchemaVersion == 1 && previous.Revision != nil {
			p.mu.Lock()
			p.revision = *previous.Revision
			// Prior session work is historical, never resumed by a new owner.
			for _, old := range previous.Media.Jobs {
				sanitizeMediaJob(&old)
				if mediaActive(old.Phase) {
					old.Phase = "interrupted"
				}
				if len(p.jobs) < 8 {
					copy := old
					p.jobs = append(p.jobs, &copy)
				} else {
					p.omitted++
				}
			}
			p.snapshot.History.LastChunkReceivedAt = progressTimestamp(previous.History.LastChunkReceivedAt)
			p.snapshot.History.LastChunkCompletedAt = progressTimestamp(previous.History.LastChunkCompletedAt)
			p.snapshot.History.LastSuccessfulIngestAt = progressTimestamp(previous.History.LastSuccessfulIngestAt)
			p.mu.Unlock()
		}
	}
	_ = w.publishSyncProgress(context.Background(), true)
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			p.mu.Lock()
			ticks := p.ticks
			p.mu.Unlock()
			select {
			case <-p.stop:
				return
			case <-ticker.C:
			case <-ticks:
			case <-p.wake:
			}
			_ = w.publishSyncProgress(context.Background(), false)
		}
	}()
}

// Shutdown drains the finite terminal queue after archive work has stopped.
// Each transaction remains capped at128 chat records, with a2s total budget.
// An exhausted budget or DB failure is returned to drainAndClose, never ignored.
func (w *WA) stopSyncProgress() error {
	p := w.progress
	p.mu.Lock()
	if !p.owned || p.stopped {
		p.mu.Unlock()
		return nil
	}
	p.stopped = true
	p.snapshot.Owner.Stopped = true
	p.dirty = true
	close(p.stop)
	p.mu.Unlock()
	<-p.done
	p.mu.Lock()
	batches := (len(p.dirtyChats) + 127) / 128
	p.mu.Unlock()
	if batches < 1 {
		batches = 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < batches; i++ {
		if err := w.publishSyncProgress(ctx, true); err != nil {
			return errors.New("progress shutdown persistence failed")
		}
		p.mu.Lock()
		remaining := len(p.dirtyChats)
		p.mu.Unlock()
		if remaining == 0 {
			return nil
		}
	}
	return errors.New("progress shutdown observations remain unpersisted")
}

func cloneProgress(s SyncProgress) SyncProgress {
	b, _ := json.Marshal(s)
	var out SyncProgress
	_ = json.Unmarshal(b, &out)
	return out
}
func (p *syncProgressState) captureLocked(now time.Time) SyncProgress {
	s := p.snapshot
	s.ObservedAt = progressTime(now)
	s.Owner.HeartbeatAt = progressTime(now)
	s.Media.Jobs = make([]ProgressMediaJob, 0, len(p.jobs))
	s.Media.ActiveCount = p.activeMedia
	for i := len(p.jobs) - 1; i >= 0; i-- {
		job := *p.jobs[i]
		s.Media.Jobs = append(s.Media.Jobs, job)
	}
	s.Media.OmittedCount = p.omitted
	return cloneProgress(s)
}
func (w *WA) publishSyncProgress(parent context.Context, force bool) error {
	ctx, cancel := context.WithTimeout(parent, 600*time.Millisecond)
	defer cancel()
	p := w.progress
	select {
	case p.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-p.gate }()
	p.mu.Lock()
	now := p.now()
	heartbeat := now.Sub(p.lastHeartbeat) >= 5*time.Second
	if !p.owned || (!force && (p.stopped || (!heartbeat && (!p.dirty || now.Sub(p.lastWrite) < time.Second)))) {
		p.mu.Unlock()
		return nil
	}
	s := p.captureLocked(now)
	s.Owner.Connected = progressBool(w.Client.IsConnected())
	s.Owner.Stopped = p.stopped
	revision := p.revision + 1
	s.Revision = &revision
	chats := make(map[string]chatProgress)
	for chat, value := range p.dirtyChats {
		if len(chats) >= 128 {
			break
		}
		chats[chat] = value
		delete(p.dirtyChats, chat)
	}
	p.dirty = len(p.dirtyChats) > 0
	p.mu.Unlock()
	data, err := json.Marshal(s)
	if err == nil {
		values := map[string]string{progressKey: string(data)}
		for chat, value := range chats {
			b, e := json.Marshal(value)
			if e != nil {
				err = e
				break
			}
			values[progressChatKey+chat] = string(b)
		}
		if err == nil {
			err = w.store.writeProgress(ctx, values)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.unavailable = true
		p.dirty = true
		for chat, value := range chats {
			if _, newer := p.dirtyChats[chat]; !newer {
				p.dirtyChats[chat] = value
			}
		}
		return err
	}
	p.revision = revision
	p.snapshot.Revision = &revision
	p.snapshot.ObservedAt = s.ObservedAt
	p.snapshot.Owner.HeartbeatAt = s.Owner.HeartbeatAt
	p.snapshot.Owner.Connected = s.Owner.Connected
	p.lastWrite = now
	p.lastHeartbeat = now
	p.unavailable = false
	return nil
}

// Bounded connection-local busy policy avoids the archive's 10-second default
// stalling diagnostics. No state mutex or archive write mutex covers DB IO.
func (s *Store) writeProgress(ctx context.Context, values map[string]string) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `PRAGMA busy_timeout=100`); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), `PRAGMA busy_timeout=10000`)
	for attempt := 0; attempt < 3; attempt++ {
		tx, e := conn.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		for key, value := range values {
			_, e = tx.ExecContext(ctx, `INSERT INTO mcp_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
			if e != nil {
				break
			}
		}
		if e == nil {
			e = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if e == nil {
			return nil
		}
		_ = tx.Rollback()
		err = e
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return err
}
func (p *syncProgressState) recountLocked(last *historyChunkProgress) {
	aggregate := historyChunkProgress{}
	if len(p.chunks) == 0 && last != nil {
		aggregate = *last
	} else {
		for _, c := range p.chunks {
			aggregate.total += c.total
			aggregate.processed += c.processed
			aggregate.inserted += c.inserted
			aggregate.updated += c.updated
			aggregate.duplicate += c.duplicate
			aggregate.ignored += c.ignored
			aggregate.failed += c.failed
		}
	}
	p.snapshot.History.Processing = aggregate.output(len(p.chunks))
	p.dirty = true
}
func (w *WA) historyProgressStart(data *waHistorySync.HistorySync) string {
	id := opaqueProgressID("chunk_")
	p := w.progress
	p.mu.Lock()
	now := p.now()
	h := &p.snapshot.History
	h.Phase = "processing"
	h.ProviderPercent = nil
	if data.Progress != nil && data.GetProgress() <= 100 {
		v := data.GetProgress()
		h.ProviderPercent = &v
	}
	h.SyncType = progressString(data.GetSyncType().String())
	h.ChunkOrder = data.ChunkOrder
	h.ReceivedAt = progressTime(now)
	h.LastChunkReceivedAt = h.ReceivedAt
	c := &historyChunkProgress{}
	for _, conv := range data.GetConversations() {
		c.total += int64(len(conv.GetMessages()))
	}
	p.chunks[id] = c
	p.recountLocked(nil)
	p.mu.Unlock()
	_ = w.publishSyncProgress(context.Background(), true)
	return id
}
func (w *WA) historyProgressCounts(id string, summary IngestTelemetry) {
	p := w.progress
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.chunks[id]; c != nil {
		c.processed = summary.HistoryReceived
		c.inserted = summary.HistoryInserted
		c.updated = summary.HistoryUpdated
		c.duplicate = summary.HistoryDuplicate
		c.ignored = summary.HistoryIgnored
		c.failed = summary.HistoryFailed
		p.recountLocked(nil)
	}
}
func (w *WA) historyProgressEnd(id string, summary IngestTelemetry) {
	w.historyProgressCounts(id, summary)
	p := w.progress
	p.mu.Lock()
	c := p.chunks[id]
	delete(p.chunks, id)
	p.recountLocked(c)
	h := &p.snapshot.History
	now := p.now()
	h.LastChunkCompletedAt = progressTime(now)
	if summary.HistoryFailed+summary.HistoryMetadataFailed == 0 {
		h.LastSuccessfulIngestAt = progressTime(now)
	}
	if len(p.chunks) == 0 {
		h.Phase = "idle"
		if summary.HistoryFailed+summary.HistoryMetadataFailed > 0 {
			h.Phase = "failed"
		}
	}
	p.mu.Unlock()
	_ = w.publishSyncProgress(context.Background(), true)
}
func (w *WA) chatProgressBoundary(chat string, start bool, failed bool) {
	p := w.progress
	// Retain historical timestamps across owner sessions without DB IO under mu.
	p.mu.Lock()
	missing := p.chats[chat] == nil
	p.mu.Unlock()
	var prior chatProgress
	if missing {
		var raw string
		if w.store.db.QueryRow(`SELECT value FROM mcp_meta WHERE key=?`, progressChatKey+chat).Scan(&raw) == nil && len(raw) <= 8192 {
			if json.Unmarshal([]byte(raw), &prior) != nil || prior.SchemaVersion != 1 {
				prior = chatProgress{}
			}
		}
	}
	p.mu.Lock()
	c := p.chats[chat]
	if c == nil {
		c = &chatProgress{SchemaVersion: 1, SessionID: p.snapshot.SessionID, LastObserved: progressTimestamp(prior.LastObserved), LastSuccessful: progressTimestamp(prior.LastSuccessful), LastErrorAt: progressTimestamp(prior.LastErrorAt), LastErrorCode: prior.LastErrorCode}
		p.chats[chat] = c
	}
	now := progressTime(p.now())
	c.ObservedAt = now
	if start {
		c.active++
		c.LastObserved = now
	} else {
		if c.active > 0 {
			c.active--
		}
		if failed {
			c.LastErrorAt = now
			c.LastErrorCode = progressString("history_ingest_failed")
		} else {
			c.LastSuccessful = now
		}
	}
	c.Processing = progressBool(c.active > 0)
	p.dirtyChats[chat] = *c
	p.dirty = true
	p.mu.Unlock()
	_ = w.publishSyncProgress(context.Background(), false)
}
func (s *Store) readSyncProgress(ctx context.Context) (SyncProgress, string) {
	out := unknownProgress()
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM mcp_meta WHERE key=?`, progressKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return out, "unknown"
	}
	if err != nil || len(raw) > 65536 || json.Unmarshal([]byte(raw), &out) != nil || out.SchemaVersion != 1 {
		return unknownProgress(), "unavailable"
	}
	return out, "observed"
}
func progressTimestamp(value *string) *string {
	if value == nil {
		return nil
	}
	if _, e := time.Parse(time.RFC3339Nano, *value); e != nil {
		return nil
	}
	return value
}
func sanitizeProgress(s SyncProgress, now time.Time, self bool) (SyncProgress, string) {
	role := "archive_reader"
	if self {
		role = "self_owner"
	}
	s.Owner.Role = role
	s.Owner.Freshness = "unknown"
	at := progressTimestamp(s.Owner.HeartbeatAt)
	observed := progressTimestamp(s.ObservedAt)
	if at == nil || observed == nil {
		return unknownProgress(), "unavailable"
	}
	observedTime, _ := time.Parse(time.RFC3339Nano, *observed)
	if observedTime.After(now) {
		return unknownProgress(), "unavailable"
	}
	ts, _ := time.Parse(time.RFC3339Nano, *at)
	if ts.After(now) {
		return unknownProgress(), "unavailable"
	}
	s.Owner.Freshness = "fresh"
	if now.Sub(ts) >= 15*time.Second {
		s.Owner.Freshness = "stale"
	}
	if s.Owner.Stopped {
		s.Owner.Freshness = "stopped"
	}
	if s.Owner.Freshness != "fresh" {
		s.Owner.Connected = nil
		if s.History.Phase == "processing" {
			s.History.Phase = "interrupted"
		}
		s.History.Processing.ActiveChunks = 0
		for i := range s.Media.Jobs {
			if mediaActive(s.Media.Jobs[i].Phase) {
				s.Media.Jobs[i].Phase = "interrupted"
			}
		}
		s.Media.ActiveCount = 0
	}
	s.Owner.Stopped = false
	s.SessionID = ""
	s.ObservedAt = progressTimestamp(s.ObservedAt)
	s.Owner.HeartbeatAt = at
	s.History.CallableHere = self
	s.Media.CallableHere = self
	s.History.AvailabilityCode = nil
	s.Media.AvailabilityCode = nil
	if !self {
		s.History.AvailabilityCode = progressString("no_owner_rpc")
		s.Media.AvailabilityCode = progressString("no_owner_rpc")
	}
	if !oneOf(s.History.Phase, "unknown", "waiting_for_history", "processing", "idle", "failed", "interrupted") {
		s.History.Phase = "unknown"
	}
	if s.History.ProviderPercent != nil && *s.History.ProviderPercent > 100 {
		s.History.ProviderPercent = nil
	}
	if s.History.SyncType != nil && !oneOf(*s.History.SyncType, "INITIAL_BOOTSTRAP", "INITIAL_STATUS_V3", "FULL", "RECENT", "PUSH_NAME", "NON_BLOCKING_DATA", "ON_DEMAND", "NO_HISTORY") {
		s.History.SyncType = nil
	}
	s.History.ProviderScope = "latest_provider_chunk_type"
	s.History.Processing.Scope = "latest_completed_chunk_or_concurrent_active_aggregate"
	s.History.ReceivedAt = progressTimestamp(s.History.ReceivedAt)
	s.History.LastChunkReceivedAt = progressTimestamp(s.History.LastChunkReceivedAt)
	s.History.LastChunkCompletedAt = progressTimestamp(s.History.LastChunkCompletedAt)
	s.History.LastSuccessfulIngestAt = progressTimestamp(s.History.LastSuccessfulIngestAt)
	if len(s.Media.Jobs) > 8 {
		s.Media.OmittedCount += len(s.Media.Jobs) - 8
		s.Media.Jobs = s.Media.Jobs[:8]
	}
	if s.Media.Jobs == nil {
		s.Media.Jobs = []ProgressMediaJob{}
	}
	s.Media.AutomaticBulkDownload = false
	for i := range s.Media.Jobs {
		sanitizeMediaJob(&s.Media.Jobs[i])
	}
	return s, "observed"
}
func oneOf(value string, allowed ...string) bool {
	for _, s := range allowed {
		if value == s {
			return true
		}
	}
	return false
}
func (a *App) syncProgressOutput(ctx context.Context) (SyncProgress, string) {
	self := a.wa != nil
	var s SyncProgress
	var state string
	if self {
		p := a.wa.progress
		p.mu.Lock()
		s = p.captureLocked(p.now())
		s.Owner.Connected = progressBool(a.wa.Client.IsConnected())
		if p.unavailable {
			state = "unavailable"
		} else {
			state = "observed"
		}
		p.mu.Unlock()
	} else {
		s, state = a.store.readSyncProgress(ctx)
	}
	if state == "observed" {
		s, state = sanitizeProgress(s, time.Now(), self)
		if state == "observed" {
			return s, state
		}
	}
	s = unknownProgress()
	if self {
		s.Owner.Role = "self_owner"
	}
	s.History.CallableHere = self
	s.Media.CallableHere = self
	if !self {
		s.History.AvailabilityCode = progressString("no_owner_rpc")
		s.Media.AvailabilityCode = progressString("no_owner_rpc")
	}
	return s, state
}

// Selected-chat coverage is archive evidence, not a phone inventory. Only
// reference observations classify media; downloaded never means understood.
type EvidenceArchive struct {
	Count  int     `json:"archived_message_count"`
	Oldest *string `json:"oldest_archived_message_at"`
	Newest *string `json:"newest_archived_message_at"`
}
type EvidenceIngest struct {
	LastObserved   *string `json:"last_observed_history_at"`
	LastSuccessful *string `json:"last_successful_ingest_at"`
	LastErrorAt    *string `json:"last_error_at"`
	LastErrorCode  *string `json:"last_error_code"`
	Processing     *bool   `json:"currently_processing"`
}
type EvidenceAttachments struct {
	ReferenceCount int    `json:"reference_count"`
	Cached         *int   `json:"cached_downloaded_count"`
	Failed         *int   `json:"unavailable_failed_count"`
	Unchecked      *int   `json:"not_checked_count"`
	ReadStatus     string `json:"read_status"`
}
type EvidenceCoverage struct {
	ObservedAt  string              `json:"observed_at"`
	Archive     EvidenceArchive     `json:"archive"`
	Ingest      EvidenceIngest      `json:"ingest"`
	Attachments EvidenceAttachments `json:"attachments"`
}

func (a *App) evidenceCoverage(ctx context.Context, chat string) (*EvidenceCoverage, error) {
	out := &EvidenceCoverage{ObservedAt: *progressTime(time.Now()), Attachments: EvidenceAttachments{ReadStatus: "unknown"}}
	var oldest, newest sql.NullInt64
	err := a.store.db.QueryRowContext(ctx, `SELECT COUNT(*),MIN(timestamp),MAX(timestamp) FROM mcp_messages WHERE chat_jid=?`, chat).Scan(&out.Archive.Count, &oldest, &newest)
	if err != nil {
		return nil, err
	}
	if oldest.Valid {
		out.Archive.Oldest = progressTime(time.Unix(oldest.Int64, 0))
		out.Archive.Newest = progressTime(time.Unix(newest.Int64, 0))
	}
	// Existing chat timestamps are RFC3339 (not an alternate timestamp format).
	if out.Archive.Oldest != nil {
		*out.Archive.Oldest = time.Unix(oldest.Int64, 0).Format(time.RFC3339)
		*out.Archive.Newest = time.Unix(newest.Int64, 0).Format(time.RFC3339)
	}
	cached, failed, unchecked := 0, 0, 0
	// Only accepted aliases participate. Group by the actual canonical reference
	// so multiple verified LIDs cannot inflate counts. A validated cached copy is
	// stronger evidence than an unavailable attempt at the other address.
	rows, err := a.store.db.QueryContext(ctx, `SELECT MAX(CASE
 WHEN direct.value='cached' OR legacy.value='cached' THEN 2
 WHEN direct.value='failed' OR legacy.value='failed' THEN 1 ELSE 0 END)
 FROM mcp_messages m
 LEFT JOIN mcp_aliases a ON a.pn=m.chat_jid
 LEFT JOIN mcp_meta direct ON direct.key=?||m.chat_jid||char(31)||m.id
 LEFT JOIN mcp_meta legacy ON legacy.key=?||a.lid||char(31)||m.id
 WHERE m.chat_jid=? AND m.deleted=0 AND m.kind IN ('image','audio','voice','video','document','sticker','gif')
 GROUP BY m.id`, "sync_progress_media_v1:", "sync_progress_media_v1:", chat)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var state int
		if err = rows.Scan(&state); err != nil {
			rows.Close()
			return nil, err
		}
		out.Attachments.ReferenceCount++
		switch state {
		case 2:
			cached++
		case 1:
			failed++
		default:
			unchecked++
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out.Attachments.Cached = &cached
	out.Attachments.Failed = &failed
	out.Attachments.Unchecked = &unchecked
	// Read-through also covers an already admitted old-address publisher writing
	// after AcceptAlias commits. No second alias registry or metadata migration is
	// required; the existing verified archive relation remains authoritative.
	snapshot, state := a.store.readSyncProgress(ctx)
	session := ""
	if state == "observed" {
		projected, valid := sanitizeProgress(snapshot, time.Now(), false)
		if valid == "observed" && projected.Owner.Freshness == "fresh" {
			session = snapshot.SessionID
		}
	}
	rows, err = a.store.db.QueryContext(ctx, `SELECT value FROM mcp_meta WHERE key=? OR key IN (SELECT ?||lid FROM mcp_aliases WHERE pn=?)`, progressChatKey+chat, progressChatKey, chat)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		var record chatProgress
		if len(raw) > 8192 || json.Unmarshal([]byte(raw), &record) != nil || record.SchemaVersion != 1 {
			continue
		}
		out.Ingest.LastObserved = newestProgressTime(out.Ingest.LastObserved, record.LastObserved)
		out.Ingest.LastSuccessful = newestProgressTime(out.Ingest.LastSuccessful, record.LastSuccessful)
		latestError := newestProgressTime(out.Ingest.LastErrorAt, record.LastErrorAt)
		if latestError != out.Ingest.LastErrorAt {
			out.Ingest.LastErrorAt = latestError
			out.Ingest.LastErrorCode = nil
			if record.LastErrorCode != nil && oneOf(*record.LastErrorCode, "history_ingest_failed") {
				out.Ingest.LastErrorCode = record.LastErrorCode
			}
		}
		if session != "" && record.SessionID == session && record.Processing != nil && progressTimestamp(record.ObservedAt) != nil {
			observed, _ := time.Parse(time.RFC3339Nano, *record.ObservedAt)
			if !observed.After(time.Now()) {
				active := *record.Processing || (out.Ingest.Processing != nil && *out.Ingest.Processing)
				out.Ingest.Processing = &active
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return out, nil
}
func newestProgressTime(current, candidate *string) *string {
	candidate = progressTimestamp(candidate)
	if candidate == nil {
		return current
	}
	if current == nil {
		return candidate
	}
	old, _ := time.Parse(time.RFC3339Nano, *current)
	next, _ := time.Parse(time.RFC3339Nano, *candidate)
	if next.After(old) {
		return candidate
	}
	return current
}
