package main

// REQ-WC-004/005/008: exact-source manual Go trace review; no automatic Go anchor claim.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hansen/whatsapp-mcp/internal/eventdelivery"
	"github.com/hansen/whatsapp-mcp/internal/eventsecrets"
	"go.mau.fi/whatsmeow/types"
)

type EventSender interface {
	Verify(context.Context, string, string, string) error
	Send(context.Context, eventdelivery.Request) (eventdelivery.Receipt, error)
}
type EventHooks struct {
	BeforeReceiptCommit func(context.Context, string) error
}
type EventConfig struct {
	Store                         *Store
	WA                            *WA
	OwnerID, ProfileID, Transport string
	Owner, Enabled                bool
	Secrets                       eventsecrets.EventSecretProvider
	Sender                        EventSender
	Now                           func() time.Time
	After                         func(time.Duration) <-chan time.Time
	Random                        io.Reader
	Clipboard                     func(string) error
	PendingLimit                  int
	Hooks                         *EventHooks
}
type EventDelivery struct {
	Mode   string `json:"mode"`
	URL    string `json:"url"`
	Secret string `json:"secret,omitempty"`
}
type EventSubscribeRequest struct {
	paramsBase
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Delivery  EventDelivery   `json:"delivery"`
	Cursor    json.RawMessage `json:"cursor"`
	TTLMS     json.RawMessage `json:"ttlMs,omitempty"`
}
type EventUnsubscribeRequest struct {
	paramsBase
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Delivery  EventDelivery   `json:"delivery"`
}
type EventSubscribeResult struct {
	ID            string          `json:"id"`
	RefreshBefore time.Time       `json:"refreshBefore"`
	Cursor        json.RawMessage `json:"cursor"`
	Truncated     bool            `json:"truncated"`
	resultBase
}
type EventFilter struct {
	ChatJIDs   []string `json:"chat_jids,omitempty"`
	SenderJIDs []string `json:"sender_jids,omitempty"`
}
type EventMonitor struct {
	Filter                  EventFilter `json:"filter"`
	ID                      string      `json:"id"`
	State                   string      `json:"state"`
	Generation              int64       `json:"generation"`
	ExpiresAt               time.Time   `json:"expires_at"`
	ActivatedAt             time.Time   `json:"activated_at"`
	Pending                 int64       `json:"pending_count"`
	Accepted                int64       `json:"accepted_count"`
	Failed                  int64       `json:"failed_count"`
	Suppressed              int64       `json:"suppressed_count"`
	Overflow                int64       `json:"overflow_count"`
	EventsEnabled           bool        `json:"events_enabled"`
	ProducerConnected       bool        `json:"producer_connected"`
	OldestPendingAgeSeconds int64       `json:"oldest_pending_age_seconds"`
	LastAttemptAt           *time.Time  `json:"last_attempt_at,omitempty"`
	LastReceiptAt           *time.Time  `json:"last_receipt_at,omitempty"`
	LastHTTPStatus          int         `json:"last_http_status"`
	ReceiptStatus           string      `json:"receipt_status"`
	LastErrorCode           string      `json:"last_error_code,omitempty"`
	SummaryCompleted        *bool       `json:"summary_completed"`
	UserNotified            *bool       `json:"user_notified"`
}
type EventAccessStatus struct {
	Enabled   bool   `json:"enabled"`
	OwnerID   string `json:"owner_id"`
	ProfileID string `json:"profile_id"`
}
type eventSub struct {
	id, args, url, key, old, state           string
	rotation, expires, activated, generation int64
}
type EventService struct {
	cfg              EventConfig
	mu               sync.Mutex
	cond             *sync.Cond
	closing, started bool
	ops              int
	cancel           context.CancelFunc
	wake             chan struct{}
	loopDone         chan struct{}
	running          map[string]bool
	pinned           map[string]int
	global           eventBucket
	buckets          map[string]*eventBucket
	workerError      string
	streamCancels    map[uint64]context.CancelFunc
	streamNext       uint64
	randomMu         sync.Mutex
	secretMu         sync.Mutex
}
type eventBucket struct {
	tokens float64
	at     time.Time
}

const eventName = "whatsapp.message.created"
const eventSchema = `
CREATE TABLE IF NOT EXISTS mcp_event_access(profile_id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,key_ref TEXT NOT NULL,generation INTEGER NOT NULL,state TEXT NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mcp_event_subscriptions(id TEXT PRIMARY KEY,profile_id TEXT NOT NULL,principal_id TEXT NOT NULL,name TEXT NOT NULL,arguments_json TEXT NOT NULL,callback_url TEXT NOT NULL,key_ref TEXT NOT NULL,old_key_ref TEXT NOT NULL DEFAULT '',rotation_until INTEGER NOT NULL DEFAULT 0,verified_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,state TEXT NOT NULL,generation INTEGER NOT NULL,activated_at INTEGER NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,last_error_code TEXT NOT NULL DEFAULT '',suppressed_count INTEGER NOT NULL DEFAULT 0,overflow_count INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS mcp_event_outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,initial_origin_chat_jid TEXT NOT NULL,message_id TEXT NOT NULL,chat_jid TEXT NOT NULL,sender_jid TEXT NOT NULL,occurred_at INTEGER NOT NULL,observed_at INTEGER NOT NULL,kind TEXT NOT NULL,body_bytes BLOB NOT NULL,UNIQUE(initial_origin_chat_jid,message_id));
CREATE INDEX IF NOT EXISTS mcp_event_outbox_logical ON mcp_event_outbox(chat_jid,message_id);
CREATE TABLE IF NOT EXISTS mcp_event_deliveries(subscription_id TEXT NOT NULL,event_id TEXT NOT NULL,state TEXT NOT NULL,attempt_count INTEGER NOT NULL DEFAULT 0,next_attempt_at INTEGER NOT NULL,lease_until INTEGER NOT NULL DEFAULT 0,accepted_at INTEGER NOT NULL DEFAULT 0,last_http_status INTEGER NOT NULL DEFAULT 0,last_attempt_at INTEGER NOT NULL DEFAULT 0,last_error_code TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,PRIMARY KEY(subscription_id,event_id),FOREIGN KEY(subscription_id) REFERENCES mcp_event_subscriptions(id),FOREIGN KEY(event_id) REFERENCES mcp_event_outbox(event_id));
CREATE INDEX IF NOT EXISTS mcp_event_due ON mcp_event_deliveries(state,next_attempt_at);
CREATE TABLE IF NOT EXISTS mcp_event_staged_keys(ref TEXT PRIMARY KEY,created_at INTEGER NOT NULL);
INSERT INTO mcp_meta(key,value) VALUES('events_schema_version','1') ON CONFLICT(key) DO NOTHING;
`

func NewEventService(cfg EventConfig) (*EventService, error) {
	if cfg.Store == nil || !cfg.Owner || cfg.Transport != "http" || len(cfg.ProfileID) != 64 || cfg.OwnerID == "" {
		return nil, errors.New("events require writable owner HTTP mode")
	}
	if _, err := hex.DecodeString(cfg.ProfileID); err != nil || strings.ToLower(cfg.ProfileID) != cfg.ProfileID {
		return nil, errors.New("invalid events profile")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.After == nil {
		cfg.After = time.After
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	if cfg.PendingLimit == 0 {
		cfg.PendingLimit = 10000
	}
	if cfg.PendingLimit < 1 || cfg.PendingLimit > 10000 {
		return nil, errors.New("invalid queue limit")
	}
	if cfg.Secrets == nil {
		var err error
		cfg.Secrets, err = eventsecrets.Native(cfg.ProfileID)
		if err != nil {
			return nil, err
		}
	}
	if cfg.Sender == nil {
		var err error
		cfg.Sender, err = eventdelivery.New(eventdelivery.Config{})
		if err != nil {
			return nil, err
		}
	}
	s := &EventService{cfg: cfg, wake: make(chan struct{}, 1), running: map[string]bool{}, pinned: map[string]int{}, buckets: map[string]*eventBucket{}}
	s.cond = sync.NewCond(&s.mu)
	if err := cfg.Store.transaction(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(eventSchema); err != nil {
			return err
		}
		var version string
		if err := tx.QueryRow(`SELECT value FROM mcp_meta WHERE key='events_schema_version'`).Scan(&version); err != nil {
			return err
		}
		if version != "1" {
			return errors.New("unsupported events schema version; use matching owner binary")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	var owner string
	err := cfg.Store.db.QueryRow(`SELECT owner_id FROM mcp_event_access WHERE profile_id=?`, cfg.ProfileID).Scan(&owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil && owner != cfg.OwnerID {
		return nil, errors.New("events owner does not match stored principal")
	}
	cfg.Store.eventsMu.Lock()
	if cfg.Store.events != nil && !cfg.Store.events.isClosing() {
		cfg.Store.eventsMu.Unlock()
		return nil, errors.New("events service already owns this store")
	}
	cfg.Store.events = s
	cfg.Store.eventsMu.Unlock()
	return s, nil
}
func (s *EventService) admit() (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return nil, errors.New("events closing")
	}
	s.ops++
	return func() { s.mu.Lock(); s.ops--; s.cond.Broadcast(); s.mu.Unlock() }, nil
}
func (s *EventService) isClosing() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.closing }
func (s *EventService) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *EventService) randomID(prefix string) (string, error) {
	b := make([]byte, 32)
	s.randomMu.Lock()
	_, err := io.ReadFull(s.cfg.Random, b)
	s.randomMu.Unlock()
	if err != nil {
		return "", errors.New("events entropy unavailable")
	}
	return prefix + hex.EncodeToString(b), nil
}
func normalizeEventURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return "", errors.New("invalid callback URL")
	}
	u.Scheme = "https"
	u.Host = strings.ToLower(u.Hostname())
	if strings.Contains(u.Host, ":") {
		u.Host = "[" + u.Host + "]"
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}
func filterArgs(raw json.RawMessage) (EventFilter, string, error) {
	var f EventFilter
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, "", errors.New("invalid exact event filter")
	}
	if dec.Decode(new(any)) != io.EOF {
		return f, "", errors.New("invalid event filter JSON")
	}
	if len(f.ChatJIDs) == 0 && len(f.SenderJIDs) == 0 {
		return f, "", errors.New("exact chat or sender filter required")
	}
	normalize := func(list []string, sender bool) ([]string, error) {
		if len(list) > 32 {
			return nil, errors.New("too many event targets")
		}
		m := map[string]bool{}
		for _, v := range list {
			jid, err := types.ParseJID(v)
			if err != nil || jid.User == "" || jid.ToNonAD() != jid || jid.String() != v || (jid.Server != types.DefaultUserServer && jid.Server != types.HiddenUserServer && (!(!sender && jid.Server == types.GroupServer))) {
				return nil, errors.New("invalid exact event JID")
			}
			for _, c := range jid.User {
				if !(c >= '0' && c <= '9' || (!sender && jid.Server == types.GroupServer && c == '-')) {
					return nil, errors.New("invalid exact event JID")
				}
			}
			m[v] = true
		}
		out := make([]string, 0, len(m))
		for v := range m {
			out = append(out, v)
		}
		sort.Strings(out)
		return out, nil
	}
	var err error
	f.ChatJIDs, err = normalize(f.ChatJIDs, false)
	if err != nil {
		return f, "", err
	}
	f.SenderJIDs, err = normalize(f.SenderJIDs, true)
	if err != nil {
		return f, "", err
	}
	b, _ := json.Marshal(f)
	return f, string(b), nil
}
func (s *EventService) subscriptionID(name, args, url string) string {
	h := sha256.New()
	for _, v := range []string{"wc-events-v1", s.cfg.ProfileID, s.cfg.OwnerID, url, name, args} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(v)))
		h.Write(n[:])
		h.Write([]byte(v))
	}
	return "sub_" + hex.EncodeToString(h.Sum(nil))
}
func ttlDuration(raw json.RawMessage) (time.Duration, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 24 * time.Hour, nil
	}
	v, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || v <= 0 {
		return 0, errors.New("invalid finite event TTL")
	}
	if v < 60000 {
		v = 60000
	}
	if v > 604800000 {
		v = 604800000
	}
	return time.Duration(v) * time.Millisecond, nil
}
func accessTx(ctx context.Context, tx *sql.Tx, profile, owner string) (string, int64, error) {
	var key, state, actual string
	var generation int64
	err := tx.QueryRowContext(ctx, `SELECT key_ref,generation,state,owner_id FROM mcp_event_access WHERE profile_id=?`, profile).Scan(&key, &generation, &state, &actual)
	if err != nil || state != "active" || actual != owner {
		return "", 0, errors.New("events owner access unavailable")
	}
	return key, generation, nil
}

type eventAccessGrant struct {
	ref        string
	generation int64
}

func (s *EventService) grant(ctx context.Context) (int64, error) {
	grant, err := s.validatedGrant(ctx)
	return grant.generation, err
}

func (s *EventService) validatedGrant(ctx context.Context) (eventAccessGrant, error) {
	var ref string
	var generation int64
	err := s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
		key, g, e := accessTx(ctx, tx, s.cfg.ProfileID, s.cfg.OwnerID)
		ref, generation = key, g
		return e
	})
	if err == nil {
		_, err = s.readAccessCredential(ctx, ref)
	}
	if err == nil {
		// Keychain latency may overlap revoke/rotation. The key just read must
		// still belong to this exact active grant before admitting the call.
		err = s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
			current, g, e := accessTx(ctx, tx, s.cfg.ProfileID, s.cfg.OwnerID)
			if e != nil || current != ref || g != generation {
				return errors.New("events grant changed during credential read")
			}
			return nil
		})
	}
	if err == nil && s.cfg.WA != nil && s.cfg.WA.loggedOut.Load() {
		err = errors.New("events account logged out")
	}
	return eventAccessGrant{ref: ref, generation: generation}, err
}

func (s *EventService) revalidateGrant(ctx context.Context, original eventAccessGrant) error {
	current, err := s.validatedGrant(ctx)
	if err != nil {
		return err
	}
	if current != original {
		return errors.New("events grant changed during verification")
	}
	return nil
}
func subTx(ctx context.Context, tx *sql.Tx, id, profile, owner string) (eventSub, error) {
	var x eventSub
	x.id = id
	err := tx.QueryRowContext(ctx, `SELECT arguments_json,callback_url,key_ref,old_key_ref,rotation_until,expires_at,state,generation,activated_at FROM mcp_event_subscriptions WHERE id=? AND profile_id=? AND principal_id=?`, id, profile, owner).Scan(&x.args, &x.url, &x.key, &x.old, &x.rotation, &x.expires, &x.state, &x.generation, &x.activated)
	return x, err
}
func (s *EventService) Subscribe(ctx context.Context, r EventSubscribeRequest) (EventSubscribeResult, error) {
	var out EventSubscribeResult
	finish, err := s.admit()
	if err != nil {
		return out, err
	}
	defer finish()
	if r.Name != eventName || r.Delivery.Mode != "webhook" || (len(r.Cursor) > 0 && string(r.Cursor) != "null") {
		return out, errors.New("unsupported event or replay cursor")
	}
	_, args, err := filterArgs(r.Arguments)
	if err != nil {
		return out, err
	}
	url, err := normalizeEventURL(r.Delivery.URL)
	if err != nil {
		return out, err
	}
	ttl, err := ttlDuration(r.TTLMS)
	if err != nil {
		return out, err
	}
	key, err := decodeEventKey(r.Delivery.Secret)
	if err != nil {
		return out, err
	}
	id := s.subscriptionID(r.Name, args, url)
	grant, err := s.validatedGrant(ctx)
	if err != nil {
		return out, err
	}
	var prior eventSub
	err = s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
		var e error
		prior, e = subTx(ctx, tx, id, s.cfg.ProfileID, s.cfg.OwnerID)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		return e
	})
	if err != nil {
		return out, err
	}
	if prior.state == "stopped" {
		return out, errors.New("locally stopped monitor requires explicit restart or fresh callback")
	}
	if err := s.cfg.Sender.Verify(ctx, url, id, r.Delivery.Secret); err != nil {
		return out, &eventProtocolError{Code: -32015, Reason: eventdelivery.Code(err)}
	}
	s.secretMu.Lock()
	defer s.secretMu.Unlock()
	// Verification and native staging can both block. Refresh native validity
	// after each boundary and keep the original exact grant pinned throughout.
	// Native lookups stay outside SQL; loss after the last lookup is still an
	// asynchronous in-flight boundary, not atomic cross-store revocation.
	if err := s.revalidateGrant(ctx, grant); err != nil {
		return out, err
	}
	ref, err := s.stageKey(ctx, id, key)
	if err != nil {
		return out, errors.New("callback credential unavailable")
	}
	activated := false
	defer func() {
		if !activated {
			_ = s.cleanupKey(context.Background(), ref)
		}
	}()
	if err := s.revalidateGrant(ctx, grant); err != nil {
		return out, err
	}
	now := s.cfg.Now()
	expires := now.Add(ttl)
	err = s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
		currentRef, g, e := accessTx(ctx, tx, s.cfg.ProfileID, s.cfg.OwnerID)
		if e != nil || currentRef != grant.ref || g != grant.generation || s.isClosing() || (s.cfg.WA != nil && s.cfg.WA.loggedOut.Load()) {
			return errors.New("events grant changed during verification")
		}
		current, e := subTx(ctx, tx, id, s.cfg.ProfileID, s.cfg.OwnerID)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if e == nil && current.generation != prior.generation {
			return errors.New("monitor changed during verification")
		}
		if current.state == "stopped" {
			return errors.New("monitor stopped")
		}
		if e != nil {
			var n int
			if e := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mcp_event_subscriptions WHERE profile_id=? AND principal_id=? AND state IN ('active','paused')`, s.cfg.ProfileID, s.cfg.OwnerID).Scan(&n); e != nil {
				return e
			}
			if n >= 64 {
				return errors.New("monitor limit reached")
			}
		}
		state := "active"
		start := now.UnixMilli()
		if current.state == "paused" {
			state = "paused"
			start = current.activated
		} else if current.state == "active" && current.expires > now.UnixMilli() {
			start = current.activated
		}
		old := current.key
		rotation := int64(0)
		if old != "" {
			rotation = now.Add(5 * time.Minute).UnixMilli()
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO mcp_event_subscriptions(id,profile_id,principal_id,name,arguments_json,callback_url,key_ref,old_key_ref,rotation_until,verified_at,expires_at,state,generation,activated_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET key_ref=excluded.key_ref,old_key_ref=excluded.old_key_ref,rotation_until=excluded.rotation_until,verified_at=excluded.verified_at,expires_at=excluded.expires_at,state=excluded.state,generation=excluded.generation,activated_at=excluded.activated_at,updated_at=excluded.updated_at,last_error_code=''`, id, s.cfg.ProfileID, s.cfg.OwnerID, eventName, args, url, ref, old, rotation, now.UnixMilli(), expires.UnixMilli(), state, current.generation+1, start, now.UnixMilli(), now.UnixMilli())
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `DELETE FROM mcp_event_staged_keys WHERE ref=?`, ref)
		return e
	})
	if err != nil {
		return out, errors.New("subscription activation failed")
	}
	activated = true
	s.Wake()
	return EventSubscribeResult{ID: id, RefreshBefore: expires, Cursor: json.RawMessage("null")}, nil
}
func decodeEventKey(secret string) ([]byte, error) {
	if !strings.HasPrefix(secret, "whsec_") {
		return nil, errors.New("invalid callback credential")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil || len(key) < 24 || len(key) > 64 {
		return nil, errors.New("invalid callback credential")
	}
	return key, nil
}
func (s *EventService) cancelTx(ctx context.Context, tx *sql.Tx, id, state, code string) error {
	_, err := tx.ExecContext(ctx, `UPDATE mcp_event_subscriptions SET state=?,generation=generation+1,updated_at=?,last_error_code=? WHERE id=? AND profile_id=? AND principal_id=?`, state, s.cfg.Now().UnixMilli(), code, id, s.cfg.ProfileID, s.cfg.OwnerID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE mcp_event_deliveries SET state='canceled',last_error_code=? WHERE subscription_id=? AND state IN ('pending','leased')`, code, id)
	return err
}
func (s *EventService) Control(ctx context.Context, id, action string) error {
	finish, err := s.admit()
	if err != nil {
		return err
	}
	defer finish()
	grant, err := s.grant(ctx)
	if err != nil {
		return err
	}
	var restart eventSub
	if action == "restart" {
		err = s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
			var e error
			restart, e = subTx(ctx, tx, id, s.cfg.ProfileID, s.cfg.OwnerID)
			return e
		})
		if err != nil || restart.state != "stopped" || restart.expires <= s.cfg.Now().UnixMilli() {
			return errors.New("monitor cannot restart; create fresh subscription")
		}
		key, e := s.cfg.Secrets.Get(ctx, restart.key)
		if e != nil {
			return errors.New("callback credential unavailable")
		}
		if e := s.cfg.Sender.Verify(ctx, restart.url, id, "whsec_"+base64.StdEncoding.EncodeToString(key)); e != nil {
			return &eventProtocolError{Code: -32015, Reason: eventdelivery.Code(e)}
		}
	}
	return s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
		_, currentGrant, e := accessTx(ctx, tx, s.cfg.ProfileID, s.cfg.OwnerID)
		if e != nil || currentGrant != grant || (s.cfg.WA != nil && s.cfg.WA.loggedOut.Load()) {
			return errors.New("events grant changed")
		}
		x, err := subTx(ctx, tx, id, s.cfg.ProfileID, s.cfg.OwnerID)
		if err != nil {
			return errors.New("monitor not found")
		}
		switch action {
		case "pause":
			return s.cancelTx(ctx, tx, id, "paused", "")
		case "stop":
			return s.cancelTx(ctx, tx, id, "stopped", "")
		case "resume", "restart":
			allowed := x.state == "paused"
			if action == "restart" {
				allowed = x.state == "stopped" && x.generation == restart.generation
			}
			if !allowed || x.expires <= s.cfg.Now().UnixMilli() {
				return errors.New("monitor cannot resume; resubscribe")
			}
			_, err = tx.ExecContext(ctx, `UPDATE mcp_event_subscriptions SET state='active',generation=generation+1,activated_at=?,updated_at=? WHERE id=?`, s.cfg.Now().UnixMilli(), s.cfg.Now().UnixMilli(), id)
			return err
		default:
			return errors.New("unsupported monitor control")
		}
	})
}
func (s *EventService) Unsubscribe(ctx context.Context, r EventUnsubscribeRequest) error {
	_, args, err := filterArgs(r.Arguments)
	if err != nil {
		return err
	}
	url, err := normalizeEventURL(r.Delivery.URL)
	if err != nil {
		return err
	}
	if r.Name != eventName || r.Delivery.Mode != "webhook" {
		return errors.New("unsupported event")
	}
	finish, err := s.admit()
	if err != nil {
		return err
	}
	defer finish()
	if _, err := s.grant(ctx); err != nil {
		return err
	}
	return s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error { return s.cancelTx(ctx, tx, s.subscriptionID(r.Name, args, url), "revoked", "") })
}
func (s *EventService) Monitors(ctx context.Context) ([]EventMonitor, error) {
	rows, err := s.cfg.Store.db.QueryContext(ctx, `SELECT id,arguments_json,state,generation,expires_at,activated_at,suppressed_count,overflow_count,last_error_code,(SELECT COUNT(*) FROM mcp_event_deliveries d WHERE d.subscription_id=s.id AND d.state IN ('pending','leased')),(SELECT COUNT(*) FROM mcp_event_deliveries d WHERE d.subscription_id=s.id AND d.state='accepted'),(SELECT COUNT(*) FROM mcp_event_deliveries d WHERE d.subscription_id=s.id AND d.state='failed'),(SELECT MIN(created_at) FROM mcp_event_deliveries d WHERE d.subscription_id=s.id AND d.state IN ('pending','leased')),(SELECT MAX(last_attempt_at) FROM mcp_event_deliveries d WHERE d.subscription_id=s.id),(SELECT MAX(accepted_at) FROM mcp_event_deliveries d WHERE d.subscription_id=s.id),(SELECT last_http_status FROM mcp_event_deliveries d WHERE d.subscription_id=s.id ORDER BY last_attempt_at DESC,event_id LIMIT 1) FROM mcp_event_subscriptions s WHERE profile_id=? AND principal_id=? ORDER BY created_at,id`, s.cfg.ProfileID, s.cfg.OwnerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EventMonitor{}
	for rows.Next() {
		var x EventMonitor
		var args string
		var expiry, active int64
		var oldest, lastAttempt, lastReceipt, lastHTTP sql.NullInt64
		if err := rows.Scan(&x.ID, &args, &x.State, &x.Generation, &expiry, &active, &x.Suppressed, &x.Overflow, &x.LastErrorCode, &x.Pending, &x.Accepted, &x.Failed, &oldest, &lastAttempt, &lastReceipt, &lastHTTP); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(args), &x.Filter); err != nil {
			return nil, errors.New("monitor filter unavailable")
		}
		x.EventsEnabled = !s.isClosing()
		x.ProducerConnected = s.cfg.WA != nil && s.cfg.WA.Client.IsConnected()
		if oldest.Valid {
			x.OldestPendingAgeSeconds = int64(s.cfg.Now().Sub(time.UnixMilli(oldest.Int64)) / time.Second)
			if x.OldestPendingAgeSeconds < 0 {
				x.OldestPendingAgeSeconds = 0
			}
		}
		if lastAttempt.Int64 > 0 {
			at := time.UnixMilli(lastAttempt.Int64)
			x.LastAttemptAt = &at
		}
		if lastReceipt.Int64 > 0 {
			at := time.UnixMilli(lastReceipt.Int64)
			x.LastReceiptAt = &at
		}
		x.LastHTTPStatus = int(lastHTTP.Int64)
		x.ReceiptStatus = "unknown"
		if x.LastHTTPStatus >= 200 && x.LastHTTPStatus < 300 {
			x.ReceiptStatus = "accepted"
		} else if x.LastHTTPStatus != 0 {
			x.ReceiptStatus = "not_accepted"
		}
		s.mu.Lock()
		if x.LastErrorCode == "" {
			x.LastErrorCode = s.workerError
		}
		s.mu.Unlock()
		x.ExpiresAt = time.UnixMilli(expiry)
		x.ActivatedAt = time.UnixMilli(active)
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *EventService) revokeAll(ctx context.Context, code string) error {
	return s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE mcp_event_subscriptions SET state='revoked',generation=generation+1,last_error_code=?,updated_at=? WHERE profile_id=? AND principal_id=?`, code, s.cfg.Now().UnixMilli(), s.cfg.ProfileID, s.cfg.OwnerID)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mcp_event_deliveries SET state='canceled',last_error_code=? WHERE state IN ('pending','leased') AND subscription_id IN (SELECT id FROM mcp_event_subscriptions WHERE profile_id=? AND principal_id=?)`, code, s.cfg.ProfileID, s.cfg.OwnerID)
		return err
	})
}
func (s *EventService) enqueueTx(ctx context.Context, tx *sql.Tx, in archiveInput) error {
	if !in.live || in.kind != "original" || in.m.FromMe || s.isClosing() || (s.cfg.WA != nil && s.cfg.WA.loggedOut.Load()) {
		return nil
	}
	if _, _, err := accessTx(ctx, tx, s.cfg.ProfileID, s.cfg.OwnerID); err != nil {
		return nil
	}
	now := s.cfg.Now()
	rows, err := tx.QueryContext(ctx, `SELECT id,arguments_json,activated_at,expires_at FROM mcp_event_subscriptions WHERE profile_id=? AND principal_id=? AND state='active'`, s.cfg.ProfileID, s.cfg.OwnerID)
	if err != nil {
		return err
	}
	type candidate struct {
		id, args        string
		active, expires int64
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.args, &c.active, &c.expires); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var ids []string
	for _, c := range candidates {
		if c.expires <= now.UnixMilli() {
			if err := s.cancelTx(ctx, tx, c.id, "expired", "expired"); err != nil {
				return err
			}
			continue
		}
		var f EventFilter
		if err := json.Unmarshal([]byte(c.args), &f); err != nil {
			return err
		}
		match := func(list []string, v string) (bool, error) {
			if len(list) == 0 {
				return true, nil
			}
			for _, target := range list {
				canonical, err := canonicalTx(ctx, tx, target)
				if err != nil {
					return false, err
				}
				if canonical == v {
					return true, nil
				}
			}
			return false, nil
		}
		chat, e := match(f.ChatJIDs, in.m.ChatJID)
		if e != nil {
			return e
		}
		sender, e := match(f.SenderJIDs, in.m.SenderJID)
		if e != nil {
			return e
		}
		if !chat || !sender {
			continue
		}
		if in.m.Timestamp.Before(time.UnixMilli(c.active).Add(-5*time.Second)) || in.m.Timestamp.After(now.Add(5*time.Minute)) {
			if _, err := tx.ExecContext(ctx, `UPDATE mcp_event_subscriptions SET suppressed_count=suppressed_count+1 WHERE id=?`, c.id); err != nil {
				return err
			}
			continue
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mcp_event_deliveries d JOIN mcp_event_subscriptions s ON s.id=d.subscription_id WHERE s.profile_id=? AND s.principal_id=? AND d.state IN ('pending','leased')`, s.cfg.ProfileID, s.cfg.OwnerID).Scan(&n); err != nil {
			return err
		}
		if n+len(ids) >= s.cfg.PendingLimit {
			if err := s.cancelTx(ctx, tx, c.id, "failed", "queue_overflow"); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE mcp_event_subscriptions SET overflow_count=overflow_count+1 WHERE id=?`, c.id); err != nil {
				return err
			}
			continue
		}
		ids = append(ids, c.id)
	}
	if len(ids) == 0 {
		return nil
	}
	id, err := s.randomID("evt_")
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"eventId": id, "name": eventName, "timestamp": in.m.Timestamp.UTC().Format(time.RFC3339Nano), "data": map[string]any{"chat_jid": in.m.ChatJID, "sender_jid": in.m.SenderJID, "message_id": in.m.ID, "kind": in.m.Kind, "observed_at": now.UTC().Format(time.RFC3339Nano)}, "cursor": nil})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_event_outbox(event_id,initial_origin_chat_jid,message_id,chat_jid,sender_jid,occurred_at,observed_at,kind,body_bytes) VALUES(?,?,?,?,?,?,?,?,?)`, id, in.m.ChatJID, in.m.ID, in.m.ChatJID, in.m.SenderJID, in.m.Timestamp.UnixMilli(), now.UnixMilli(), in.m.Kind, body); err != nil {
		return err
	}
	for _, sub := range ids {
		if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_event_deliveries(subscription_id,event_id,state,next_attempt_at,created_at) VALUES(?,?,'pending',?,?)`, sub, id, now.UnixMilli(), now.UnixMilli()); err != nil {
			return err
		}
	}
	return nil
}
func reconcileEventAliasTx(ctx context.Context, tx *sql.Tx, lid, pn string) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mcp_event_outbox'`).Scan(&n); err != nil || n == 0 {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mcp_event_outbox SET chat_jid=CASE WHEN chat_jid=? THEN ? ELSE chat_jid END,sender_jid=CASE WHEN sender_jid=? THEN ? ELSE sender_jid END WHERE chat_jid=? OR sender_jid=?`, lid, pn, lid, pn, lid, lid); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE mcp_event_deliveries AS d SET state='superseded',last_error_code='alias_duplicate' WHERE d.state='pending' AND EXISTS(SELECT 1 FROM mcp_event_deliveries prior JOIN mcp_event_outbox po ON po.event_id=prior.event_id JOIN mcp_event_outbox current ON current.event_id=d.event_id WHERE prior.subscription_id=d.subscription_id AND prior.event_id<>d.event_id AND po.chat_jid=current.chat_jid AND po.message_id=current.message_id AND (prior.state='accepted' OR (prior.state IN ('pending','leased') AND po.seq<current.seq)))`)
	return err
}
