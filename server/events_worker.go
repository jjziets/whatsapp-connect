package main

// REQ-WC-005/006/008/009: one owner, durable leases, bounded at-least-once delivery.
import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"github.com/hansen/whatsapp-mcp/internal/eventdelivery"
	"sync"
	"time"
)

type eventJob struct {
	sub, event, url, key, old, auth        string
	body                                   []byte
	rotation, expires, generation, created int64
	authGeneration                         int64
	attempt                                int
}

func refill(b *eventBucket, now time.Time, rate, burst float64) {
	if b.at.IsZero() {
		b.at = now
		b.tokens = burst
	}
	elapsed := now.Sub(b.at).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rate
		if b.tokens > burst {
			b.tokens = burst
		}
		b.at = now
	}
}
func (s *EventService) reserve(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || len(s.running) >= 4 || s.running[id] {
		return false
	}
	now := s.cfg.Now()
	refill(&s.global, now, 20, 20)
	b := s.buckets[id]
	if b == nil {
		b = &eventBucket{}
		s.buckets[id] = b
	}
	refill(b, now, 5, 10)
	if s.global.tokens < 1 || b.tokens < 1 {
		return false
	}
	s.global.tokens--
	b.tokens--
	s.running[id] = true
	return true
}
func (s *EventService) release(j eventJob) {
	s.mu.Lock()
	delete(s.running, j.sub)
	for _, ref := range []string{j.key, j.old, j.auth} {
		if ref != "" {
			s.pinned[ref]--
			if s.pinned[ref] <= 0 {
				delete(s.pinned, ref)
			}
		}
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	s.Wake()
}
func (s *EventService) claim(ctx context.Context) ([]eventJob, error) {
	now := s.cfg.Now().UnixMilli()
	err := s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, `SELECT id FROM mcp_event_subscriptions WHERE profile_id=? AND principal_id=? AND state='active' AND expires_at<=?`, s.cfg.ProfileID, s.cfg.OwnerID, now)
		if e != nil {
			return e
		}
		var ids []string
		for rows.Next() {
			var id string
			if e := rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, id := range ids {
			if e := s.cancelTx(ctx, tx, id, "expired", "expired"); e != nil {
				return e
			}
		}
		_, e = tx.ExecContext(ctx, `UPDATE mcp_event_deliveries SET state='failed',last_error_code='delivery_exhausted' WHERE state IN ('pending','leased') AND (attempt_count>=10 OR created_at<=?) AND subscription_id IN (SELECT id FROM mcp_event_subscriptions WHERE profile_id=? AND principal_id=?)`, now-int64(24*time.Hour/time.Millisecond), s.cfg.ProfileID, s.cfg.OwnerID)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `UPDATE mcp_event_subscriptions SET last_error_code='delivery_exhausted' WHERE profile_id=? AND principal_id=? AND EXISTS(SELECT 1 FROM mcp_event_deliveries d WHERE d.subscription_id=mcp_event_subscriptions.id AND d.last_error_code='delivery_exhausted')`, s.cfg.ProfileID, s.cfg.OwnerID)
		return e
	})
	if err != nil {
		return nil, err
	}
	rows, err := s.cfg.Store.db.QueryContext(ctx, `WITH heads AS (SELECT d.subscription_id,d.event_id,d.next_attempt_at,d.created_at,ROW_NUMBER() OVER(PARTITION BY d.subscription_id ORDER BY d.next_attempt_at,d.created_at,d.event_id) AS head FROM mcp_event_deliveries d JOIN mcp_event_subscriptions s ON s.id=d.subscription_id WHERE s.profile_id=? AND s.principal_id=? AND s.state='active' AND s.expires_at>? AND ((d.state='pending' AND d.next_attempt_at<=?) OR(d.state='leased' AND d.lease_until<=?)) AND NOT EXISTS(SELECT 1 FROM mcp_event_deliveries busy WHERE busy.subscription_id=d.subscription_id AND busy.state='leased' AND busy.lease_until>?)) SELECT subscription_id,event_id FROM heads WHERE head=1 ORDER BY next_attempt_at,created_at,event_id LIMIT 128`, s.cfg.ProfileID, s.cfg.OwnerID, now, now, now, now)
	if err != nil {
		return nil, err
	}
	type pair struct{ sub, event string }
	var candidates []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.sub, &p.event); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	var jobs []eventJob
	for _, p := range candidates {
		if !s.reserve(p.sub) {
			continue
		}
		j := eventJob{sub: p.sub, event: p.event}
		err := s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
			j = eventJob{sub: p.sub, event: p.event}
			ref, authGeneration, e := accessTx(ctx, tx, s.cfg.ProfileID, s.cfg.OwnerID)
			if e != nil {
				return e
			}
			j.auth = ref
			j.authGeneration = authGeneration
			var state string
			e = tx.QueryRowContext(ctx, `SELECT s.callback_url,s.key_ref,s.old_key_ref,s.rotation_until,s.expires_at,s.generation,d.created_at,d.attempt_count,d.state,o.body_bytes FROM mcp_event_subscriptions s JOIN mcp_event_deliveries d ON d.subscription_id=s.id JOIN mcp_event_outbox o ON o.event_id=d.event_id WHERE s.id=? AND d.event_id=? AND s.state='active'`, p.sub, p.event).Scan(&j.url, &j.key, &j.old, &j.rotation, &j.expires, &j.generation, &j.created, &j.attempt, &state, &j.body)
			if e != nil {
				return e
			}
			res, e := tx.ExecContext(ctx, `UPDATE mcp_event_deliveries SET state='leased',attempt_count=attempt_count+1,lease_until=?,last_attempt_at=? WHERE subscription_id=? AND event_id=? AND ((state='pending' AND next_attempt_at<=?) OR (state='leased' AND lease_until<=?))`, now+60000, now, p.sub, p.event, now, now)
			if e != nil {
				return e
			}
			n, e := res.RowsAffected()
			if e != nil {
				return e
			}
			if n != 1 {
				return errors.New("lease unavailable")
			}
			return nil
		})
		if err != nil {
			// Only the subscription reservation exists: this failed candidate
			// never acquired credential pins belonging to other running jobs.
			s.release(eventJob{sub: p.sub})
			continue
		}
		s.mu.Lock()
		for _, ref := range []string{j.key, j.old, j.auth} {
			if ref != "" {
				s.pinned[ref]++
			}
		}
		s.mu.Unlock()
		jobs = append(jobs, j)
		if len(jobs) == 4 {
			break
		}
	}
	return jobs, nil
}
func (s *EventService) finishJob(ctx context.Context, j eventJob, receipt eventdelivery.Receipt, code string) error {
	now := s.cfg.Now()
	base := time.Second * time.Duration(1<<min(j.attempt, 10))
	if base > 15*time.Minute {
		base = 15 * time.Minute
	}
	delay := base
	if base > time.Second {
		var entropy [1]byte
		s.randomMu.Lock()
		_, e := s.cfg.Random.Read(entropy[:])
		s.randomMu.Unlock()
		if e == nil {
			delay = time.Second + time.Duration(float64(base-time.Second)*float64(entropy[0])/255)
		}
	}
	return s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
		code := code
		status := receipt.StatusCode
		current, e := subTx(ctx, tx, j.sub, s.cfg.ProfileID, s.cfg.OwnerID)
		if e != nil {
			return e
		}
		auth, authGeneration, accessErr := accessTx(ctx, tx, s.cfg.ProfileID, s.cfg.OwnerID)
		changed := current.generation != j.generation || current.key != j.key || current.old != j.old || auth != j.auth || authGeneration != j.authGeneration
		if changed && !(status >= 200 && status < 300 && code == "") {
			if status >= 400 && status < 500 && status != 408 && status != 429 {
				// Nonretryable 4xx responses are terminal for this immutable delivery even
				// after a refresh. An old response cannot revoke the newer monitor.
				if current.generation != j.generation {
					terminalCode := "callback_rejected"
					if status == 410 {
						terminalCode = "callback_gone"
					}
					_, e = tx.ExecContext(ctx, `UPDATE mcp_event_deliveries SET state=CASE WHEN state='canceled' THEN state ELSE 'failed' END,lease_until=0,last_http_status=?,last_error_code=? WHERE subscription_id=? AND event_id=?`, status, terminalCode, j.sub, j.event)
					return e
				}
				// Same monitor generation (e.g. only access token rotated): use
				// normal 410 revocation or terminal 4xx classification below.
			} else {
				if accessErr == nil && current.state == "active" && current.expires > now.UnixMilli() {
					_, e = tx.ExecContext(ctx, `UPDATE mcp_event_deliveries SET state='pending',lease_until=0,next_attempt_at=?,last_http_status=?,last_error_code='generation_changed' WHERE subscription_id=? AND event_id=? AND state='leased'`, now.UnixMilli(), status, j.sub, j.event)
				}
				return e
			}
		}
		state := "pending"
		next := now.Add(delay)
		if receipt.RetryAfter > 0 {
			d := receipt.RetryAfter
			if d > 15*time.Minute {
				d = 15 * time.Minute
			}
			next = now.Add(d)
		}
		if next.After(now.Add(15 * time.Minute)) {
			next = now.Add(15 * time.Minute)
		}
		accepted := int64(0)
		if status >= 200 && status < 300 && code == "" {
			state = "accepted"
			accepted = now.UnixMilli()
		} else if status == 410 {
			if err := s.cancelTx(ctx, tx, j.sub, "revoked", "callback_gone"); err != nil {
				return err
			}
			state = "canceled"
			code = "callback_gone"
		} else if status == 413 || (status >= 400 && status < 500 && status != 408 && status != 429) {
			state = "failed"
			code = "callback_rejected"
		} else if j.attempt+1 >= 10 || now.Sub(time.UnixMilli(j.created)) >= 24*time.Hour {
			state = "failed"
			code = "delivery_exhausted"
		} else if code == "" {
			code = "callback_retry"
		}
		// Stop/revoke can cancel a leased row while its HTTP request is already
		// admitted. Preserve receipt audit, but never reactivate canceled pending work.
		var previous string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM mcp_event_deliveries WHERE subscription_id=? AND event_id=?`, j.sub, j.event).Scan(&previous); err != nil {
			return err
		}
		if previous == "canceled" && state != "accepted" {
			state = "canceled"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mcp_event_deliveries SET state=?,next_attempt_at=?,lease_until=0,accepted_at=?,last_http_status=?,last_error_code=? WHERE subscription_id=? AND event_id=?`, state, next.UnixMilli(), accepted, status, code, j.sub, j.event); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE mcp_event_subscriptions SET last_error_code=? WHERE id=? AND generation=?`, code, j.sub, j.generation)
		return err
	})
}

// A claim is only a reservation. Recheck generation/ref snapshots both before
// and after native reads; keychain latency must not turn old keys into admission.
func (s *EventService) jobAdmission(ctx context.Context, j eventJob) (valid, stale bool, err error) {
	err = s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
		valid, stale = false, false
		auth, g, e := accessTx(ctx, tx, s.cfg.ProfileID, s.cfg.OwnerID)
		if e != nil {
			return nil
		}
		x, e := subTx(ctx, tx, j.sub, s.cfg.ProfileID, s.cfg.OwnerID)
		if e != nil {
			return e
		}
		var state string
		if e := tx.QueryRowContext(ctx, `SELECT state FROM mcp_event_deliveries WHERE subscription_id=? AND event_id=?`, j.sub, j.event).Scan(&state); e != nil {
			return e
		}
		if x.state != "active" || x.expires <= s.cfg.Now().UnixMilli() || state != "leased" {
			return nil
		}
		stale = x.generation != j.generation || x.key != j.key || x.old != j.old || x.rotation != j.rotation || auth != j.auth || g != j.authGeneration
		valid = !stale
		return nil
	})
	if s.isClosing() || (s.cfg.WA != nil && s.cfg.WA.loggedOut.Load()) {
		valid = false
	}
	return
}
func (s *EventService) requeueStale(ctx context.Context, j eventJob) error {
	err := s.cfg.Store.transaction(context.WithoutCancel(ctx), func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `UPDATE mcp_event_deliveries SET state='pending',lease_until=0,next_attempt_at=?,attempt_count=MAX(attempt_count-1,0),last_error_code='generation_changed' WHERE subscription_id=? AND event_id=? AND state='leased'`, s.cfg.Now().UnixMilli(), j.sub, j.event)
		return e
	})
	if err == nil {
		s.mu.Lock()
		s.global.tokens = min(s.global.tokens+1, 20)
		if bucket := s.buckets[j.sub]; bucket != nil {
			bucket.tokens = min(bucket.tokens+1, 10)
		}
		s.mu.Unlock()
		s.Wake()
	}
	return err
}
func (s *EventService) runJob(ctx context.Context, j eventJob) error {
	defer s.release(j)
	finish, err := s.admit()
	if err != nil {
		return nil
	}
	defer finish()
	check := func() (bool, error) {
		valid, stale, e := s.jobAdmission(ctx, j)
		if e != nil {
			return false, e
		}
		if stale {
			return false, s.requeueStale(ctx, j)
		}
		return valid, nil
	}
	valid, err := check()
	if err != nil || !valid {
		return err
	}
	key, keyErr := s.cfg.Secrets.Get(ctx, j.key)
	if keyErr == nil {
		_, keyErr = s.readAccessCredential(ctx, j.auth)
	}
	secrets := []string{"whsec_" + base64.StdEncoding.EncodeToString(key)}
	if keyErr == nil && j.old != "" && s.cfg.Now().UnixMilli() < j.rotation {
		var old []byte
		old, keyErr = s.cfg.Secrets.Get(ctx, j.old)
		if keyErr == nil {
			secrets = append(secrets, "whsec_"+base64.StdEncoding.EncodeToString(old))
		}
	}
	// This fence also handles a missing old ref caused by concurrent rotation/GC:
	// it is stale work, not a credential failure against the new generation.
	valid, err = check()
	if err != nil || !valid {
		return err
	}
	if keyErr != nil {
		return s.finishJob(context.WithoutCancel(ctx), j, eventdelivery.Receipt{}, "credential_unavailable")
	}
	receipt, sendErr := s.cfg.Sender.Send(ctx, eventdelivery.Request{URL: j.url, SubscriptionID: j.sub, EventID: j.event, Body: j.body, Secrets: secrets})
	if s.cfg.Hooks != nil && s.cfg.Hooks.BeforeReceiptCommit != nil {
		if err := s.cfg.Hooks.BeforeReceiptCommit(ctx, j.event); err != nil {
			return errors.New("receipt completion interrupted")
		}
	}
	code := ""
	if sendErr != nil {
		code = eventdelivery.Code(sendErr)
	}
	return s.finishJob(context.WithoutCancel(ctx), j, receipt, code)
}
func (s *EventService) DispatchOnce(ctx context.Context) (int, error) {
	finish, err := s.admit()
	if err != nil {
		return 0, err
	}
	defer finish()
	jobs, err := s.claim(ctx)
	if err != nil {
		return 0, err
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for _, j := range jobs {
		wg.Add(1)
		go func(j eventJob) {
			defer wg.Done()
			if err := s.runJob(ctx, j); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}(j)
	}
	wg.Wait()
	return len(jobs), errors.Join(errs...)
}
func (s *EventService) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return errors.New("events closing")
	}
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	ctx, s.cancel = context.WithCancel(ctx)
	s.loopDone = make(chan struct{})
	s.mu.Unlock()
	go func() {
		defer close(s.loopDone)
		lastPrune := time.Time{}
		for {
			if lastPrune.IsZero() || s.cfg.Now().Sub(lastPrune) >= time.Hour {
				_ = s.Prune(ctx)
				lastPrune = s.cfg.Now()
			}
			if ctx.Err() != nil {
				return
			}
			jobs, err := s.claim(ctx)
			if err == nil {
				for _, j := range jobs {
					go func(j eventJob) {
						if err := s.runJob(ctx, j); err != nil {
							s.reportWorkerError(err)
						}
					}(j)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-s.wake:
			case <-s.cfg.After(s.nextWait(ctx)):
			}
		}
	}()
	return nil
}
func (s *EventService) Close(ctx context.Context) error {
	s.mu.Lock()
	if !s.closing {
		s.closing = true
		if s.cancel != nil {
			s.cancel()
		}
	}
	var streams []context.CancelFunc
	for _, cancel := range s.streamCancels {
		streams = append(streams, cancel)
	}
	done := s.loopDone
	s.mu.Unlock()
	for _, cancel := range streams {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	stop := context.AfterFunc(ctx, func() { s.mu.Lock(); s.cond.Broadcast(); s.mu.Unlock() })
	defer stop()
	s.mu.Lock()
	for s.ops > 0 || len(s.running) > 0 {
		if err := ctx.Err(); err != nil {
			s.mu.Unlock()
			return err
		}
		s.cond.Wait()
	}
	s.mu.Unlock()
	s.cfg.Store.eventsMu.Lock()
	if s.cfg.Store.events == s {
		s.cfg.Store.events = nil
	}
	s.cfg.Store.eventsMu.Unlock()
	return nil
}
func (s *EventService) Prune(ctx context.Context) error {
	s.secretMu.Lock()
	defer s.secretMu.Unlock()
	now := s.cfg.Now().UnixMilli()
	err := s.cfg.Store.transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE mcp_event_deliveries SET state='failed',last_error_code='delivery_exhausted' WHERE state='pending' AND created_at<=? AND subscription_id IN (SELECT id FROM mcp_event_subscriptions WHERE profile_id=? AND principal_id=?)`, now-int64(24*time.Hour/time.Millisecond), s.cfg.ProfileID, s.cfg.OwnerID); err != nil {
			return err
		}
		s.mu.Lock()
		active := make(map[string]bool)
		for id := range s.running {
			active[id] = true
		}
		s.mu.Unlock()
		rows, err := tx.QueryContext(ctx, `SELECT subscription_id,event_id FROM mcp_event_deliveries WHERE state NOT IN ('pending','leased') AND MAX(accepted_at,created_at)<=? AND subscription_id IN (SELECT id FROM mcp_event_subscriptions WHERE profile_id=? AND principal_id=?)`, now-int64(7*24*time.Hour/time.Millisecond), s.cfg.ProfileID, s.cfg.OwnerID)
		if err != nil {
			return err
		}
		type p struct{ sub, event string }
		var drop []p
		for rows.Next() {
			var x p
			if err := rows.Scan(&x.sub, &x.event); err != nil {
				rows.Close()
				return err
			}
			if !active[x.sub] {
				drop = append(drop, x)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, x := range drop {
			if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_event_deliveries WHERE subscription_id=? AND event_id=?`, x.sub, x.event); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM mcp_event_outbox WHERE NOT EXISTS(SELECT 1 FROM mcp_event_deliveries d WHERE d.event_id=mcp_event_outbox.event_id)`)
		return err
	})
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	s.mu.Lock()
	for ref := range s.pinned {
		keep[ref] = true
	}
	s.mu.Unlock()
	rows, err := s.cfg.Store.db.QueryContext(ctx, `SELECT key_ref,old_key_ref,rotation_until,state,expires_at FROM mcp_event_subscriptions WHERE profile_id=?`, s.cfg.ProfileID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var key, old, state string
		var rotation, expires int64
		if err := rows.Scan(&key, &old, &rotation, &state, &expires); err != nil {
			rows.Close()
			return err
		}
		if (state == "active" || state == "paused") && expires > now {
			keep[key] = true
			if rotation > now && old != "" {
				keep[old] = true
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var auth string
	if err := s.cfg.Store.db.QueryRowContext(ctx, `SELECT key_ref FROM mcp_event_access WHERE profile_id=? AND state='active'`, s.cfg.ProfileID).Scan(&auth); err == nil {
		keep[auth] = true
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	refs, err := s.cfg.Secrets.ListRefs(ctx)
	if err != nil {
		return errors.New("credential metadata unavailable")
	}
	for _, ref := range refs {
		if !keep[ref] {
			if err := s.cleanupKey(ctx, ref); err != nil {
				return errors.New("credential cleanup unavailable")
			}
		}
	}
	return nil
}

// Post-commit wake drives new work. The timer follows durable retry/lease due
// times, with a short rate-refill wait only while eligible work is already due.
func (s *EventService) nextWait(ctx context.Context) time.Duration {
	var due sql.NullInt64
	err := s.cfg.Store.db.QueryRowContext(ctx, `SELECT MIN(CASE WHEN d.state='leased' THEN d.lease_until ELSE d.next_attempt_at END) FROM mcp_event_deliveries d JOIN mcp_event_subscriptions sub ON sub.id=d.subscription_id WHERE d.state IN ('pending','leased') AND sub.state='active' AND sub.profile_id=? AND sub.principal_id=?`, s.cfg.ProfileID, s.cfg.OwnerID).Scan(&due)
	if err != nil {
		return time.Second
	}
	if !due.Valid {
		return time.Minute
	}
	wait := time.UnixMilli(due.Int64).Sub(s.cfg.Now())
	if wait <= 0 {
		return 50 * time.Millisecond
	}
	if wait > time.Minute {
		return time.Minute
	}
	return wait
}

func (s *EventService) reportWorkerError(err error) {
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	s.mu.Lock()
	s.workerError = "events_worker_failed"
	s.mu.Unlock()
	if s.cfg.WA != nil {
		s.cfg.WA.log.Warn().Str("code", "events_worker_failed").Msg("event delivery needs attention")
	}
	_ = s.cfg.Store.recordFailure(context.Background(), "events_worker_failed")
}
