// Package eventdelivery implements the transport/signing/verification subset of
// REQ-WC-006. Subscription authorization, persistence and retries belong to callers.
package eventdelivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBody = 262144
const maxResponse = 8192
const maxRetryAfter = 15 * time.Minute

// Resolver is a trusted dependency; implementations must honor context cancellation.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// Config permits trusted dependency injection, never a destination-policy bypass.
// Zero timeouts select defaults. Positive values may only shorten those defaults.
type Config struct {
	Resolver              Resolver
	DialContext           func(context.Context, string, string) (net.Conn, error)
	RootCAs               *x509.CertPool
	Now                   func() time.Time
	Random                io.Reader
	RequestTimeout        time.Duration
	DNSTimeout            time.Duration
	ConnectTimeout        time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
}

// Client is safe for concurrent use when its injected dependencies are also safe.
type Client struct {
	cfg      Config
	http     *http.Client
	randomMu sync.Mutex
}

type Request struct {
	URL            string
	SubscriptionID string
	EventID        string
	Body           []byte
	Secrets        []string
}

// Receipt acknowledges transport receipt only, never a Dot run or notification.
type Receipt struct {
	StatusCode int
	RetryAfter time.Duration
}

type deliveryError string

func (e deliveryError) Error() string { return "callback " + string(e) }

// Code returns a bounded reason suitable for protocol adapters, without details.
func Code(err error) string {
	if err == nil {
		return ""
	}
	var coded deliveryError
	if errors.As(err, &coded) {
		return string(coded)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	return "transport_failed"
}

func New(cfg Config) (*Client, error) {
	defaults := []struct {
		value *time.Duration
		max   time.Duration
	}{
		{&cfg.RequestTimeout, 10 * time.Second}, {&cfg.DNSTimeout, 2 * time.Second},
		{&cfg.ConnectTimeout, 2 * time.Second}, {&cfg.TLSHandshakeTimeout, 3 * time.Second},
		{&cfg.ResponseHeaderTimeout, 3 * time.Second},
	}
	for _, field := range defaults {
		if *field.value < 0 || *field.value > field.max {
			return nil, deliveryError("invalid_config")
		}
		if *field.value == 0 {
			*field.value = field.max
		}
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.DialContext == nil {
		cfg.DialContext = (&net.Dialer{Timeout: cfg.ConnectTimeout}).DialContext
	}
	if cfg.RootCAs != nil {
		cfg.RootCAs = cfg.RootCAs.Clone()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	c := &Client{cfg: cfg}
	c.http = &http.Client{Transport: c.transport(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c, nil
}

// Send signs exactly one frozen event. The caller owns verification and lifecycle.
func (c *Client) Send(ctx context.Context, q Request) (Receipt, error) {
	if !validID(q.SubscriptionID) || !validID(q.EventID) || len(q.Body) == 0 || len(q.Body) > maxBody {
		return Receipt{}, deliveryError("invalid_request")
	}
	body := append([]byte(nil), q.Body...)
	var event struct {
		EventID string `json:"eventId"`
	}
	if !json.Valid(body) || json.Unmarshal(body, &event) != nil || event.EventID != q.EventID {
		return Receipt{}, deliveryError("invalid_request")
	}
	keys, err := decodeKeys(q.Secrets)
	if err != nil {
		return Receipt{}, err
	}
	return c.post(ctx, q.URL, q.SubscriptionID, q.EventID, body, keys)
}

// Verify consumes a fresh challenge within this call only. It creates no grant or cache.
func (c *Client) Verify(ctx context.Context, callbackURL, subscriptionID, secret string) error {
	if !validID(subscriptionID) {
		return deliveryError("invalid_request")
	}
	if _, err := validateURL(callbackURL); err != nil {
		return err
	}
	keys, err := decodeKeys([]string{secret})
	if err != nil {
		return err
	}
	entropy := make([]byte, 48)
	c.randomMu.Lock()
	_, err = io.ReadFull(c.cfg.Random, entropy)
	c.randomMu.Unlock()
	if err != nil {
		return deliveryError("random_failed")
	}
	challenge := base64.RawURLEncoding.EncodeToString(entropy[:32])
	id := "msg_verification_" + base64.RawURLEncoding.EncodeToString(entropy[32:])
	body, err := json.Marshal(struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}{"verification", challenge})
	if err != nil {
		return deliveryError("invalid_request")
	}
	started := c.cfg.Now()
	response, data, err := c.exchange(ctx, callbackURL, subscriptionID, id, body, keys)
	if err != nil {
		return err
	}
	elapsed := c.cfg.Now().Sub(started)
	var echo struct {
		Challenge string `json:"challenge"`
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || elapsed < 0 || elapsed >= 30*time.Second || json.Unmarshal(data, &echo) != nil {
		return deliveryError("challenge_failed")
	}
	if subtle.ConstantTimeCompare([]byte(challenge), []byte(echo.Challenge)) != 1 {
		return deliveryError("challenge_failed")
	}
	return nil
}

func (c *Client) post(ctx context.Context, url, subscriptionID, id string, body []byte, keys [][]byte) (Receipt, error) {
	receipt, _, err := c.exchange(ctx, url, subscriptionID, id, body, keys)
	return receipt, err
}

func (c *Client) exchange(ctx context.Context, callbackURL, subscriptionID, id string, body []byte, keys [][]byte) (Receipt, []byte, error) {
	target, err := validateURL(callbackURL)
	if err != nil {
		return Receipt{}, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()
	timestamp := strconv.FormatInt(c.cfg.Now().Unix(), 10)
	signatures := make([]string, len(keys))
	for i, key := range keys {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(id + "." + timestamp + "."))
		mac.Write(body)
		signatures[i] = "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return Receipt{}, nil, deliveryError("invalid_url")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", timestamp)
	req.Header.Set("webhook-signature", strings.Join(signatures, " "))
	req.Header.Set("X-MCP-Subscription-Id", subscriptionID)
	response, err := c.http.Do(req)
	if err != nil {
		return Receipt{}, nil, deliveryError(Code(err))
	}
	defer response.Body.Close()
	// The request context remains alive through this read, bounding a stalled body.
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		return Receipt{}, nil, deliveryError(Code(err))
	}
	if len(data) > maxResponse {
		return Receipt{}, nil, deliveryError("response_too_large")
	}
	receipt := Receipt{StatusCode: response.StatusCode, RetryAfter: retryAfter(response.Header.Get("Retry-After"), c.cfg.Now())}
	return receipt, data, nil
}

func decodeKeys(secrets []string) ([][]byte, error) {
	if len(secrets) < 1 || len(secrets) > 2 {
		return nil, deliveryError("invalid_secret")
	}
	keys := make([][]byte, len(secrets))
	for i, secret := range secrets {
		if !strings.HasPrefix(secret, "whsec_") || len(secret) > 94 {
			return nil, deliveryError("invalid_secret")
		}
		encoded := strings.TrimPrefix(secret, "whsec_")
		key, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(key) < 24 || len(key) > 64 || base64.StdEncoding.EncodeToString(key) != encoded {
			return nil, deliveryError("invalid_secret")
		}
		keys[i] = key
	}
	return keys, nil
}
func validID(id string) bool {
	if len(id) == 0 || len(id) > 256 {
		return false
	}
	for _, b := range []byte(id) {
		if b < 32 || b == 127 {
			return false
		}
	}
	return true
}
func retryAfter(value string, now time.Time) time.Duration {
	if value == "" {
		return 0
	}
	// Bound numeric input before multiplying; large valid delays saturate.
	if len(value) <= 32 {
		if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
			if seconds >= uint64(maxRetryAfter/time.Second) {
				return maxRetryAfter
			}
			return time.Duration(seconds) * time.Second
		}
	}
	if date, err := http.ParseTime(value); err == nil {
		delta := date.Sub(now)
		if delta > maxRetryAfter {
			return maxRetryAfter
		}
		if delta > 0 {
			return delta
		}
	}
	return 0
}
