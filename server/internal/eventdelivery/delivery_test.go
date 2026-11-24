package eventdelivery

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const fixedSecret = "whsec_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
const fixedBody = `{"eventId":"evt_fixed","name":"whatsapp.message.created","data":{},"cursor":null}`

// Independently computed with Python3 hmac/hashlib (artifacts/delivery-hmac-vector.json).
const fixedSignature = "v1,cMqPVDdqccKSJgCD+QPdn65vpDpB0b5SpV4egVxidac="

var fixedNow = time.Unix(1700000000, 0)

type testResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr
	calls   int
	err     error
	wait    bool
}

func (r *testResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if r.wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	n := r.calls - 1
	if n >= len(r.answers) {
		n = len(r.answers) - 1
	}
	if n < 0 {
		return nil, nil
	}
	return r.answers[n], nil
}
func ips(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, v := range s {
		out[i] = netip.MustParseAddr(v)
	}
	return out
}

type wireRequest struct {
	header    http.Header
	body      []byte
	host, sni string
}
type harness struct {
	cfg    Config
	server *httptest.Server
	seen   chan wireRequest
	mu     sync.Mutex
	dials  []string
}

func newHarness(t *testing.T, handler func(http.ResponseWriter, *http.Request)) *harness {
	t.Helper()
	h := &harness{seen: make(chan wireRequest, 32)}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "callback.example"}, DNSNames: []string{"callback.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	h.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h.seen <- wireRequest{r.Header.Clone(), body, r.Host, r.TLS.ServerName}
		handler(w, r.WithContext(context.WithValue(r.Context(), bodyKey{}, body)))
	}))
	h.server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	h.server.StartTLS()
	t.Cleanup(h.server.Close)
	h.cfg = Config{Resolver: &testResolver{answers: [][]netip.Addr{ips("8.8.8.8")}}, RootCAs: roots, Now: func() time.Time { return fixedNow }, Random: rand.Reader,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			h.mu.Lock()
			h.dials = append(h.dials, address)
			h.mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, h.server.Listener.Addr().String())
		}}
	return h
}

type bodyKey struct{}

func (h *harness) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func request() Request {
	return Request{URL: "https://callback.example/private-callback", SubscriptionID: "sub_fixture", EventID: "evt_fixed", Body: []byte(fixedBody), Secrets: []string{fixedSecret}}
}
func requireCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || Code(err) != want {
		t.Fatalf("code=%q want=%q err=%v", Code(err), want, err)
	}
	if len(err.Error()) > 128 || strings.Contains(err.Error(), fixedSecret) || strings.Contains(err.Error(), "private-callback") || strings.Contains(err.Error(), fixedBody) {
		t.Fatalf("unsafe error text")
	}
}

func TestSignedFrozenDeliveryAndRotation(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) })
	now := fixedNow
	h.cfg.Now = func() time.Time { return now }
	c := h.client(t)
	q := request()
	for i := 0; i < 3; i++ {
		if i == 1 {
			now = now.Add(time.Second)
		}
		if i == 2 {
			q.Body = []byte(strings.Replace(fixedBody, "created", "creatEd", 1))
			q.Secrets = append(q.Secrets, "whsec_"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
		}
		receipt, err := c.Send(context.Background(), q)
		if err != nil || receipt.StatusCode != 202 {
			t.Fatalf("receipt=%+v err=%v", receipt, err)
		}
	}
	first, second, third := <-h.seen, <-h.seen, <-h.seen
	if string(first.body) != fixedBody || !bytes.Equal(first.body, second.body) || first.header.Get("webhook-signature") != fixedSignature {
		t.Fatal("literal vector or frozen body mismatch")
	}
	if second.header.Get("webhook-timestamp") != "1700000001" || second.header.Get("webhook-signature") != "v1,mVvCtkW6o8hW+bqb6kXAsptTYdykfXK/9OFUIi4syM0=" {
		t.Fatal("retry did not re-sign with current timestamp")
	}
	if third.header.Get("webhook-signature") == second.header.Get("webhook-signature") {
		t.Fatal("body mutation not signed")
	}
	if third.header.Get("webhook-signature") != "v1,tgjAz9wTxAyZ+oOBaYN3Zoyp+THSwS/Pz9/I47rhtoM= v1,Hkrc+4ak4ONL0ZUOcJLeb2LqJznYGU29vWUjYhIwFh4=" {
		t.Fatal("one-byte mutation/rotation literal vector mismatch")
	}
	signatures := strings.Split(third.header.Get("webhook-signature"), " ")
	if len(signatures) != 2 {
		t.Fatal("rotation needs exactly two signatures")
	}
	for _, s := range signatures {
		if !strings.HasPrefix(s, "v1,") {
			t.Fatal("signature version")
		}
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "v1,")); err != nil || len(raw) != 32 {
			t.Fatal("signature shape")
		}
	}
	for _, got := range []wireRequest{first, second, third} {
		if got.host != "callback.example" || got.sni != "callback.example" || got.header.Get("webhook-id") != "evt_fixed" || got.header.Get("X-MCP-Subscription-Id") != "sub_fixture" || got.header.Get("Content-Type") != "application/json" {
			t.Fatal("wire headers/host/SNI mismatch")
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, dial := range h.dials {
		if dial != "8.8.8.8:443" {
			t.Fatalf("dial was not pinned: %s", dial)
		}
	}
}

func TestRejectUnsafeURLDNSAndSecretsBeforeDial(t *testing.T) {
	cases := []struct {
		name, url, secret string
		answers           []netip.Addr
		code              string
	}{
		{"http", "http://callback.example/a", fixedSecret, ips("8.8.8.8"), "invalid_url"},
		{"port", "https://callback.example:8443/a", fixedSecret, ips("8.8.8.8"), "invalid_url"},
		{"userinfo", "https://u:p@callback.example/a", fixedSecret, ips("8.8.8.8"), "invalid_url"},
		{"fragment", "https://callback.example/a#x", fixedSecret, ips("8.8.8.8"), "invalid_url"},
		{"badsecret", "https://callback.example/a", "whsec_!", ips("8.8.8.8"), "invalid_secret"},
		{"shortsecret", "https://callback.example/a", "whsec_" + base64.StdEncoding.EncodeToString(make([]byte, 23)), ips("8.8.8.8"), "invalid_secret"},
		{"longsecret", "https://callback.example/a", "whsec_" + base64.StdEncoding.EncodeToString(make([]byte, 65)), ips("8.8.8.8"), "invalid_secret"},
	}
	for _, addr := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "0.0.0.0", "224.0.0.1", "240.0.0.1", "::1", "::", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "::ffff:8.8.8.8", "64:ff9b::808:808"} {
		cases = append(cases, struct {
			name, url, secret string
			answers           []netip.Addr
			code              string
		}{addr, "https://callback.example/a", fixedSecret, ips(addr), "blocked_address"})
	}
	cases = append(cases, struct {
		name, url, secret string
		answers           []netip.Addr
		code              string
	}{"mixed", "https://callback.example/a", fixedSecret, ips("8.8.8.8", "127.0.0.1"), "blocked_address"})
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unsafe request reached HTTP") })
			h.cfg.Resolver = &testResolver{answers: [][]netip.Addr{tt.answers}}
			c := h.client(t)
			q := request()
			q.URL = tt.url
			q.Secrets = []string{tt.secret}
			_, err := c.Send(context.Background(), q)
			requireCode(t, err, tt.code)
			requireCode(t, c.Verify(context.Background(), tt.url, "sub_fixture", tt.secret), tt.code)
			h.mu.Lock()
			defer h.mu.Unlock()
			if len(h.dials) != 0 {
				t.Fatal("unsafe destination dialed")
			}
		})
	}
}

func TestRebindingRedirectProxyAndTLSName(t *testing.T) {
	t.Run("rebind", func(t *testing.T) {
		h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Connection", "close")
			w.WriteHeader(204)
		})
		resolver := &testResolver{answers: [][]netip.Addr{ips("8.8.8.8"), ips("127.0.0.1")}}
		h.cfg.Resolver = resolver
		c := h.client(t)
		if _, err := c.Send(context.Background(), request()); err != nil {
			t.Fatal(err)
		}
		_, err := c.Send(context.Background(), request())
		requireCode(t, err, "blocked_address")
		h.mu.Lock()
		defer h.mu.Unlock()
		if len(h.dials) != 1 || resolver.calls != 2 {
			t.Fatal("new connection failed to revalidate DNS")
		}
	})
	t.Run("redirect-and-proxy", func(t *testing.T) {
		t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
		t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
		t.Setenv("NO_PROXY", "")
		h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://127.0.0.1/secret")
			w.WriteHeader(302)
		})
		receipt, err := h.client(t).Send(context.Background(), request())
		if err != nil || receipt.StatusCode != 302 {
			t.Fatalf("redirect/proxy: %+v %v", receipt, err)
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if len(h.dials) != 1 {
			t.Fatal("followed redirect")
		}
	})
	t.Run("wrong-TLS-name", func(t *testing.T) {
		h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid TLS accepted") })
		q := request()
		q.URL = "https://wrong.example/a"
		_, err := h.client(t).Send(context.Background(), q)
		requireCode(t, err, "tls_failed")
	})
}

func TestVerificationChallengeFreshSignedSingleUseAndBounded(t *testing.T) {
	for _, mode := range []string{"good", "wrong", "replay", "stale", "oversize", "slow", "non2xx", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			var now atomic.Int64
			now.Store(fixedNow.Unix())
			previous := ""
			count := 0
			h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
				count++
				body := r.Context().Value(bodyKey{}).([]byte)
				var payload struct{ Type, Challenge string }
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Error(err)
				}
				raw, err := base64.RawURLEncoding.DecodeString(payload.Challenge)
				if err != nil || len(raw) != 32 || payload.Type != "verification" {
					t.Error("invalid challenge")
				}
				if r.Header.Get("webhook-id") == "" || r.Header.Get("webhook-signature") == "" || r.Header.Get("X-MCP-Subscription-Id") != "sub_fixture" {
					t.Error("verification unsigned")
				}
				challenge := payload.Challenge
				switch mode {
				case "wrong":
					challenge = "wrong"
				case "replay":
					if count == 2 {
						challenge = previous
					}
				case "stale":
					now.Add(31)
				case "oversize":
					io.WriteString(w, strings.Repeat("x", 8193))
					return
				case "slow":
					<-r.Context().Done()
					return
				case "non2xx":
					w.WriteHeader(400)
				case "malformed":
					io.WriteString(w, "{")
					return
				}
				previous = payload.Challenge
				json.NewEncoder(w).Encode(map[string]string{"challenge": challenge})
			})
			h.cfg.Now = func() time.Time { return time.Unix(now.Load(), 0) }
			if mode == "slow" {
				h.cfg.RequestTimeout = 40 * time.Millisecond
			}
			c := h.client(t)
			err := c.Verify(context.Background(), "https://callback.example/private-callback", "sub_fixture", fixedSecret)
			switch mode {
			case "good", "replay":
				if err != nil {
					t.Fatal(err)
				}
			case "slow":
				requireCode(t, err, "timeout")
			case "oversize":
				requireCode(t, err, "response_too_large")
			default:
				requireCode(t, err, "challenge_failed")
			}
			if mode == "good" || mode == "replay" {
				err = c.Verify(context.Background(), "https://callback.example/private-callback", "sub_fixture", fixedSecret)
				if mode == "replay" {
					requireCode(t, err, "challenge_failed")
				} else if err != nil {
					t.Fatal(err)
				}
				a, b := <-h.seen, <-h.seen
				if bytes.Equal(a.body, b.body) || a.header.Get("webhook-id") == b.header.Get("webhook-id") {
					t.Fatal("challenge/id reused")
				}
			}
		})
	}
}

func TestDeliveryBoundsAndResponseSemantics(t *testing.T) {
	for _, tt := range []struct {
		status int
		retry  string
		want   time.Duration
	}{{200, "", 0}, {204, "", 0}, {408, "3", 3 * time.Second}, {429, "999999999", 15 * time.Minute}, {500, "Tue, 14 Nov 2023 22:13:25 GMT", 5 * time.Second}, {410, "-1", 0}, {413, "garbage", 0}, {400, "", 0}, {503, "Tue, 14 Nov 2023 22:13:00 GMT", 0}} {
		t.Run(http.StatusText(tt.status)+tt.retry, func(t *testing.T) {
			h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", tt.retry)
				w.WriteHeader(tt.status)
			})
			got, err := h.client(t).Send(context.Background(), request())
			if err != nil || got.StatusCode != tt.status || got.RetryAfter != tt.want {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
	t.Run("body-limit", func(t *testing.T) {
		h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
		c := h.client(t)
		q := request()
		prefix := `{"eventId":"evt_fixed","padding":"`
		suffix := `"}`
		q.Body = []byte(prefix + strings.Repeat("a", 262144-len(prefix)-len(suffix)) + suffix)
		if _, err := c.Send(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		q.Body = append(q.Body, ' ')
		_, err := c.Send(context.Background(), q)
		requireCode(t, err, "invalid_request")
		if len(h.seen) != 1 {
			t.Fatal("oversize sent")
		}
	})
	t.Run("response-limit", func(t *testing.T) {
		h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat("x", 8193)) })
		_, err := h.client(t).Send(context.Background(), request())
		requireCode(t, err, "response_too_large")
	})
	t.Run("DNS-timeout", func(t *testing.T) {
		h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {})
		h.cfg.Resolver = &testResolver{wait: true}
		h.cfg.DNSTimeout = 30 * time.Millisecond
		_, err := h.client(t).Send(context.Background(), request())
		requireCode(t, err, "timeout")
	})
	t.Run("random-fails-closed", func(t *testing.T) {
		h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { t.Error("request after entropy failure") })
		h.cfg.Random = failReader{}
		err := h.client(t).Verify(context.Background(), request().URL, "sub_fixture", fixedSecret)
		requireCode(t, err, "random_failed")
	})
	for _, duration := range []time.Duration{-1, time.Minute} {
		if _, err := New(Config{RequestTimeout: duration}); Code(err) != "invalid_config" {
			t.Fatalf("invalid timeout accepted: %v", err)
		}
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("synthetic entropy failure") }
