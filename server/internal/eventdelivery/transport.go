package eventdelivery

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

func validateURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 8192 || strings.ContainsAny(raw, "#\\") {
		return nil, deliveryError("invalid_url")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return nil, deliveryError("invalid_url")
	}
	host := u.Hostname()
	if host == "" || strings.HasSuffix(u.Host, ":") {
		return nil, deliveryError("invalid_url")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if !publicAddress(addr) {
			return nil, deliveryError("blocked_address")
		}
		return u, nil
	}
	if strings.ContainsAny(host, ":%") || len(host) > 253 {
		return nil, deliveryError("invalid_url")
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, deliveryError("invalid_url")
		}
		for _, ch := range []byte(label) {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return nil, deliveryError("invalid_url")
			}
		}
	}
	return u, nil
}

// Conservative special-purpose exclusions. Reject entire reserved blocks even
// where IANA documents individual globally reachable exceptions. IPv6 is limited
// to current global-unicast 2000::/3, with special transition/documentation ranges
// removed. This intentionally fails closed on future allocations until reviewed.
// Registries checked 2026-11-06:
// https://www.iana.org/assignments/iana-ipv4-special-registry
// https://www.iana.org/assignments/iana-ipv6-special-registry
// https://www.iana.org/assignments/ipv6-unicast-address-assignments
var excludedPrefixes = func() []netip.Prefix {
	values := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"2001::/23", "2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3fff::/20",
	}
	result := make([]netip.Prefix, len(values))
	for i, value := range values {
		result[i] = netip.MustParsePrefix(value)
	}
	return result
}()

// Positive allocation list also excludes reserved holes inside 2000::/3.
// New allocations require a policy update, rather than silently becoming allowed.
var allocatedIPv6Prefixes = func() []netip.Prefix {
	values := []string{
		"2001:200::/23", "2001:400::/23", "2001:600::/23", "2001:800::/22", "2001:c00::/23", "2001:e00::/23",
		"2001:1200::/23", "2001:1400::/22", "2001:1800::/23", "2001:1a00::/23", "2001:1c00::/22", "2001:2000::/19",
		"2001:4000::/23", "2001:4200::/23", "2001:4400::/23", "2001:4600::/23", "2001:4800::/23", "2001:4a00::/23", "2001:4c00::/23",
		"2001:5000::/20", "2001:8000::/19", "2001:a000::/20", "2001:b000::/20", "2003::/18",
		"2400::/12", "2410::/12", "2600::/12", "2610::/23", "2620::/23", "2630::/12", "2800::/12", "2a00::/12", "2a10::/12", "2c00::/12",
	}
	result := make([]netip.Prefix, len(values))
	for i, value := range values {
		result[i] = netip.MustParsePrefix(value)
	}
	return result
}()

func publicAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	if address.Is6() {
		allocated := false
		for _, prefix := range allocatedIPv6Prefixes {
			if prefix.Contains(address) {
				allocated = true
				break
			}
		}
		if !allocated {
			return false
		}
	}
	for _, prefix := range excludedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func (c *Client) transport() *http.Transport {
	return &http.Transport{
		Proxy:       nil,
		DialContext: c.dial,
		DialTLSContext: func(ctx context.Context, network, authority string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(authority)
			if err != nil {
				return nil, deliveryError("invalid_url")
			}
			conn, err := c.dial(ctx, network, authority)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.cfg.RootCAs, ServerName: host})
			tlsCtx, cancel := context.WithTimeout(ctx, c.cfg.TLSHandshakeTimeout)
			defer cancel()
			if err = tlsConn.HandshakeContext(tlsCtx); err != nil {
				conn.Close()
				if tlsCtx.Err() != nil || Code(err) == "timeout" {
					return nil, deliveryError("timeout")
				}
				return nil, deliveryError("tls_failed")
			}
			return tlsConn, nil
		},
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxIdleConns:      4, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 4,
		IdleConnTimeout:        30 * time.Second,
		ResponseHeaderTimeout:  c.cfg.ResponseHeaderTimeout,
		MaxResponseHeaderBytes: 8192,
	}
}
func (c *Client) dial(ctx context.Context, network, authority string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil || port != "443" {
		return nil, deliveryError("invalid_url")
	}
	addresses := []netip.Addr{}
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = append(addresses, literal)
	} else {
		dnsCtx, cancel := context.WithTimeout(ctx, c.cfg.DNSTimeout)
		addresses, err = c.cfg.Resolver.LookupNetIP(dnsCtx, "ip", host)
		timedOut := dnsCtx.Err() != nil
		cancel()
		if timedOut || Code(err) == "timeout" {
			return nil, deliveryError("timeout")
		}
		if err != nil || len(addresses) == 0 {
			return nil, deliveryError("dns_failed")
		}
	}
	// Validate the complete answer set before performing any connection attempt.
	for _, address := range addresses {
		if !publicAddress(address) {
			return nil, deliveryError("blocked_address")
		}
	}
	connectCtx, cancel := context.WithTimeout(ctx, c.cfg.ConnectTimeout)
	defer cancel()
	conn, err := c.cfg.DialContext(connectCtx, network, net.JoinHostPort(addresses[0].String(), "443"))
	if err != nil {
		if connectCtx.Err() != nil || Code(err) == "timeout" {
			return nil, deliveryError("timeout")
		}
		return nil, deliveryError("connect_failed")
	}
	if conn == nil {
		return nil, deliveryError("connect_failed")
	}
	return conn, nil
}
