package eventdelivery

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
)

// IANA's global-unicast registry reserves unallocated space within 2000::/3.
// A broad /3 allow rule alone admits 6bone and future-allocation destinations.
func TestRejectReservedIPv6AllocationViaRealHTTPSPath(t *testing.T) {
	for _, address := range []string{"3000::1", "3ffe:831f::1", "2001:1000::1", "2d00::1"} {
		t.Run(address, func(t *testing.T) {
			h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
			h.cfg.Resolver = &testResolver{answers: [][]netip.Addr{ips(address)}}
			_, err := h.client(t).Send(context.Background(), request())
			requireCode(t, err, "blocked_address")
			h.mu.Lock()
			defer h.mu.Unlock()
			if len(h.dials) != 0 {
				t.Fatal("reserved allocation was dialed")
			}
		})
	}
	t.Run("allocated-public-ipv6", func(t *testing.T) {
		h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
		h.cfg.Resolver = &testResolver{answers: [][]netip.Addr{ips("2606:4700::1")}}
		got, err := h.client(t).Send(context.Background(), request())
		if err != nil || got.StatusCode != 204 {
			t.Fatalf("public allocation rejected: %+v %v", got, err)
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if len(h.dials) != 1 || h.dials[0] != "[2606:4700::1]:443" {
			t.Fatal("IPv6 was not pinned")
		}
	})
}
