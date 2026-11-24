//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/hansen/whatsapp-mcp/internal/eventdelivery"
	"sync"
	"testing"
)

func TestEventsTerminalResponseAfterRefresh(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 408, 410, 413, 422, 429} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			h := evSetup(t, 0)
			r := evReq(alice.String(), "")
			evSub(t, h, r)
			h.sender.receipt = eventdelivery.Receipt{StatusCode: status}
			var once sync.Once
			h.sender.beforeSend = func() {
				once.Do(func() {
					r.Delivery.Secret = "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32))
					if _, e := h.s.Subscribe(context.Background(), r); e != nil {
						t.Error(e)
					}
				})
			}
			evLive(h, alice, alice, "terminal-after-refresh", h.clock.Now())
			evDispatch(t, h)
			evDispatch(t, h)
			if status == 408 || status == 429 {
				if n := len(h.sender.requests()); n != 2 {
					t.Fatalf("transient HTTP%d did not retry after subscription refresh: %d sends", status, n)
				}
				return
			}
			if n := len(h.sender.requests()); n != 1 {
				t.Fatalf("terminal HTTP%d retried after subscription refresh: %d sends", status, n)
			}
		})
	}
}
