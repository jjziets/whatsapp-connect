//go:build libsqlite3

package main

import (
	"context"
	"testing"
)

// Existing real lock fixture and composition; no native key lookup or account.
func TestOwnerEventsExplicitAuthenticatedReaderFailsClosed(t *testing.T) {
	app, _, _ := evOwnedApp(t)
	reader := &App{store: app.store, mode: "read-only"}
	rt, err := composeEventServe(context.Background(), reader, func() {}, EventConfig{Enabled: true, Transport: "http", Owner: true})
	if err == nil {
		if rt != nil {
			_ = rt.Close(context.Background())
		}
		t.Fatal("explicit authenticated Events reader silently returned unauthenticated HTTP handler; require startup failure")
	}
}
