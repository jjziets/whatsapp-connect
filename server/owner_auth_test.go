//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Proposed new API. Undefined baseline symbols are missing-API evidence ONLY.
func TestOwnerHTTPAuthenticationAndPrebind(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	token := "Bearer " + base64.RawURLEncoding.EncodeToString(key)
	for _, tc := range []struct {
		name     string
		headers  []string
		ordinary string
		want     int
	}{
		{"missing", nil, "", 401}, {"wrong", []string{"Bearer " + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32))}, "", 401},
		{"combined", []string{token + ", " + token}, "", 401}, {"padded", []string{token + "="}, "", 401}, {"scheme", []string{"Basic " + token}, "", 401}, {"CRLF", []string{token + "\r\nInjected: bad"}, "", 401}, {"malformed", []string{"Bearer !"}, "", 401}, {"short", []string{"Bearer Qg"}, "", 401},
		{"duplicate", []string{token, token}, "", 401}, {"ordinary-cannot-replace", nil, token, 401}, {"valid", []string{token}, "Bearer unrelated", 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h := ownerHTTPAuthorize(key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) }))
			r := httptest.NewRequest("POST", "http://127.0.0.1/mcp", nil)
			for _, v := range tc.headers {
				r.Header.Add("X-WhatsApp-Owner-Authorization", v)
			}
			r.Header.Set("Authorization", tc.ordinary)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want || (calls == 1) != (tc.want == 204) {
				t.Fatalf("status=%d calls=%d", w.Code, calls)
			}
		})
	}
	// Startup table uses real evOwnedApp; invalid addr/mode/reader must not read key.
	app, _, _ := evOwnedApp(t)
	for _, tc := range []struct {
		name, addr string
		app        *App
		key        []byte
		wantReads  int
	}{
		{"hostname", "localhost:8080", app, key, 0}, {"wildcard", "0.0.0.0:8080", app, key, 0}, {"ipv6-wildcard", "[::]:8080", app, key, 0}, {"remote", "192.0.2.1:8080", app, key, 0}, {"invalid-port", "127.0.0.1:no", app, key, 0},
		{"reader", "127.0.0.1:8080", &App{store: app.store}, key, 0},
		{"missing-key", "127.0.0.1:8080", app, nil, 1}, {"wrong-key-length", "127.0.0.1:8080", app, []byte{1}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads, binds := 0, 0
			_, err := startOwnerHTTP(context.Background(), tc.app, tc.addr, OwnerHTTPDependencies{ReadKey: func() ([]byte, error) { reads++; return tc.key, nil }, BeforeBind: func() { binds++ }})
			if err == nil || binds != 0 || reads != tc.wantReads {
				t.Fatalf("err=%v reads=%d binds=%d", err, reads, binds)
			}
		})
	}
	for _, reason := range []string{"missing", "denied", "locked"} {
		t.Run(reason, func(t *testing.T) {
			binds := 0
			_, err := startOwnerHTTP(context.Background(), app, "127.0.0.1:8080", OwnerHTTPDependencies{ReadKey: func() ([]byte, error) { return nil, errors.New(reason) }, BeforeBind: func() { binds++ }})
			if err == nil || binds != 0 {
				t.Fatal("key failure bound listener")
			}
		})
	}
	for _, mode := range []struct {
		transport string
		events    bool
	}{{"http", false}, {"stdio", true}} {
		err := validateOwnerHTTPMode(mode.transport, mode.events)
		if err == nil {
			t.Fatal("invalid owner HTTP mode accepted")
		}
	}
	// Shared vector procedure: same physical DB through direct/parent/file symlink.
	dir := t.TempDir()
	db := filepath.Join(dir, "Data With Spaces", "whatsapp.db")
	if err := os.MkdirAll(filepath.Dir(db), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(db)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(canonical)))
	fileAlias := filepath.Join(dir, "db-alias")
	parentAlias := filepath.Join(dir, "parent-alias")
	if err := os.Symlink(db, fileAlias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(db), parentAlias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{db, fileAlias, filepath.Join(parentAlias, "whatsapp.db")} {
		got, err := ownerHTTPAccount(path)
		if err != nil || got != want {
			t.Fatalf("account mismatch %q %v", got, err)
		}
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "absent"), dangling); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "absent"), dangling} {
		if _, err := ownerHTTPAccount(path); err == nil {
			t.Fatal("nonexistent DB accepted")
		}
	}
}
