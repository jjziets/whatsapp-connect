//go:build libsqlite3

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"google.golang.org/protobuf/proto"
)

// TRACEWEAVER: C-007 / TRACE-OWNERMSG-007 / VER-OWNERMSG-007.
// Public contract over the real encrypted archive and pinned message producers.
func TestMediaForwardPublicContract(t *testing.T) {
	ctx := context.Background()
	owner, transport := messageApp(t)
	w := owner.wa
	var mediaCalls atomic.Int32
	spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(*http.Request) (*http.Response, error) {
		mediaCalls.Add(1)
		return nil, errors.New("unexpected media I/O from preview or inert invocation")
	})})

	const sourceID = "synthetic-duplicate-photo"
	const caption = "Synthetic photo caption.\nKeep the full second line."
	selected, selectedBytes := mediaForwardContractImage(t, caption, color.RGBA{R: 237, A: 255})
	other, _ := mediaForwardContractImage(t, "Wrong chat's caption", color.RGBA{G: 203, A: 255})
	archiveIngest(t, w, bob, bob, sourceID, t0, other, false)
	archiveIngest(t, w, group, bob, sourceID, t0, selected, true)
	hash := sha256.Sum256(selectedBytes)
	sha := hex.EncodeToString(hash[:])
	before := mediaForwardContractOutbox(t, owner)

	defaultOwner := *owner
	defaultOwner.messageWrites = false
	reader := defaultOwner
	reader.wa, reader.mode = nil, "archive-reader"
	inert := defaultOwner
	inert.messageConfirmationTest = true
	inactive := *owner
	inactive.authority = &eventOwnerAuthority{}
	writeMetadata := map[string][]byte{}
	for _, mode := range []struct {
		name       string
		app        *App
		canForward bool
	}{
		{"default-owner", &defaultOwner, false},
		{"archive-reader", &reader, false},
		{"inactive-owner", &inactive, false},
		{"active-owner", owner, true},
		{"inert-owner", &inert, true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			cs := regressionClient(t, mode.app)
			list, err := cs.ListTools(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			tools := make(map[string]*mcp.Tool)
			for _, tool := range list.Tools {
				tools[tool.Name] = tool
			}
			if pre := tools["prepare_media_forward"]; pre == nil {
				t.Error("missing prepare_media_forward in actual MCP tools/list")
			} else if a := pre.Annotations; a == nil || !a.ReadOnlyHint || a.OpenWorldHint == nil || *a.OpenWorldHint {
				t.Error("media preparation must advertise local read-only behavior")
			}
			write := tools["forward_media"]
			if (write != nil) != mode.canForward {
				t.Errorf("forward_media advertised=%t, want %t for this MCP session", write != nil, mode.canForward)
			}
			if write != nil {
				a := write.Annotations
				if a == nil || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint || !a.IdempotentHint || a.OpenWorldHint == nil || !*a.OpenWorldHint {
					t.Error("forward_media must advertise an idempotent high-risk external write")
				}
				writeMetadata[mode.name], err = json.Marshal(write)
				if err != nil {
					t.Fatal(err)
				}
			}

			requestID := "synthetic-photo-" + mode.name
			start := time.Now()
			var preview map[string]any
			call(t, cs, "prepare_media_forward", map[string]any{
				"request_id": requestID, "chat_jid": alice.String(),
				"source_chat_jid": group.String(), "source_message_id": sourceID,
			}, &preview)
			for field, want := range map[string]any{
				"operation": "forward_media", "request_id": requestID,
				"account_jid": "491500000000@s.whatsapp.net", "chat_jid": alice.String(),
				"display_name": "Alice Anders", "is_group": false,
				"source_chat_jid": group.String(), "source_message_id": sourceID, "source_display_name": "Team Lunch",
				"kind": "image", "mime_type": "image/jpeg", "file_name": "",
				"size_bytes": float64(len(selectedBytes)), "sha256": sha, "caption": caption,
				"source_provenance": "known_ordinary",
			} {
				if got := preview[field]; got != want {
					t.Errorf("photo preview %s = %v, want %v", field, got, want)
				}
			}
			payloadDigest, _ := preview["payload_digest"].(string)
			digest, err := hex.DecodeString(payloadDigest)
			if err != nil || len(digest) != sha256.Size {
				t.Error("photo preview must bind a full SHA-256 payload digest")
			}
			expiryValue, _ := preview["expires_at"].(string)
			expiry, err := time.Parse(time.RFC3339Nano, expiryValue)
			if err != nil || expiry.Before(start.Add(14*time.Minute)) || expiry.After(time.Now().Add(16*time.Minute)) {
				t.Errorf("photo preview expiry must be fifteen minutes, got %q", expiryValue)
			}
			notice, _ := preview["confirmation_notice"].(string)
			if !strings.Contains(strings.ToLower(notice), "host approval card") || strings.HasSuffix(strings.TrimSpace(notice), "?") {
				t.Error("photo preview must direct approval to the host card without asking a chat question")
			}
			for _, want := range []string{"Alice Anders", alice.String(), "Team Lunch", group.String(), sourceID, "image/jpeg", caption, sha} {
				if !strings.Contains(notice, want) {
					t.Errorf("photo confirmation notice missing %q", want)
				}
			}
			if mode.name == "inert-owner" && write != nil {
				delete(preview, "confirmation_notice")
				var status struct {
					State     string `json:"state"`
					MessageID string `json:"message_id"`
				}
				call(t, cs, "forward_media", preview, &status)
				if status.State != "confirmation_test_only_not_sent" || status.MessageID != "" {
					t.Errorf("inert forward reported external effects: %+v", status)
				}
			}
		})
	}
	if !bytes.Equal(writeMetadata["active-owner"], writeMetadata["inert-owner"]) {
		t.Error("real and inert forward_media metadata or schema differ")
	}
	if after := mediaForwardContractOutbox(t, owner); before != after {
		t.Errorf("preview or inert call mutated the outbox: before %v, after %v", before, after)
	}
	if mediaCalls.Load() != 0 || transport.calls.Load() != 0 {
		t.Error("preview or inert call accessed media provider or recipient")
	}
}

func mediaForwardContractImage(t *testing.T, caption string, fill color.RGBA) (*waE2E.Message, []byte) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.SetRGBA(0, 0, fill)
	var buffer bytes.Buffer
	if err := jpeg.Encode(&buffer, img, nil); err != nil {
		t.Fatal(err)
	}
	data := buffer.Bytes()
	hash := sha256.Sum256(data)
	return &waE2E.Message{ImageMessage: &waE2E.ImageMessage{
		Caption: proto.String(caption), Mimetype: proto.String("image/jpeg"),
		FileLength: proto.Uint64(uint64(len(data))), FileSHA256: hash[:],
	}}, data
}

func mediaForwardContractOutbox(t *testing.T, owner *App) [2]int {
	t.Helper()
	var state [2]int
	if err := owner.store.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='mcp_outbox'").Scan(&state[0]); err != nil {
		t.Fatal(err)
	}
	if state[0] > 0 {
		if err := owner.store.db.QueryRow("SELECT count(*) FROM mcp_outbox").Scan(&state[1]); err != nil {
			t.Fatal(err)
		}
	}
	return state
}
