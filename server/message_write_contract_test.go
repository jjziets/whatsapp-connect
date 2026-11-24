//go:build libsqlite3

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TRACEWEAVER: C-007 / TRACE-OWNERMSG-007 / VER-OWNERMSG-007.
// Public MCP contract, using the real encrypted setup and production server.
// No WhatsApp connection, real profile, Keychain or sending transport is used.
func TestOwnerMessageReadOnlyPublicContract(t *testing.T) {
	for _, mode := range []string{"default-owner", "archive-reader"} {
		t.Run(mode, func(t *testing.T) {
			_, wa := setup(t)
			app := &App{store: wa.store, wa: wa}
			if mode == "archive-reader" {
				app.wa = nil
				app.mode = "archive-reader"
			}
			cs := regressionClient(t, app)
			const text = "Synthetic review only.\nPlease confirm this exact text."
			before := time.Now()
			result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
				Name: "prepare_message", Arguments: map[string]any{
					"request_id": "synthetic-preview-001", "chat_jid": alice.String(),
					"text": text, "reply_to_message_id": "A1",
				},
			})
			if err != nil {
				t.Fatalf("read-only prepare_message must exist at actual MCP boundary: %v", err)
			}
			if result.IsError {
				t.Fatalf("known synthetic recipient and nil-raw text quote must preview: %+v", result.Content)
			}
			var preview struct {
				RequestID          string    `json:"request_id"`
				AccountJID         string    `json:"account_jid"`
				ChatJID            string    `json:"chat_jid"`
				DisplayName        string    `json:"display_name"`
				IsGroup            bool      `json:"is_group"`
				Text               string    `json:"text"`
				PayloadDigest      string    `json:"payload_digest"`
				ExpiresAt          time.Time `json:"expires_at"`
				ConfirmationNotice string    `json:"confirmation_notice"`
				ReplyTo            struct {
					MessageID string `json:"message_id"`
					ChatJID   string `json:"chat_jid"`
					AuthorJID string `json:"author_jid"`
					Text      string `json:"text"`
				} `json:"reply_to"`
			}
			encoded, err := json.Marshal(result.StructuredContent)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &preview); err != nil {
				t.Fatal(err)
			}
			if preview.RequestID != "synthetic-preview-001" || preview.ChatJID != alice.String() || preview.Text != text || preview.DisplayName != "Alice Anders" || preview.IsGroup {
				t.Fatalf("preview must bind exact synthetic target/text: %s", encoded)
			}
			if preview.AccountJID != "491500000000@s.whatsapp.net" || preview.PayloadDigest == "" {
				t.Fatalf("preview must bind synthetic owner and payload digest: %s", encoded)
			}
			if preview.ReplyTo.MessageID != "A1" || preview.ReplyTo.ChatJID != alice.String() || preview.ReplyTo.AuthorJID != alice.String() || preview.ReplyTo.Text != "hi, lunch tomorrow?" {
				t.Fatalf("preview quote must come from real archived nil-raw text: %s", encoded)
			}
			if preview.ExpiresAt.Before(before.Add(14*time.Minute)) || preview.ExpiresAt.After(time.Now().Add(16*time.Minute)) {
				t.Fatalf("preview expiry must be fifteen minutes: %s", encoded)
			}
			for _, exact := range []string{"Alice Anders", alice.String(), text, "A1", "hi, lunch tomorrow?"} {
				if !strings.Contains(preview.ConfirmationNotice, exact) {
					t.Errorf("confirmation notice missing exact target/content %q: %q", exact, preview.ConfirmationNotice)
				}
			}
			if !strings.Contains(strings.ToLower(preview.ConfirmationNotice), "host approval card") || strings.HasSuffix(strings.TrimSpace(preview.ConfirmationNotice), "?") {
				t.Error("text preview must direct approval to the host card without asking a chat question")
			}
			tools, err := cs.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, tool := range tools.Tools {
				if tool.Name == "send_text" {
					t.Fatal("writes disabled must not advertise send_text")
				}
			}
			var tables int
			if err := wa.store.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='mcp_outbox'").Scan(&tables); err != nil {
				t.Fatal(err)
			}
			if tables != 0 {
				var rows int
				if err := wa.store.db.QueryRow("SELECT count(*) FROM mcp_outbox").Scan(&rows); err != nil {
					t.Fatal(err)
				}
				if rows != 0 {
					t.Fatalf("pure preview reserved %d outbox rows", rows)
				}
			}
		})
	}
	t.Run("unknown-status", func(t *testing.T) {
		_, wa := setup(t)
		cs := regressionClient(t, &App{store: wa.store, mode: "archive-reader"})
		result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_send_status", Arguments: map[string]any{"request_id": "synthetic-never-reserved"}})
		if err != nil {
			t.Fatalf("read-only get_send_status must exist at actual MCP boundary: %v", err)
		}
		if result.IsError {
			t.Fatalf("absent outbox/request must be truthful structured status: %+v", result.Content)
		}
		var status struct {
			RequestID string `json:"request_id"`
			State     string `json:"state"`
		}
		encoded, err := json.Marshal(result.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &status); err != nil {
			t.Fatal(err)
		}
		if status.RequestID != "synthetic-never-reserved" || (status.State != "unknown" && status.State != "unavailable") {
			t.Fatalf("unknown request is not proof of nondelivery: %s", encoded)
		}
	})
}
