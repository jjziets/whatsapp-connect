//go:build libsqlite3

package main

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Actual MCP qualification metadata and encrypted zero-effect checks.
func TestOwnerMessageInertConfirmationMode(t *testing.T) {
	real, _ := messageApp(t)
	inert, f := messageApp(t)
	inert.messageWrites = false
	inert.messageConfirmationTest = true
	rs, is := regressionClient(t, real), regressionClient(t, inert)
	rtools, err := rs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	itools, err := is.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("single-host-approval-guidance", func(t *testing.T) {
		initialization := strings.ToLower(rs.InitializeResult().Instructions)
		if !strings.Contains(initialization, "host approval card") || !strings.Contains(initialization, "no separate chat confirmation") {
			t.Error("MCP initialization must direct the agent to the host approval card without a separate chat confirmation")
		}
		if strings.Contains(initialization, "ask the owner to confirm") || strings.Contains(initialization, "only invoke send_text after the owner confirms") {
			t.Error("MCP initialization still tells the agent to obtain confirmation before invoking the host action")
		}

		guidance := map[string]string{}
		for _, tool := range rtools.Tools {
			guidance[tool.Name] = strings.ToLower(tool.Description)
		}
		for _, name := range []string{"prepare_message", "prepare_media_forward", "send_text", "forward_media"} {
			description := guidance[name]
			if !strings.Contains(description, "host approval card") {
				t.Errorf("%s must direct the agent to the host approval card", name)
			}
			if strings.Contains(description, "ask the owner to confirm") || strings.Contains(description, "payload only after") || strings.Contains(description, "attachment only after") {
				t.Errorf("%s still suggests a separate confirmation before requesting the host action", name)
			}
		}
	})
	var rtool, itool *mcp.Tool
	for _, v := range rtools.Tools {
		if v.Name == "send_text" {
			rtool = v
		}
	}
	for _, v := range itools.Tools {
		if v.Name == "send_text" {
			itool = v
		}
	}
	if itool == nil {
		t.Fatal("inert owner send_text not advertised")
	}
	a, _ := json.Marshal(rtool)
	b, _ := json.Marshal(itool)
	if string(a) != string(b) {
		t.Fatal("qualification tool schema/title/description/annotations differ from real mode")
	}
	p := previewMessage(t, inert, "inert-confirmation", alice.String(), "")
	before, _ := inert.store.Stats(context.Background())
	var rows int
	inert.store.db.QueryRow(`SELECT count(*) FROM mcp_outbox`).Scan(&rows)
	var status SendStatus
	raw, _ := json.Marshal(p)
	var args map[string]any
	json.Unmarshal(raw, &args)
	call(t, is, "send_text", args, &status)
	if status.State != "confirmation_test_only_not_sent" || status.MessageID != "" {
		t.Fatalf("false sending result: %+v", status)
	}
	after, _ := inert.store.Stats(context.Background())
	var count int
	inert.store.db.QueryRow(`SELECT count(*) FROM mcp_outbox`).Scan(&count)
	if f.calls.Load() != 0 || count != rows || !reflect.DeepEqual(before, after) {
		t.Fatal("inert mode reserved/dispatched/changed archive")
	}
	var st map[string]any
	call(t, is, "whatsapp_status", nil, &st)
	meta, ok := st["message_confirmation_test"].(map[string]any)
	if !ok || meta["invocations"] != float64(1) {
		t.Fatalf("missing sanitized invocation evidence: %+v", st)
	}
	reader := *inert
	reader.wa = nil
	tools, _ := regressionClient(t, &reader).ListTools(context.Background(), nil)
	for _, v := range tools.Tools {
		if v.Name == "send_text" {
			t.Fatal("archive reader advertised write")
		}
	}
}

func TestOwnerMessageModeCombinations(t *testing.T) {
	for _, tc := range []struct {
		transport                    string
		events, writes, inert, valid bool
	}{{"stdio", false, false, false, true}, {"stdio", false, true, false, true}, {"stdio", false, false, true, true}, {"stdio", false, true, true, false}, {"http", false, false, true, false}, {"stdio", true, false, true, false}, {"http", false, true, false, false}} {
		e := validateMessageServeOptions(tc.transport, tc.events, tc.writes, tc.inert)
		if (e == nil) != tc.valid {
			t.Fatalf("mode %+v: %v", tc, e)
		}
	}
	a, f := messageApp(t)
	a.messageConfirmationTest = true
	p := previewMessage(t, a, "invalid-combined-mode", alice.String(), "")
	if _, _, e := a.sendText(context.Background(), nil, p); e == nil || f.calls.Load() != 0 {
		t.Fatal("combined real/inert mode not refused")
	}
}
