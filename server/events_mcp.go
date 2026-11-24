package main

// REQ-WC-004/007/008: native methods share the SDK initialize/session machinery.
import (
	"context"
	"encoding/json"
	"errors"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"net/http"
)

type resultBase = mcp.ResultBase
type paramsBase = mcp.ParamsBase
type eventProtocolError struct {
	Code   int64
	Reason string
}

func (e *eventProtocolError) Error() string { return "event request failed: " + e.Reason }
func eventRPCError(err error) error {
	if err == nil {
		return nil
	}
	var callback *eventProtocolError
	if errors.As(err, &callback) {
		data, _ := json.Marshal(map[string]string{"reason": callback.Reason})
		return &jsonrpc.Error{Code: callback.Code, Message: "CallbackEndpointError", Data: data}
	}
	return &jsonrpc.Error{Code: -32602, Message: "event request unavailable"}
}

type eventsListParams struct {
	mcp.ParamsBase
	Cursor json.RawMessage `json:"cursor,omitempty"`
}
type eventsListResult struct {
	mcp.ResultBase
	Events []any `json:"events"`
}
type eventEmpty struct{ mcp.ResultBase }
type eventsInitialize struct {
	mcp.ResultBase
	Original mcp.Result
}

func (r *eventsInitialize) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(r.Original)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	caps, ok := out["capabilities"].(map[string]any)
	if !ok {
		return nil, errors.New("invalid SDK initialize capabilities")
	}
	caps["events"] = map[string]any{}
	return json.Marshal(out)
}
func (s *EventService) Register(server *mcp.Server) error {
	if !s.cfg.Owner || s.cfg.Transport != "http" || s.cfg.WA == nil {
		return errors.New("events unavailable in this transport")
	}
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			result, err := next(ctx, method, req)
			if err == nil && (method == "initialize" || method == "server/discover") {
				return &eventsInitialize{Original: result}, nil
			}
			return result, err
		}
	})
	if err := mcp.AddReceivingCustomMethod(server, "events/list", func(ctx context.Context, ss *mcp.ServerSession, p *eventsListParams) (*eventsListResult, error) {
		if len(p.Cursor) > 0 && string(p.Cursor) != "null" {
			return nil, eventRPCError(errors.New("catalog cursor unsupported"))
		}
		if _, err := s.grant(ctx); err != nil {
			return nil, eventRPCError(err)
		}
		schema := map[string]any{"type": "object", "properties": map[string]any{"chat_jids": map[string]any{"type": "array", "minItems": 1, "maxItems": 32, "uniqueItems": true, "items": map[string]any{"type": "string"}}, "sender_jids": map[string]any{"type": "array", "minItems": 1, "maxItems": 32, "uniqueItems": true, "items": map[string]any{"type": "string"}}}, "anyOf": []any{map[string]any{"required": []string{"chat_jids"}}, map[string]any{"required": []string{"sender_jids"}}}, "additionalProperties": false}
		properties := map[string]any{}
		for _, name := range []string{"chat_jid", "sender_jid", "message_id", "kind", "observed_at"} {
			properties[name] = map[string]string{"type": "string"}
		}
		return &eventsListResult{Events: []any{map[string]any{"name": eventName, "description": "New live incoming original in exact selected chats/from selected people; history and outgoing excluded.", "delivery": []string{"webhook"}, "inputSchema": schema, "payloadSchema": map[string]any{"type": "object", "properties": properties, "required": []string{"chat_jid", "sender_jid", "message_id", "kind", "observed_at"}, "additionalProperties": false}}}}, nil
	}); err != nil {
		return err
	}
	if err := mcp.AddReceivingCustomMethod(server, "events/subscribe", func(ctx context.Context, ss *mcp.ServerSession, p *EventSubscribeRequest) (*EventSubscribeResult, error) {
		out, err := s.Subscribe(ctx, *p)
		return &out, eventRPCError(err)
	}); err != nil {
		return err
	}
	if err := mcp.AddReceivingCustomMethod(server, "events/unsubscribe", func(ctx context.Context, ss *mcp.ServerSession, p *EventUnsubscribeRequest) (*eventEmpty, error) {
		err := s.Unsubscribe(ctx, *p)
		return &eventEmpty{}, eventRPCError(err)
	}); err != nil {
		return err
	}
	type empty struct{}
	type idInput struct {
		ID string `json:"id"`
	}
	type monitorOutput struct {
		Monitors []EventMonitor `json:"monitors"`
	}
	type controlOutput struct {
		State string `json:"state"`
		Gap   string `json:"gap"`
	}
	mcp.AddTool(server, &mcp.Tool{Name: "list_message_monitors", Description: "Observed monitor health; callback receipt is separate from Dot summary and user push.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, monitorOutput, error) {
		if _, err := s.grant(ctx); err != nil {
			return nil, monitorOutput{}, err
		}
		rows, err := s.Monitors(ctx)
		return nil, monitorOutput{rows}, err
	})
	for _, action := range []string{"pause", "resume", "stop"} {
		action := action
		mcp.AddTool(server, &mcp.Tool{Name: action + "_message_monitor", Description: action + " an exact monitor ID; one admitted callback may complete. Resume starts now without replay.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false}}, func(ctx context.Context, _ *mcp.CallToolRequest, in idInput) (*mcp.CallToolResult, controlOutput, error) {
			err := s.Control(ctx, in.ID, action)
			return nil, controlOutput{State: action, Gap: "No replay; at most one already admitted callback may complete."}, err
		})
	}
	return nil
}
func (s *EventService) HTTPHandler(server *mcp.Server) (http.Handler, error) {
	if s.cfg.Transport != "http" || !s.cfg.Owner {
		return nil, errors.New("events HTTP unavailable")
	}
	sdk := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finish, err := s.admit()
		if err != nil {
			http.Error(w, "events closing", http.StatusServiceUnavailable)
			return
		}
		defer finish()
		// SDK GET/SSE can remain open for a session lifetime. Track only stream
		// contexts so Close can stop them without cutting off short admitted RPCs.
		if r.Method == http.MethodGet {
			streamCtx, cancel := context.WithCancel(r.Context())
			s.mu.Lock()
			s.streamNext++
			id := s.streamNext
			if s.streamCancels == nil {
				s.streamCancels = make(map[uint64]context.CancelFunc)
			}
			s.streamCancels[id] = cancel
			closing := s.closing
			s.mu.Unlock()
			defer func() { cancel(); s.mu.Lock(); delete(s.streamCancels, id); s.mu.Unlock() }()
			if closing {
				cancel()
			}
			r = r.WithContext(streamCtx)
		}
		if !s.authorized(r.Context(), r.Header.Get("Authorization")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sdk.ServeHTTP(w, r)
	}), nil
}
