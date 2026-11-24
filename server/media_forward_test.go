//go:build libsqlite3

package main

// TRACEWEAVER: C-007 / TRACE-OWNERMSG-007 / VER-OWNERMSG-007.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hansen/whatsapp-mcp/internal/securestore"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/cbcutil"
	"go.mau.fi/whatsmeow/util/hkdfutil"
	"google.golang.org/protobuf/proto"
)

func mediaForwardTestArgs(id string) map[string]any {
	return map[string]any{
		"request_id": "fixture-" + id, "chat_jid": alice.String(),
		"source_chat_jid": group.String(), "source_message_id": id,
	}
}

func mediaForwardTestPreview(t *testing.T, cs *mcp.ClientSession, id string) map[string]any {
	t.Helper()
	var p map[string]any
	call(t, cs, "prepare_media_forward", mediaForwardTestArgs(id), &p)
	return p
}

func TestMediaForwardReadOnlyLegacyDisclosure(t *testing.T) {
	ctx := context.Background()
	a, _ := messageApp(t)
	w := a.wa
	msg, plain := mediaForwardContractImage(t, "Legacy photo caption", color.RGBA{B: 210, A: 255})
	archiveIngest(t, w, group, bob, "legacy-photo", t0, msg, true)
	if _, err := w.store.db.Exec("DROP TABLE IF EXISTS mcp_media_forward_provenance"); err != nil {
		t.Fatal(err)
	}
	if err := w.store.db.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(w.dataDir, "whatsapp.db")
	db, err := securestore.Open(path, true, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	var queryOnly int
	if err := db.QueryRow("PRAGMA query_only").Scan(&queryOnly); err != nil || queryOnly != 1 {
		t.Fatalf("expected actual query-only archive, query_only=%d err=%v", queryOnly, err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader := &App{store: NewStore(db), mode: "archive-reader"}
	cs := regressionClient(t, reader)
	for range 2 {
		p := mediaForwardTestPreview(t, cs, "legacy-photo")
		notice, _ := p["confirmation_notice"].(string)
		if p["source_provenance"] != "legacy_unknown" || p["file_name"] != "" || p["caption"] != "Legacy photo caption" {
			t.Fatalf("legacy source preview metadata incorrect: %v", p)
		}
		ack, _ := p["legacy_source_acknowledgement"].(string)
		for _, phrase := range []string{"Filename: none", fmt.Sprintf("%d bytes", len(plain)), "Legacy photo caption", "original privacy restrictions cannot be verified", "ordinary shareable attachment"} {
			if !strings.Contains(notice, phrase) {
				t.Errorf("notice missing %q", phrase)
			}
		}
		if ack == "" || !strings.Contains(notice, ack) {
			t.Error("exact legacy acknowledgement must be visible in both notice and flat payload")
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("reader preview changed encrypted archive file")
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name='mcp_media_forward_provenance'").Scan(&count); err != nil || count != 0 {
		t.Fatal("reader preview changed legacy schema")
	}
	if _, err := os.Stat(filepath.Join(w.dataDir, "media")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reader preview populated a media cache")
	}
}

func TestMediaForwardRejectsRestrictedOriginals(t *testing.T) {
	ctx := context.Background()
	a, _ := messageApp(t)
	w := a.wa
	cs := regressionClient(t, a)
	ordinary := func() *waE2E.Message {
		m, _ := mediaForwardContractImage(t, "Privacy fixture", color.RGBA{R: 190, A: 255})
		return m
	}
	for _, shape := range []string{"wrapper-only", "inner-only", "expired-history", "limit-sharing", "restriction-upgrade", "revoked-history-stub", "limited-conversation", "conflicting-original-caption"} {
		t.Run(shape, func(t *testing.T) {
			msg := ordinary()
			web := archiveWeb(group, bob, shape, t0, msg)
			switch shape {
			case "wrapper-only":
				web.Message = &waE2E.Message{ViewOnceMessageV2: &waE2E.FutureProofMessage{Message: msg}}
			case "inner-only":
				msg.ImageMessage.ViewOnce = proto.Bool(true)
			case "expired-history":
				web.EphemeralDuration = proto.Uint32(60)
			case "limit-sharing":
				msg.MessageContextInfo = &waE2E.MessageContextInfo{LimitSharingV2: &waCommon.LimitSharing{SharingLimited: proto.Bool(true)}}
			case "conflicting-original-caption":
				archiveIngest(t, w, group, bob, shape, t0, ordinary(), false)
				msg.ImageMessage.Caption = proto.String("Conflicting caption on the same original")
			case "revoked-history-stub":
				archiveIngest(t, w, group, bob, shape, t0, ordinary(), false)
				web.Message = nil
				web.MessageStubType = waWeb.WebMessageInfo_REVOKE.Enum()
			case "restriction-upgrade":
				archiveIngest(t, w, group, bob, shape, t0, ordinary(), false)
				p := mediaForwardTestPreview(t, cs, shape)
				if p["source_provenance"] != "known_ordinary" || !strings.Contains(p["confirmation_notice"].(string), "Ordinary archived attachment") {
					t.Fatal("ordinary provenance precondition and full notice missing")
				}
				web.Message = &waE2E.Message{EphemeralMessage: &waE2E.FutureProofMessage{Message: msg}}
			}
			if shape == "limited-conversation" {
				w.ingestHistory(ctx, &waHistorySync.HistorySync{Conversations: []*waHistorySync.Conversation{{
					ID: proto.String(group.String()), LimitSharing: proto.Bool(true), Messages: []*waHistorySync.HistorySyncMsg{{Message: web}},
				}}})
			} else {
				event, err := w.Client.ParseWebMessage(group, web)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.ingestMessageOutcome(ctx, event, true); err != nil {
					t.Fatal(err)
				}
			}
			res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "prepare_media_forward", Arguments: mediaForwardTestArgs(shape)})
			if err != nil {
				t.Fatalf("restricted-source check must reach forward preview: %v", err)
			}
			if !res.IsError || !strings.Contains(strings.ToLower(fmt.Sprint(res.Content[0])), "restricted") {
				t.Fatalf("restricted source reached confirmation: %v", res.Content)
			}
		})
	}
}

func TestMediaForwardVerifiedDispatchAndReplay(t *testing.T) {
	ctx := context.Background()
	for _, outcome := range []string{"ack", "revoked-during-upload", "oversize-response", "canceled-upload"} {
		t.Run(outcome, func(t *testing.T) {
			a, transport := messageApp(t)
			w := a.wa
			const id = "fixture-archived-photo"
			msg, plain := mediaForwardContractImage(t, "Full approved caption\nsecond line", color.RGBA{R: 240, B: 30, A: 255})
			msg.ImageMessage.ContextInfo = &waE2E.ContextInfo{MentionedJID: []string{"private-synthetic-mention"}, StanzaID: proto.String("private-synthetic-quote"), ForwardingScore: proto.Uint32(4)}
			archiveIngest(t, w, group, bob, id, t0, msg, false)
			dir := filepath.Join(w.dataDir, "media", group.String())
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, id+".jpg"), plain, 0600); err != nil {
				t.Fatal(err)
			}
			uploadCalls := 0
			var uploaded []byte
			spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(req *http.Request) (*http.Response, error) {
				uploadCalls++
				if req.Method != http.MethodPost || !strings.HasPrefix(req.URL.Path, "/mms/image/") {
					return nil, errors.New("unexpected media transfer")
				}
				reserved, err := a.store.sendStatus(ctx, "fixture-"+id)
				if err != nil || reserved.State != "dispatching" || reserved.MessageID == "" {
					t.Errorf("upload preceded durable reservation: state=%q err=%v", reserved.State, err)
				}
				uploaded, err = io.ReadAll(req.Body)
				_ = req.Body.Close()
				if err != nil {
					return nil, err
				}
				if outcome == "revoked-during-upload" {
					if err := a.store.MarkDeleted(ctx, group.String(), id, bob.String(), false, time.Now()); err != nil {
						return nil, err
					}
				}
				if outcome == "oversize-response" {
					return spResponse(req, bytes.Repeat([]byte(" "), 128*1024), -1), nil
				}
				if outcome == "canceled-upload" {
					a.wa.lifecycleMu.Lock()
					cancel := a.wa.messageCancel
					a.wa.lifecycleMu.Unlock()
					cancel()
					return nil, req.Context().Err()
				}
				response := []byte(`{"url":"https://mmg.whatsapp.net/fresh-object","direct_path":"/fresh-object?a=1"}`)
				return spResponse(req, response, int64(len(response))), nil
			})}, "mmg.whatsapp.net")
			transport.send = func(ctx context.Context, recipient types.JID, m *waE2E.Message, extra ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
				x := m.GetImageMessage()
				if recipient.String() != "66554433@lid" || x.GetCaption() != msg.GetImageMessage().GetCaption() || x.GetMimetype() != "image/jpeg" || x.GetDirectPath() != "/fresh-object?a=1" || !x.GetContextInfo().GetIsForwarded() || x.GetContextInfo().GetForwardingScore() != 5 || len(x.GetContextInfo().GetMentionedJID()) != 0 || x.GetContextInfo().GetStanzaID() != "" {
					t.Error("recipient boundary lost approved media or copied unapproved context")
				}
				if len(uploaded) < aes.BlockSize+10 || len(x.GetMediaKey()) != 32 {
					return whatsmeow.SendResponse{}, errors.New("missing freshly encrypted upload")
				}
				keys := hkdfutil.SHA256(x.GetMediaKey(), nil, []byte(whatsmeow.MediaImage), 112)
				wireHash := sha256.Sum256(uploaded)
				decrypted, err := cbcutil.Decrypt(keys[16:48], keys[:16], uploaded[:len(uploaded)-10])
				if err != nil || !bytes.Equal(plain, decrypted) || !bytes.Equal(wireHash[:], x.GetFileEncSHA256()) {
					t.Error("recipient protobuf does not bind the same approved bytes uploaded to SDK")
				}
				return whatsmeow.SendResponse{ID: extra[0].ID, Timestamp: time.Now(), Chat: recipient}, nil
			}

			cs := regressionClient(t, a)
			p := mediaForwardTestPreview(t, cs, id)
			delete(p, "confirmation_notice")
			var result, repeated map[string]any
			call(t, cs, "forward_media", p, &result)
			state := "rejected"
			wantSends := int32(0)
			if outcome == "ack" {
				state, wantSends = "server_acknowledged", 1
			}
			if result["state"] != state {
				t.Fatalf("first result state=%v want %s (%v)", result["state"], state, result)
			}
			call(t, cs, "forward_media", p, &repeated)
			if repeated["state"] != state || repeated["message_id"] != result["message_id"] || uploadCalls != 1 || transport.calls.Load() != wantSends {
				t.Fatalf("exact replay created effects or changed result: uploads %d, sends %d, result %v", uploadCalls, transport.calls.Load(), repeated)
			}
			if outcome == "ack" {
				archived := archiveMessage(t, w, alice, result["message_id"].(string))
				if !archived.FromMe || archived.Kind != "image" || archived.Text != msg.GetImageMessage().GetCaption() {
					t.Fatal("ack did not produce the correct outgoing archive row")
				}
			}
		})
	}
}

func TestMediaForwardProviderBoundsAndCacheFallback(t *testing.T) {
	for _, shape := range []string{"authenticated-download", "tampered-cache", "symlink-cache", "unexpected-redirect", "chunked-overflow", "invalid-path", "untrusted-host"} {
		t.Run(shape, func(t *testing.T) {
			a, transport := messageApp(t)
			w := a.wa
			id := "provider-" + shape
			msg, data := mediaForwardContractImage(t, "Synthetic provider attachment", color.RGBA{G: 190, A: 255})
			key := bytes.Repeat([]byte{0x39}, 32)
			keys := hkdfutil.SHA256(key, nil, []byte(whatsmeow.MediaImage), 112)
			var ciphertext bytes.Buffer
			_, encryptedHash, _, _, err := cbcutil.EncryptStream(keys[16:48], keys[:16], keys[48:80], bytes.NewReader(data), &ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			x := msg.ImageMessage
			x.DirectPath, x.MediaKey, x.FileEncSHA256 = proto.String("/archive-fixture?a=1"), key, encryptedHash
			if shape == "invalid-path" {
				x.DirectPath = proto.String("//other.invalid/not-an-archive-reference")
			}
			if shape == "tampered-cache" || shape == "symlink-cache" {
				dir := filepath.Join(w.dataDir, "media", group.String())
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				cachePath := filepath.Join(dir, id+".jpg")
				if shape == "tampered-cache" {
					bad := bytes.Clone(data)
					bad[len(bad)-1] ^= 1
					if err := os.WriteFile(cachePath, bad, 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					outside := filepath.Join(t.TempDir(), "otherwise-valid.jpg")
					if err := os.WriteFile(outside, data, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, cachePath); err != nil {
						t.Fatal(err)
					}
				}
			}
			archiveIngest(t, w, group, bob, id, t0, msg, false)
			var gets, posts int
			overflow := &bytes.Buffer{}
			host := "mmg.whatsapp.net"
			if shape == "untrusted-host" {
				host = "mmg.whatsapp.net.other.invalid"
			}
			spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(req *http.Request) (*http.Response, error) {
				switch req.Method {
				case http.MethodGet:
					gets++
					if shape == "unexpected-redirect" {
						redirect := spResponse(req, nil, 0)
						redirect.StatusCode = http.StatusTemporaryRedirect
						redirect.Header.Set("Location", "https://mmg.whatsapp.net/second-attempt")
						return redirect, nil
					}
					if shape == "chunked-overflow" {
						overflow.Write(ciphertext.Bytes())
						overflow.Write(make([]byte, 24*1024))
						resp := spResponse(req, nil, -1)
						resp.Body = io.NopCloser(overflow)
						return resp, nil
					}
					return spResponse(req, ciphertext.Bytes(), -1), nil
				case http.MethodPost:
					posts++
					_ = req.Body.Close()
					response := []byte(`{"url":"https://mmg.whatsapp.net/uploaded","direct_path":"/uploaded?a=1"}`)
					return spResponse(req, response, int64(len(response))), nil
				default:
					return nil, errors.New("unexpected method")
				}
			})}, host)
			cs := regressionClient(t, a)
			p := mediaForwardTestPreview(t, cs, id)
			delete(p, "confirmation_notice")
			var result SendStatus
			call(t, cs, "forward_media", p, &result)
			wantState, wantGets, wantPosts := "rejected", 1, 0
			switch shape {
			case "authenticated-download", "tampered-cache", "symlink-cache":
				wantState, wantPosts = "server_acknowledged", 1
			case "invalid-path", "untrusted-host":
				wantGets = 0
			}
			if result.State != wantState || gets != wantGets || posts != wantPosts || transport.calls.Load() != int32(wantPosts) {
				t.Fatalf("provider/cache operation=%s, GET=%d, POST=%d, recipient=%d", result.State, gets, posts, transport.calls.Load())
			}
			if shape == "chunked-overflow" && overflow.Len() != 24*1024-1 {
				t.Fatalf("SDK read past allowed encrypted size plus one byte: overflow remaining=%d", overflow.Len())
			}
		})
	}
}

func TestMediaForwardLegacyTextPayloadAndSharedNamespace(t *testing.T) {
	ctx := context.Background()
	a, transport := messageApp(t)
	fixture, err := os.ReadFile("testdata/media-forward-legacy-text-payload.json")
	if err != nil {
		t.Fatal(err)
	}
	fixture = bytes.TrimSuffix(fixture, []byte("\n"))
	var old SendTextArgs
	if err := json.Unmarshal(fixture, &old); err != nil {
		t.Fatal(err)
	}
	current, err := json.Marshal(old)
	if err != nil || !bytes.Equal(current, fixture) || messageDigest(old) != old.PayloadDigest {
		t.Fatal("current text payload JSON or digest changed relative to actual baseline producer")
	}
	if _, err := a.store.db.ExecContext(ctx, `INSERT INTO mcp_outbox(request_id,account_jid,payload,message_id,state,created_at,updated_at)
		VALUES (?,?,?,'SYNTHETIC-HISTORICAL-ID','server_acknowledged','fixture','fixture')`, old.RequestID, old.AccountJID, string(fixture)); err != nil {
		t.Fatal(err)
	}
	archiveIngest(t, a.wa, alice, alice, "fixture-revoke", time.Now(), archiveRevoke("A1"), false)
	cs := regressionClient(t, a)
	var args map[string]any
	if err := json.Unmarshal(fixture, &args); err != nil {
		t.Fatal(err)
	}
	var replay map[string]json.RawMessage
	call(t, cs, "send_text", args, &replay)
	var returned SendTextArgs
	if err := json.Unmarshal(replay["payload"], &returned); err != nil {
		t.Fatal(err)
	}
	returnedJSON, err := json.Marshal(returned)
	if err != nil || !bytes.Equal(returnedJSON, fixture) || string(replay["state"]) != `"server_acknowledged"` || replay["media_payload"] != nil {
		t.Fatal("historical text replay did not retain legacy payload/status after expiry and revocation")
	}
	var stored string
	if err := a.store.db.QueryRowContext(ctx, "SELECT payload FROM mcp_outbox WHERE request_id=?", old.RequestID).Scan(&stored); err != nil || stored != string(fixture) {
		t.Fatal("historical text replay changed the stored producer payload")
	}
	msg, _ := mediaForwardContractImage(t, "Synthetic collision", color.RGBA{R: 220, A: 255})
	archiveIngest(t, a.wa, group, bob, "collision", t0, msg, false)
	mediaArgs := mediaForwardTestArgs("collision")
	mediaArgs["request_id"] = old.RequestID
	var forward map[string]any
	call(t, cs, "prepare_media_forward", mediaArgs, &forward)
	delete(forward, "confirmation_notice")
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "forward_media", Arguments: forward})
	if err != nil || !res.IsError || !strings.Contains(fmt.Sprint(res.Content[0]), "conflicts") {
		t.Fatalf("cross-operation request ID did not reject before transfer: %v, %v", res, err)
	}
	if transport.calls.Load() != 0 {
		t.Fatal("legacy replay or conflicting media sent a message")
	}
}

func TestMediaForwardArchivesSupportedTypes(t *testing.T) {
	a, transport := messageApp(t)
	w := a.wa
	var pngBytes bytes.Buffer
	if err := png.Encode(&pngBytes, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	// A one-page PDF with a catalog, page tree and one page. The byte offsets
	// below are captured as objects are written so the fixture is readable.
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	offsets := []int{}
	for i, object := range []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>",
	} {
		offsets = append(offsets, pdf.Len())
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := pdf.Len()
	pdf.WriteString("xref\n0 4\n0000000000 65535 f \n")
	for _, offset := range offsets {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)

	dir := filepath.Join(w.dataDir, "media", group.String())
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		id       string
		kind     string
		mime     string
		filename string
		payload  []byte
	}{
		{"png", "image", "image/png", "", pngBytes.Bytes()},
		{"pdf", "document", "application/pdf", "fixture.pdf", pdf.Bytes()},
		{"nameless-pdf", "document", "application/pdf", "", pdf.Bytes()},
		{"unsafe-pdf-name", "document", "application/pdf", "../fixture.pdf", pdf.Bytes()},
		{"mp3", "audio", "audio/mpeg", "", nil},
		{"m4a", "audio", "audio/mp4", "", nil},
		{"opus", "audio", "audio/ogg; codecs=opus", "", nil},
		{"voice-note", "audio", "audio/ogg", "", nil},
		{"mismatched-png", "image", "image/png", "", pdf.Bytes()},
	} {
		t.Run(fixture.id, func(t *testing.T) {
			data := fixture.payload
			if data == nil {
				fileType := fixture.id
				if fileType == "voice-note" {
					fileType = "opus"
				}
				var err error
				data, err = os.ReadFile("testdata/media-forward-fixture." + fileType)
				if err != nil {
					t.Fatal(err)
				}
			}
			digest := sha256.Sum256(data)
			caption := "Fixture full caption"
			message := &waE2E.Message{}
			switch fixture.kind {
			case "image":
				message.ImageMessage = &waE2E.ImageMessage{Caption: &caption, Mimetype: &fixture.mime, FileLength: proto.Uint64(uint64(len(data))), FileSHA256: digest[:]}
			case "document":
				document := &waE2E.DocumentMessage{Caption: &caption, Mimetype: &fixture.mime, FileLength: proto.Uint64(uint64(len(data))), FileSHA256: digest[:]}
				if fixture.filename != "" {
					document.FileName = &fixture.filename
				}
				message.DocumentWithCaptionMessage = &waE2E.FutureProofMessage{Message: &waE2E.Message{DocumentMessage: document}}
			case "audio":
				message.AudioMessage = &waE2E.AudioMessage{Mimetype: &fixture.mime, PTT: proto.Bool(fixture.id == "voice-note"), FileLength: proto.Uint64(uint64(len(data))), FileSHA256: digest[:]}
			}
			archiveIngest(t, w, group, bob, fixture.id, t0, message, true)
			name := fixture.id + extensionFor(&MessageRow{Mime: fixture.mime, FileName: fixture.filename})
			if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				t.Fatal(err)
			}
			post := 0
			spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(req *http.Request) (*http.Response, error) {
				post++
				if req.Method != http.MethodPost || !strings.HasPrefix(req.URL.Path, "/mms/"+fixture.kind+"/") {
					t.Error("wrong pinned SDK media type")
				}
				_ = req.Body.Close()
				response := []byte(`{"url":"https://mmg.whatsapp.net/fixture","direct_path":"/fixture?a=1"}`)
				return spResponse(req, response, int64(len(response))), nil
			})}, "mmg.whatsapp.net")
			transport.send = func(_ context.Context, recipient types.JID, m *waE2E.Message, extra ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
				unwrapped := (&events.Message{RawMessage: m}).UnwrapRaw().Message
				kind, f := archivedAttachment(unwrapped)
				if kind != fixture.kind || f.GetMimetype() != fixture.mime || f.GetFileLength() != uint64(len(data)) ||
					!bytes.Equal(f.GetFileSHA256(), digest[:]) || !f.GetContextInfo().GetIsForwarded() {
					t.Error("typed recipient payload does not represent the selected file")
				}
				if fixture.kind == "document" {
					doc := unwrapped.GetDocumentMessage()
					if doc.GetFileName() != fixture.filename || doc.GetCaption() != caption || m.GetDocumentWithCaptionMessage() == nil {
						t.Error("PDF caption, filename or native wrapper changed")
					}
					if fixture.filename == "" && (doc.FileName != nil || doc.Title != nil) {
						t.Error("nameless PDF must preserve absent filename and title in the actual recipient protobuf")
					}
				}
				return whatsmeow.SendResponse{ID: extra[0].ID, Timestamp: time.Now(), Chat: recipient}, nil
			}
			cs := regressionClient(t, a)
			if fixture.id == "voice-note" || fixture.id == "unsafe-pdf-name" {
				res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "prepare_media_forward", Arguments: mediaForwardTestArgs(fixture.id)})
				if err != nil || !res.IsError || post != 0 {
					t.Fatalf("unsupported source must not preview: %v, %v", res, err)
				}
				return
			}
			p := mediaForwardTestPreview(t, cs, fixture.id)
			notice, _ := p["confirmation_notice"].(string)
			if fixture.filename != "" && !strings.Contains(notice, fixture.filename) {
				t.Error("notice omitted approved document filename")
			}
			if fixture.id == "nameless-pdf" && (p["file_name"] != "" || !strings.Contains(notice, "Filename: none")) {
				t.Error("notice and payload must make the absent PDF filename explicit")
			}
			if fixture.kind == "audio" && p["caption"] != nil {
				t.Error("ordinary audio preview invented a caption")
			}
			delete(p, "confirmation_notice")
			var status SendStatus
			call(t, cs, "forward_media", p, &status)
			if fixture.id == "mismatched-png" {
				if status.State != "rejected" || post != 0 {
					t.Fatal("signature-mismatched attachment reached the provider")
				}
			} else if status.State != "server_acknowledged" || post != 1 {
				t.Fatalf("eligible attachment failed: state=%q, POSTs=%d", status.State, post)
			}
		})
	}
}

func TestMediaForwardAliasRestrictionsAndLegacyAcknowledgement(t *testing.T) {
	ctx := context.Background()
	a, _ := messageApp(t)
	w := a.wa
	pn := types.NewJID("491588822211", types.DefaultUserServer)
	lid := types.NewJID("99667788", types.HiddenUserServer)
	const aliasID = "fixture-alias-restriction"
	msg, _ := mediaForwardContractImage(t, "Alias safety fixture", color.RGBA{B: 220, A: 255})
	archiveIngest(t, w, pn, pn, aliasID, t0, msg, false)
	wrapped := &waE2E.Message{ViewOnceMessage: &waE2E.FutureProofMessage{Message: msg}}
	archiveIngest(t, w, lid, lid, aliasID, t0, wrapped, true)
	if err := w.Client.Store.LIDs.PutLIDMapping(ctx, lid, pn); err != nil {
		t.Fatal(err)
	}
	cs := regressionClient(t, a)
	args := mediaForwardTestArgs(aliasID)
	args["source_chat_jid"] = pn.String()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "prepare_media_forward", Arguments: args})
	if err != nil || !res.IsError || !strings.Contains(fmt.Sprint(res.Content[0]), "restricted") {
		t.Fatalf("verified alias merge lost the stronger privacy state: %v, %v", res, err)
	}

	const legacy = "fixture-legacy-inert"
	// Older writers stored the normalized attachment without the upstream envelope.
	if _, err := w.ingestMessageOutcome(ctx, &events.Message{
		Info: types.MessageInfo{
			MessageSource: types.MessageSource{Chat: group, Sender: bob, IsGroup: true},
			ID:            legacy,
			Timestamp:     t0,
		},
		Message: msg,
	}, false); err != nil {
		t.Fatal(err)
	}
	inert := *a
	inert.messageWrites, inert.messageConfirmationTest = false, true
	cs = regressionClient(t, &inert)
	p := mediaForwardTestPreview(t, cs, legacy)
	if p["source_provenance"] != "legacy_unknown" || p["legacy_source_acknowledgement"] != legacyForwardAck {
		t.Fatal("legacy row did not expose the exact acknowledgement")
	}
	delete(p, "confirmation_notice")
	var status SendStatus
	call(t, cs, "forward_media", p, &status)
	if status.State != "confirmation_test_only_not_sent" {
		t.Fatalf("valid legacy acknowledgement did not reach inert mode: %s", status.State)
	}
	delete(p, "legacy_source_acknowledgement")
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "forward_media", Arguments: p})
	if err != nil || !res.IsError {
		t.Fatalf("legacy acknowledgement could be removed: %v, %v", res, err)
	}

	// A matching actual original can establish ordinary provenance for this
	// exact historical source and invalidate its previously displayed warning.
	archiveIngest(t, w, group, bob, legacy, t0, msg, true)
	fresh := mediaForwardTestPreview(t, cs, legacy)
	if fresh["source_provenance"] != "known_ordinary" || fresh["legacy_source_acknowledgement"] != nil {
		t.Fatal("matching producer original did not establish positive provenance")
	}
}

func TestMediaForwardSharesOwnerDispatchAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, transport := messageApp(t)
	w := a.wa
	const id = "fixture-shared-admission"
	msg, data := mediaForwardContractImage(t, "Synthetic admission fixture", color.RGBA{B: 217, A: 255})
	archiveIngest(t, w, group, bob, id, t0, msg, false)
	dir := filepath.Join(w.dataDir, "media", group.String())
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".jpg"), data, 0600); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var uploads atomic.Int32
	spInstallMedia(t, w, &http.Client{Transport: spRoundTrip(func(req *http.Request) (*http.Response, error) {
		if uploads.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		_ = req.Body.Close()
		response := []byte(`{"url":"https://mmg.whatsapp.net/admission","direct_path":"/admission?a=1"}`)
		return spResponse(req, response, int64(len(response))), nil
	})}, "mmg.whatsapp.net")
	cs := regressionClient(t, a)
	p := mediaForwardTestPreview(t, cs, id)
	delete(p, "confirmation_notice")
	done := make(chan error, 1)
	go func() {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "forward_media", Arguments: p})
		if err == nil && res.IsError {
			err = fmt.Errorf("media dispatch returned %v", res.Content)
		}
		done <- err
	}()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("dispatch ended before upload: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	otherApp := *a
	other := regressionClient(t, &otherApp)
	var active SendStatus
	call(t, other, "forward_media", p, &active)
	if active.State != "dispatching" || uploads.Load() != 1 {
		t.Fatalf("duplicate entered an active dispatch: state=%q, uploads=%d", active.State, uploads.Load())
	}
	text := previewMessage(t, a, "fixture-while-uploading", alice.String(), "")
	if _, _, err := a.sendText(ctx, nil, text); err == nil || !strings.Contains(err.Error(), "another message") {
		t.Fatalf("text did not share the media dispatch lane: %v", err)
	}
	if err := w.RequestOlderHistory(ctx, alice, 1); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("history did not share the media dispatch lane: %v", err)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if transport.calls.Load() != 1 || uploads.Load() != 1 {
		t.Fatalf("shared lane dispatched extra media or text: sends=%d, uploads=%d", transport.calls.Load(), uploads.Load())
	}
}
