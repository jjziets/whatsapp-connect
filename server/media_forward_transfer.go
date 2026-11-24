package main

// TRACEWEAVER: C-007 / TRACE-OWNERMSG-007 / VER-OWNERMSG-007.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const maxForwardUploadResponse = 64 * 1024

var (
	errForwardTransfer = errors.New("archived media transfer failed before recipient send")
	errForwardBound    = errors.New("forward media response exceeded bounds")
)

func validMediaDirectPath(raw string) bool {
	if len(raw) < 2 || len(raw) > 4096 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") ||
		strings.ContainsAny(raw, "\\#\r\n\t") {
		return false
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Host != "" || u.Scheme != "" || u.User != nil || u.Opaque != "" ||
		strings.HasPrefix(u.Path, "//") || strings.ContainsAny(u.Path, "\\?#\x00\r\n\t") {
		return false
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validForwardProviderURL(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Host != u.Hostname() || u.Fragment != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return strings.HasSuffix(host, ".whatsapp.net") || strings.HasSuffix(host, ".whatsapp.com")
}

type forwardHTTPKey struct{}

type forwardHTTPBudget struct {
	owner    *WA
	cancel   context.CancelFunc
	method   string
	limit    int64
	maxTries int32
	tries    atomic.Int32
}

// This runs before the normal SDK client can follow a redirect or buffer a
// response. The existing download tool retains its own transport behavior.
func (b *forwardHTTPBudget) roundTrip(base http.RoundTripper, req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	if req.Method != b.method || !validForwardProviderURL(req.URL) || b.tries.Add(1) > b.maxTries {
		b.cancel()
		return nil, context.Canceled
	}
	response, err := base.RoundTrip(req)
	if err != nil || response == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if canceled := req.Context().Err(); canceled != nil {
			return nil, canceled
		}
		return nil, errForwardTransfer
	}
	if (response.StatusCode >= 300 && response.StatusCode < 400) || response.Body == nil {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		b.cancel()
		return nil, context.Canceled
	}
	if response.StatusCode != http.StatusOK {
		return response, nil
	}
	if response.ContentLength > b.limit ||
		(b.method == http.MethodGet && response.ContentLength >= 0 && response.ContentLength != b.limit) {
		_ = response.Body.Close()
		b.cancel()
		return nil, context.Canceled
	}
	if b.method == http.MethodGet {
		response.Body = &forwardBoundedBody{ReadCloser: response.Body, left: b.limit, cancel: b.cancel}
		return response, nil
	}
	// The SDK JSON decoder may stop at the end of the first value. Bound
	// the complete POST response, including chunked and trailing bytes.
	data, err := io.ReadAll(io.LimitReader(response.Body, b.limit+1))
	_ = response.Body.Close()
	if err != nil || int64(len(data)) > b.limit || !json.Valid(data) {
		b.cancel()
		return nil, context.Canceled
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	response.ContentLength = int64(len(data))
	return response, nil
}

type forwardBoundedBody struct {
	io.ReadCloser
	left   int64
	cancel context.CancelFunc
}

func (b *forwardBoundedBody) Read(data []byte) (int, error) {
	if int64(len(data)) > b.left+1 {
		data = data[:b.left+1]
	}
	n, err := b.ReadCloser.Read(data)
	if int64(n) > b.left {
		b.cancel()
		return int(b.left), errForwardBound
	}
	b.left -= int64(n)
	return n, err
}

// Confine the existing cache lookup to three no-follow directory/file opens.
// O_NONBLOCK prevents a cache FIFO from stalling before we can reject it.
func (w *WA) forwardCachedBytes(ctx context.Context, p ForwardMediaArgs) ([]byte, error) {
	root, err := unix.Open(w.dataDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	media, err := unix.Openat(root, "media", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(media)
	chat, err := unix.Openat(media, safeName(p.SourceChatJID), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(chat)
	name := safeName(p.SourceMessageID) + extensionFor(&MessageRow{Mime: p.MIMEType, FileName: p.FileName})
	fd, err := unix.Openat(chat, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "archived media cache")
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size != p.SizeBytes {
		return nil, errForwardTransfer
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(file, p.SizeBytes+1))
}

func validForwardBytes(p ForwardMediaArgs, data []byte) bool {
	if int64(len(data)) != p.SizeBytes || digestPayload(data) != p.SHA256 {
		return false
	}
	m, ok := forwardMIME(p.Kind, p.MIMEType)
	if !ok {
		return false
	}
	switch m {
	case "image/jpeg":
		_, err := jpeg.DecodeConfig(bytes.NewReader(data))
		return err == nil
	case "image/png":
		_, err := png.DecodeConfig(bytes.NewReader(data))
		return err == nil
	case "application/pdf":
		return len(data) >= 13 && oneOf(string(data[:7]), "%PDF-1.", "%PDF-2.") &&
			data[7] >= '0' && data[7] <= '9' && bytes.HasSuffix(bytes.TrimSpace(data), []byte("%%EOF"))
	case "audio/mpeg":
		return hasMP3Frame(data)
	case "audio/mp4":
		return hasMP4Audio(data)
	case "audio/ogg":
		return hasOpusHeader(data)
	default:
		return false
	}
}

func hasMP3Frame(data []byte) bool {
	if len(data) >= 10 && string(data[:3]) == "ID3" {
		tag := data[6:10]
		if (tag[0]|tag[1]|tag[2]|tag[3])&0x80 != 0 {
			return false
		}
		start := 10 + int(tag[0])<<21 + int(tag[1])<<14 + int(tag[2])<<7 + int(tag[3])
		if data[3] == 4 && data[5]&0x10 != 0 {
			start += 10
		}
		if start > len(data) {
			return false
		}
		data = data[start:]
	}
	// Sync, valid version, Layer III, valid bitrate and sample rate.
	return len(data) >= 4 && data[0] == 0xff && data[1]&0xe0 == 0xe0 &&
		data[1]&0x18 != 0x08 && data[1]&0x06 == 0x02 && data[2]&0xf0 != 0xf0 && data[2]&0x0c != 0x0c
}

func hasOpusHeader(data []byte) bool {
	if len(data) < 28 || string(data[:4]) != "OggS" || data[4] != 0 || data[5]&0x02 == 0 || data[26] == 0 || data[27] < 19 {
		return false
	}
	start := 27 + int(data[26])
	return len(data) >= start+19 && string(data[start:start+8]) == "OpusHead"
}

// ISO-BMFF audio shares an ftyp with common video containers. Read the bounded
// boxes and require an audio handler, rejecting any video track rather than
// trusting the MIME label or brand alone.
func hasMP4Audio(data []byte) bool {
	var fileType, audio, video bool
	ok := walkMediaBoxes(data, func(kind string, payload []byte) bool {
		switch kind {
		case "ftyp":
			fileType = len(payload) >= 8
		case "moov":
			return walkMediaBoxes(payload, func(kind string, payload []byte) bool {
				if kind != "trak" {
					return true
				}
				return walkMediaBoxes(payload, func(kind string, payload []byte) bool {
					if kind != "mdia" {
						return true
					}
					return walkMediaBoxes(payload, func(kind string, payload []byte) bool {
						if kind == "hdlr" && len(payload) >= 12 {
							audio = audio || string(payload[8:12]) == "soun"
							video = video || string(payload[8:12]) == "vide"
						}
						return true
					})
				})
			})
		}
		return true
	})
	return ok && fileType && audio && !video
}

func walkMediaBoxes(data []byte, visit func(string, []byte) bool) bool {
	for len(data) >= 8 {
		size, header := uint64(binary.BigEndian.Uint32(data)), 8
		switch size {
		case 0:
			size = uint64(len(data))
		case 1:
			if len(data) < 16 {
				return false
			}
			size, header = binary.BigEndian.Uint64(data[8:16]), 16
		}
		if size < uint64(header) || size > uint64(len(data)) || !visit(string(data[4:8]), data[header:size]) {
			return false
		}
		data = data[size:]
	}
	return len(data) == 0
}

func (w *WA) forwardPlaintext(ctx context.Context, p ForwardMediaArgs, src forwardSource) ([]byte, error) {
	cached, err := w.forwardCachedBytes(ctx, p)
	if err == nil && validForwardBytes(p, cached) {
		return cached, nil
	}
	a := src.attachment
	if ctx.Err() != nil || !validMediaDirectPath(a.GetDirectPath()) ||
		len(a.GetMediaKey()) != 32 || len(a.GetFileEncSHA256()) != sha256.Size {
		return nil, errForwardTransfer
	}
	downloadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	encryptedSize := 16*(p.SizeBytes/16+1) + 10
	budget := &forwardHTTPBudget{owner: w, cancel: cancel, method: http.MethodGet, limit: encryptedSize, maxTries: 4}
	data, err := w.Client.Download(context.WithValue(downloadCtx, forwardHTTPKey{}, budget), a)
	if err != nil || downloadCtx.Err() != nil || !validForwardBytes(p, data) {
		return nil, errForwardTransfer
	}
	return data, nil
}

func (w *WA) uploadForwardMedia(ctx context.Context, p ForwardMediaArgs, src forwardSource) (whatsmeow.UploadResponse, error) {
	data, err := w.forwardPlaintext(ctx, p, src)
	if err != nil || ctx.Err() != nil {
		return whatsmeow.UploadResponse{}, errForwardTransfer
	}
	uploadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	budget := &forwardHTTPBudget{owner: w, cancel: cancel, method: http.MethodPost, limit: maxForwardUploadResponse, maxTries: 1}
	response, err := w.Client.Upload(context.WithValue(uploadCtx, forwardHTTPKey{}, budget), data, whatsmeow.GetMediaType(src.attachment))
	target, urlErr := url.Parse(response.URL)
	if err != nil || uploadCtx.Err() != nil || urlErr != nil || !validForwardProviderURL(target) ||
		!validMediaDirectPath(target.RequestURI()) || !validMediaDirectPath(response.DirectPath) ||
		len(response.MediaKey) != 32 ||
		forwardFingerprint(response.FileEncSHA256) == "" || forwardFingerprint(response.FileSHA256) != p.SHA256 ||
		response.FileLength != uint64(p.SizeBytes) {
		return whatsmeow.UploadResponse{}, errForwardTransfer
	}
	return response, nil
}

func forwardMediaProto(p ForwardMediaArgs, src forwardSource, upload whatsmeow.UploadResponse) *waE2E.Message {
	score := min(src.attachment.GetContextInfo().GetForwardingScore(), 126) + 1
	marker := &waE2E.ContextInfo{IsForwarded: proto.Bool(true), ForwardingScore: proto.Uint32(score)}
	mime, url, path, length := proto.String(p.MIMEType), proto.String(upload.URL), proto.String(upload.DirectPath), proto.Uint64(upload.FileLength)
	switch p.Kind {
	case "image":
		return &waE2E.Message{ImageMessage: &waE2E.ImageMessage{
			Mimetype: mime, Caption: p.Caption, URL: url, DirectPath: path, FileLength: length,
			FileSHA256: upload.FileSHA256, FileEncSHA256: upload.FileEncSHA256, MediaKey: upload.MediaKey, ContextInfo: marker,
		}}
	case "document":
		var name *string
		if p.FileName != "" {
			name = proto.String(p.FileName)
		}
		doc := &waE2E.Message{DocumentMessage: &waE2E.DocumentMessage{
			Mimetype: mime, Caption: p.Caption, FileName: name, Title: name,
			URL: url, DirectPath: path, FileLength: length, FileSHA256: upload.FileSHA256,
			FileEncSHA256: upload.FileEncSHA256, MediaKey: upload.MediaKey, ContextInfo: marker,
		}}
		if p.Caption != nil && *p.Caption != "" {
			return &waE2E.Message{DocumentWithCaptionMessage: &waE2E.FutureProofMessage{Message: doc}}
		}
		return doc
	default:
		return &waE2E.Message{AudioMessage: &waE2E.AudioMessage{
			Mimetype: mime, URL: url, DirectPath: path, FileLength: length, FileSHA256: upload.FileSHA256,
			FileEncSHA256: upload.FileEncSHA256, MediaKey: upload.MediaKey, ContextInfo: marker, PTT: proto.Bool(false),
		}}
	}
}
