package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/importer"
)

func TestSafeZipName(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"conversations.json", "conversations.json", true},
		{"attachments/file-1.png", "attachments/file-1.png", true},
		{"./a/b.png", "a/b.png", true},
		{"a\\b.png", "a/b.png", true},
		{"/etc/passwd", "", false},
		{"../escape.png", "", false},
		{"a/../../escape.png", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := safeZipName(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Fatalf("safeZipName(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestValidateImportCreate(t *testing.T) {
	if err := validateImportCreate(ImportCreateRequest{Source: "bogus", TotalBytes: 10, TotalChunks: 1, ArchiveSHA256: hashOf([]byte("x"))}); err == nil {
		t.Fatal("expected invalid source error")
	}
	if err := validateImportCreate(ImportCreateRequest{Source: "tinfoil", TotalBytes: MaxImportChunkBytes + 1, TotalChunks: 1, ArchiveSHA256: hashOf([]byte("x"))}); err == nil {
		t.Fatal("expected chunk-count mismatch error")
	}
	if err := validateImportCreate(ImportCreateRequest{Source: "tinfoil", TotalBytes: 10, TotalChunks: 1, ArchiveSHA256: strings.Repeat("z", 64)}); err == nil {
		t.Fatal("expected invalid archive hash error")
	}
	if err := validateImportCreate(ImportCreateRequest{Source: "tinfoil", TotalBytes: 10, TotalChunks: 1, ArchiveSHA256: hashOf([]byte("x"))}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestImportJobPlainJSONRoundTrip(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID

	var notified int32
	f.cp.mux.HandleFunc("POST /api/sync/notify-import-complete", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&notified, 1)
		w.WriteHeader(http.StatusNoContent)
	})

	archive := []byte(`[{"uuid":"conv-1","name":"Hello","created_at":"2024-01-01T00:00:00Z","chat_messages":[{"sender":"human","text":"hi there","created_at":"2024-01-01T00:00:00Z"}]}]`)

	job := stageArchive(t, f, "tinfoil", archive)
	job.cek = append([]byte(nil), f.userKey...)

	if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err != nil {
		t.Fatalf("runImportJob: %v", err)
	}

	snap := job.Snapshot()
	if snap.Imported != 1 || snap.Failed != 0 {
		t.Fatalf("imported=%d failed=%d, want 1/0 (errors=%v)", snap.Imported, snap.Failed, snap.Errors)
	}
	if len(f.cp.blobs) != 1 {
		t.Fatalf("expected one chat blob, got %d", len(f.cp.blobs))
	}
	if atomic.LoadInt32(&notified) != 1 {
		t.Fatalf("expected one completion notification, got %d", notified)
	}
}

func TestImportJobSkipsPreReleaseDeterministicChat(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID

	createdAt := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	priorID := priorDeterministicChatID(importer.SourceTinfoil, "conv-1", createdAt)
	plaintext := []byte(`{"id":"` + priorID + `","title":"Previously imported","messages":[]}`)
	if _, err := Push(context.Background(), f.handler.deps, importSession(f), PushRequest{
		Scope: "chat", ID: priorID, Key: f.userKeyB64,
		Plaintext: base64.StdEncoding.EncodeToString(plaintext), IdempotencyKey: "pre-release-import",
	}); err != nil {
		t.Fatalf("seed prior import: %v", err)
	}

	archive := []byte(`[{"uuid":"conv-1","name":"Hello","created_at":"2024-01-01T00:00:00Z","chat_messages":[{"sender":"human","text":"hi there","created_at":"2024-01-01T00:00:00Z"}]}]`)
	job := stageArchive(t, f, "tinfoil", archive)
	job.cek = append([]byte(nil), f.userKey...)

	if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err != nil {
		t.Fatalf("runImportJob: %v", err)
	}

	snap := job.Snapshot()
	if snap.Imported != 0 || snap.Failed != 0 || snap.Counts["chat"].Skipped != 1 {
		t.Fatalf("unexpected prior import result: %+v", snap)
	}
	if len(f.cp.blobs) != 1 {
		t.Fatalf("pre-release import was duplicated: got %d blobs", len(f.cp.blobs))
	}
}

func TestPriorImportedChatProbeRejectsAmbiguousResult(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	f.cp.blobs["chat/prior-id"] = &cpBlob{ETag: 1, KeyID: f.userKeyID, Body: []byte("invalid")}

	exists, err := priorImportedChatExists(context.Background(), f.handler.deps, importSession(f), f.userKeyB64, "prior-id")
	if err == nil || exists {
		t.Fatalf("ambiguous probe result = (%v, %v), want false and error", exists, err)
	}
}

func TestImportJobZipWithImage(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	f.cp.mux.HandleFunc("POST /api/sync/notify-import-complete", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	pngBytes := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x42}, 64)...)
	conversations := []byte(`[{"uuid":"conv-img","name":"Pic","created_at":"2024-02-02T00:00:00Z","chat_messages":[{"sender":"human","text":"look","created_at":"2024-02-02T00:00:00Z","attachments":[{"type":"image","fileName":"file-1.png","mimeType":"image/png","exportPath":"attachments/file-1.png"}]}]}]`)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	writeZipEntry(t, zw, "conversations.json", conversations)
	writeZipEntry(t, zw, "attachments/file-1.png", pngBytes)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	job := stageArchive(t, f, "tinfoil", buf.Bytes())
	job.cek = append([]byte(nil), f.userKey...)

	if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err != nil {
		t.Fatalf("runImportJob: %v", err)
	}

	snap := job.Snapshot()
	if snap.Imported != 1 || snap.Failed != 0 {
		t.Fatalf("imported=%d failed=%d, want 1/0 (errors=%v)", snap.Imported, snap.Failed, snap.Errors)
	}
	if len(f.cp.attachmentIndex) != 1 {
		t.Fatalf("expected one attachment index entry, got %d", len(f.cp.attachmentIndex))
	}
}

func TestImportJobSkipsUnsupportedBinaryDocument(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	f.cp.mux.HandleFunc("POST /api/sync/notify-import-complete", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	pdfBytes := []byte("%PDF-1.7\n")
	conversations := []byte(`[{"id":"conv-doc","title":"Doc","create_time":1706832000,"mapping":{"root":{"id":"root","children":["msg"]},"msg":{"id":"msg","parent":"root","message":{"author":{"role":"user"},"content":{"content_type":"text","parts":["read this"]},"metadata":{"attachments":[{"id":"file-doc","name":"doc.pdf","mime_type":"application/pdf"}]}}}}}]`)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	writeZipEntry(t, zw, "conversations.json", conversations)
	writeZipEntry(t, zw, "file-doc.pdf", pdfBytes)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	job := stageArchive(t, f, "chatgpt", buf.Bytes())
	job.cek = append([]byte(nil), f.userKey...)

	if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err != nil {
		t.Fatalf("runImportJob: %v", err)
	}

	snap := job.Snapshot()
	if snap.Imported != 1 || snap.Failed != 0 {
		t.Fatalf("imported=%d failed=%d, want 1/0 (errors=%v)", snap.Imported, snap.Failed, snap.Errors)
	}
	if len(f.cp.attachmentIndex) != 0 {
		t.Fatalf("expected unsupported binary document to skip attachment upload, got %d", len(f.cp.attachmentIndex))
	}
	if len(snap.Warnings) == 0 {
		t.Fatal("expected warning for skipped binary document")
	}
}

func TestImportJobSkipsUnresolvedTinfoilImages(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	f.cp.mux.HandleFunc("POST /api/sync/notify-import-complete", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	archive := []byte(`[{"uuid":"conv-img-missing","name":"Pic","created_at":"2024-02-02T00:00:00Z","chat_messages":[{"sender":"human","text":"look","created_at":"2024-02-02T00:00:00Z","attachments":[{"id":"img-1","type":"image","fileName":"missing.png","mimeType":"image/png"}]}]}]`)
	job := stageArchive(t, f, "tinfoil", archive)
	job.cek = append([]byte(nil), f.userKey...)

	if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err != nil {
		t.Fatalf("runImportJob: %v", err)
	}

	snap := job.Snapshot()
	if snap.Imported != 1 || snap.Failed != 0 {
		t.Fatalf("imported=%d failed=%d, want 1/0 (errors=%v)", snap.Imported, snap.Failed, snap.Errors)
	}
	if len(f.cp.attachmentIndex) != 0 {
		t.Fatalf("expected unresolved image to skip attachment upload, got %d", len(f.cp.attachmentIndex))
	}
	if len(snap.Warnings) == 0 {
		t.Fatal("expected warning for skipped unresolved image")
	}
}

func TestImportJobSkipsTinfoilDocumentsWithoutContent(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	f.cp.mux.HandleFunc("POST /api/sync/notify-import-complete", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	archive := []byte(`[{"uuid":"conv-doc-empty","name":"Doc","created_at":"2024-02-02T00:00:00Z","chat_messages":[{"sender":"human","text":"read this","created_at":"2024-02-02T00:00:00Z","attachments":[{"id":"doc-1","type":"document","fileName":"missing.pdf"}]}]}]`)
	job := stageArchive(t, f, "tinfoil", archive)
	job.cek = append([]byte(nil), f.userKey...)

	if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err != nil {
		t.Fatalf("runImportJob: %v", err)
	}

	createdAt := time.Date(2024, time.February, 2, 0, 0, 0, 0, time.UTC)
	chatID := deterministicChatID(f.userSub, importer.SourceTinfoil, "conv-doc-empty", createdAt)
	payload := decryptNativeTestBlob(t, f, "chat", chatID)
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"attachments"`) {
		t.Fatalf("payload retained empty document attachment: %s", encoded)
	}
	if len(job.Snapshot().Warnings) == 0 {
		t.Fatal("expected warning for skipped empty document")
	}
}

func tinfoilArchiveWithChats(n int) []byte {
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"uuid":"conv-%d","name":"Chat %d","created_at":"2024-01-01T00:00:%02dZ","chat_messages":[{"sender":"human","text":"hi %d","created_at":"2024-01-01T00:00:00Z"}]}`, i, i, i%60, i)
	}
	sb.WriteString("]")
	return []byte(sb.String())
}

// TestImportJobPushesChatsConcurrently holds every chat write open
// until several are in flight, so a serial loop would deadlock here
// while the pool proceeds.
func TestImportJobPushesChatsConcurrently(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	f.cp.mux.HandleFunc("POST /api/sync/notify-import-complete", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	const chats = 12
	var inFlight, peak atomic.Int32
	release := make(chan struct{})
	var releaseOnce sync.Once
	f.cp.beforePutBlob = func(scope, id string) {
		if scope != "chat" {
			return
		}
		cur := inFlight.Add(1)
		for {
			prev := peak.Load()
			if cur <= prev || peak.CompareAndSwap(prev, cur) {
				break
			}
		}
		if cur >= importChatConcurrency {
			releaseOnce.Do(func() { close(release) })
		}
		f.cp.mu.Unlock()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
			t.Errorf("chat writes never overlapped: peak in-flight %d", peak.Load())
		}
		f.cp.mu.Lock()
		inFlight.Add(-1)
	}

	job := stageArchive(t, f, "tinfoil", tinfoilArchiveWithChats(chats))
	job.cek = append([]byte(nil), f.userKey...)
	if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err != nil {
		t.Fatalf("runImportJob: %v", err)
	}

	snap := job.Snapshot()
	if snap.Imported != chats || snap.Failed != 0 || snap.Total != chats {
		t.Fatalf("imported=%d failed=%d total=%d, want %d/0/%d (errors=%v)", snap.Imported, snap.Failed, snap.Total, chats, chats, snap.Errors)
	}
	if got := peak.Load(); got < importChatConcurrency {
		t.Fatalf("peak concurrent chat writes = %d, want at least %d", got, importChatConcurrency)
	}
	if got := peak.Load(); got > importChatConcurrency {
		t.Fatalf("peak concurrent chat writes = %d exceeds the pool limit %d", got, importChatConcurrency)
	}
	if len(f.cp.blobs) != chats {
		t.Fatalf("expected %d chat blobs, got %d", chats, len(f.cp.blobs))
	}
}

// TestImportJobWorkerFailureStopsRemainingChats pins that a definitive
// error on one worker aborts the job rather than being tallied as a
// per-chat failure while the rest of the archive keeps importing.
func TestImportJobWorkerFailureStopsRemainingChats(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	notified := captureImportNotifications(t, f)

	const chats = 40
	const failAt = 2
	createdAt := time.Date(2024, time.January, 1, 0, 0, failAt, 0, time.UTC)
	priorID := priorDeterministicChatID(importer.SourceTinfoil, fmt.Sprintf("conv-%d", failAt), createdAt)
	f.cp.getBlobFailures["chat/"+priorID] = []int{http.StatusForbidden}

	job := stageArchive(t, f, "tinfoil", tinfoilArchiveWithChats(chats))
	coord := NewImportCoordinator()
	snap := runCoordinatorJob(t, f, coord, job)

	if snap.Status != ImportJobFailed || snap.FailureReason != ImportFailureAuthorization {
		t.Fatalf("status=%s reason=%q, want failed/authorization_failed (errors=%v)", snap.Status, snap.FailureReason, snap.Errors)
	}
	if snap.Imported+snap.Failed >= chats {
		t.Fatalf("job processed every chat (%d imported, %d failed) after a definitive failure", snap.Imported, snap.Failed)
	}
	if body := notified.single(t); body["failureReason"] != string(ImportFailureAuthorization) {
		t.Fatalf("unexpected failure notification: %v", body)
	}
}

func TestImportJobEnforcesMessageLimit(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID

	archive := []byte(`[{"uuid":"conv-many","name":"Many","created_at":"2024-01-01T00:00:00Z","chat_messages":[{"sender":"human","text":"hi","created_at":"2024-01-01T00:00:00Z"}]}]`)
	job := stageArchive(t, f, "tinfoil", archive)
	job.cek = append([]byte(nil), f.userKey...)

	old := maxImportMessages
	maxImportMessages = 0
	t.Cleanup(func() { maxImportMessages = old })

	err := runImportJob(context.Background(), f.handler.deps, importSession(f), job)
	if err == nil {
		t.Fatal("expected message-limit error")
	}
	if got := classifyImportFailure(context.Background(), err); got != ImportFailureLimitExceeded {
		t.Fatalf("message limit classified as %q, want %q", got, ImportFailureLimitExceeded)
	}
}

func TestImportJobRejectsHashMismatch(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID

	archive := []byte(`[{"uuid":"c","name":"n","created_at":"2024-01-01T00:00:00Z","chat_messages":[{"sender":"human","text":"hi","created_at":"2024-01-01T00:00:00Z"}]}]`)
	job := stageArchive(t, f, "tinfoil", archive)
	job.ArchiveSHA256 = hashOf([]byte("different"))
	job.cek = append([]byte(nil), f.userKey...)

	err := runImportJob(context.Background(), f.handler.deps, importSession(f), job)
	if err == nil {
		t.Fatal("expected hash-mismatch error")
	}
	if got := classifyImportFailure(context.Background(), err); got != ImportFailureInvalidArchive {
		t.Fatalf("hash mismatch classified as %q, want %q", got, ImportFailureInvalidArchive)
	}
}

// importNotifyCapture records every callback the enclave makes to the
// controlplane's import notification endpoint.
type importNotifyCapture struct {
	mu    sync.Mutex
	calls []map[string]any
}

func captureImportNotifications(t *testing.T, f *fixture) *importNotifyCapture {
	t.Helper()
	cap := &importNotifyCapture{}
	f.cp.mux.HandleFunc("POST /api/sync/notify-import-complete", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode notify body: %v", err)
		}
		cap.mu.Lock()
		cap.calls = append(cap.calls, body)
		cap.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	return cap
}

func (c *importNotifyCapture) single(t *testing.T) map[string]any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.calls) != 1 {
		t.Fatalf("expected exactly one notification, got %d: %v", len(c.calls), c.calls)
	}
	return c.calls[0]
}

// runCoordinatorJob drives a staged job through the coordinator the way
// the start handler does and waits for the detached goroutine to end.
func runCoordinatorJob(t *testing.T, f *fixture, coord *ImportCoordinator, job *ImportJobState) ImportJobSnapshot {
	t.Helper()
	coord.jobs[job.UserID] = job
	if !coord.Start(context.Background(), f.handler.deps, importSession(f), job, append([]byte(nil), f.userKey...)) {
		t.Fatal("start returned false")
	}
	select {
	case <-job.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("job did not finish")
	}
	return job.Snapshot()
}

func TestImportJobFailureNotifiesControlplaneWithReason(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	notified := captureImportNotifications(t, f)

	job := stageArchive(t, f, "claude", []byte(`{"not":"an array"`))
	coord := NewImportCoordinator()
	snap := runCoordinatorJob(t, f, coord, job)

	if snap.Status != ImportJobFailed {
		t.Fatalf("status=%s, want failed", snap.Status)
	}
	if snap.FailureReason != ImportFailureInvalidArchive {
		t.Fatalf("failure_reason=%q, want %q", snap.FailureReason, ImportFailureInvalidArchive)
	}
	if len(snap.Errors) != 1 || snap.Errors[0] != importFailureMessage(ImportFailureInvalidArchive) {
		t.Fatalf("errors=%v, want the invalid-archive message", snap.Errors)
	}
	body := notified.single(t)
	if body["status"] != "failed" || body["failureReason"] != string(ImportFailureInvalidArchive) {
		t.Fatalf("unexpected failure notification: %v", body)
	}
}

// TestImportJobStallReportsTimeout pins the watchdog contract: a job
// that keeps recording progress outlives the stall timeout many times
// over, and is only canceled once it stops moving.
func TestImportJobStallReportsTimeout(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	notified := captureImportNotifications(t, f)

	archive := []byte(`[{"uuid":"c","name":"n","created_at":"2024-01-01T00:00:00Z","chat_messages":[{"sender":"human","text":"hi","created_at":"2024-01-01T00:00:00Z"}]}]`)
	job := stageArchive(t, f, "tinfoil", archive)
	coord := NewImportCoordinator()
	coord.stallTimeout = 50 * time.Millisecond
	const progressSteps = 8
	coord.runner = func(ctx context.Context, deps Deps, sess Session, job *ImportJobState) error {
		for i := 1; i <= progressSteps; i++ {
			time.Sleep(coord.stallTimeout / 2)
			if ctx.Err() != nil {
				return fmt.Errorf("import: canceled while progressing at step %d: %w", i, ctx.Err())
			}
			job.setProgress(i, 0, progressSteps)
		}
		<-ctx.Done()
		return fmt.Errorf("import: push chat: %w", ctx.Err())
	}
	snap := runCoordinatorJob(t, f, coord, job)

	if snap.Status != ImportJobFailed || snap.FailureReason != ImportFailureTimeout {
		t.Fatalf("status=%s reason=%q, want failed/timeout", snap.Status, snap.FailureReason)
	}
	if snap.Imported != progressSteps {
		t.Fatalf("imported=%d, want %d: the watchdog interrupted a job that was still making progress", snap.Imported, progressSteps)
	}
	body := notified.single(t)
	if body["failureReason"] != string(ImportFailureTimeout) || body["importedCount"] != float64(progressSteps) {
		t.Fatalf("unexpected timeout notification: %v", body)
	}
}

func TestImportJobPanicIsContainedAndReported(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	notified := captureImportNotifications(t, f)

	archive := []byte(`[]`)
	job := stageArchive(t, f, "tinfoil", archive)
	coord := NewImportCoordinator()
	coord.runner = func(context.Context, Deps, Session, *ImportJobState) error {
		panic("malformed export")
	}
	snap := runCoordinatorJob(t, f, coord, job)

	if snap.Status != ImportJobFailed || snap.FailureReason != ImportFailureWorker {
		t.Fatalf("status=%s reason=%q, want failed/worker_failed", snap.Status, snap.FailureReason)
	}
	if body := notified.single(t); body["failureReason"] != string(ImportFailureWorker) {
		t.Fatalf("unexpected panic notification: %v", body)
	}
}

func TestImportJobStaleKeyReportsKeyMismatch(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = "someone-elses-key"
	notified := captureImportNotifications(t, f)

	archive := []byte(`[]`)
	job := stageArchive(t, f, "tinfoil", archive)
	coord := NewImportCoordinator()
	snap := runCoordinatorJob(t, f, coord, job)

	if snap.Status != ImportJobFailed || snap.FailureReason != ImportFailureKeyMismatch {
		t.Fatalf("status=%s reason=%q errors=%v, want failed/key_mismatch", snap.Status, snap.FailureReason, snap.Errors)
	}
	if body := notified.single(t); body["failureReason"] != string(ImportFailureKeyMismatch) {
		t.Fatalf("unexpected key notification: %v", body)
	}
}

func TestStageImportChunkDoesNotRecordFailedPut(t *testing.T) {
	f := newFixture(t)
	coord := NewImportCoordinator()
	archive := []byte(`[{"uuid":"c","name":"n","created_at":"2024-01-01T00:00:00Z","chat_messages":[{"sender":"human","text":"hi","created_at":"2024-01-01T00:00:00Z"}]}]`)
	job, err := coord.Create(f.userSub, ImportCreateRequest{
		Source:        "tinfoil",
		TotalBytes:    int64(len(archive)),
		TotalChunks:   1,
		ArchiveSHA256: hashOf(archive),
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}

	deps := f.handler.deps
	deps.Buckets = nil
	err = stageImportChunk(context.Background(), deps, f.userSub, job, ImportUploadRequest{
		UploadID:    job.UploadID,
		ChunkIndex:  0,
		ChunkSHA256: hashOf(archive),
		Data:        base64.StdEncoding.EncodeToString(archive),
	})
	if err == nil {
		t.Fatal("expected staging failure")
	}
	if job.allChunksReceived() {
		t.Fatal("failed bucket write should not mark chunk received")
	}

	if err := stageImportChunk(context.Background(), f.handler.deps, f.userSub, job, ImportUploadRequest{
		UploadID:    job.UploadID,
		ChunkIndex:  0,
		ChunkSHA256: hashOf(archive),
		Data:        base64.StdEncoding.EncodeToString(archive),
	}); err != nil {
		t.Fatalf("retry stage chunk: %v", err)
	}
	if !job.allChunksReceived() {
		t.Fatal("successful retry should mark chunk received")
	}
}

func TestImportStagingCleanupExpiresStaleJobs(t *testing.T) {
	f := newFixture(t)
	// Keep the retention long while creating and uploading so the reaper
	// scheduled by create cannot race the upload request; the reap itself
	// is invoked directly below to make the test deterministic.
	f.handler.importCoordinator.stagingRetention = time.Hour
	tok := f.jwt()
	archive := []byte(`[{"uuid":"c","name":"n","created_at":"2024-01-01T00:00:00Z","chat_messages":[{"sender":"human","text":"hi","created_at":"2024-01-01T00:00:00Z"}]}]`)

	resp, body := f.post("/v1/import/create", ImportCreateRequest{
		Source:        "tinfoil",
		TotalBytes:    int64(len(archive)),
		TotalChunks:   1,
		ArchiveSHA256: hashOf(archive),
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var createResp ImportCreateResponse
	if err := json.Unmarshal(body, &createResp); err != nil {
		t.Fatal(err)
	}
	resp, body = f.post("/v1/import/upload", ImportUploadRequest{
		UploadID:    createResp.UploadID,
		ChunkIndex:  0,
		ChunkSHA256: hashOf(archive),
		Data:        base64.StdEncoding.EncodeToString(archive),
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload: %d %s", resp.StatusCode, body)
	}

	job := f.handler.importCoordinator.Get(f.userSub)
	if job == nil {
		t.Fatal("expected staging job to exist after upload")
	}
	f.handler.importCoordinator.stagingRetention = 0
	f.handler.importCoordinator.reapStaleStaging(context.Background(), f.handler.deps, job)

	token := importChunkToken(createResp.UploadID, 0)
	if f.handler.importCoordinator.Get(f.userSub) != nil {
		t.Fatal("expected stale staging job to be reaped")
	}
	if f.bk.has(token) {
		t.Fatal("expected stale staged chunk to be deleted")
	}
}

func TestImportStagingCleanupLeavesRunningJobs(t *testing.T) {
	c := NewImportCoordinator()
	job := &ImportJobState{
		ID:        "job",
		UserID:    "user",
		UploadID:  "upload",
		status:    ImportJobRunning,
		updatedAt: time.Now().Add(-time.Hour),
		done:      make(chan struct{}),
	}
	c.jobs[job.UserID] = job

	c.reapStaleStaging(context.Background(), Deps{}, job)

	if c.Get(job.UserID) != job {
		t.Fatal("running job should remain addressable")
	}
	if got := job.Snapshot().Status; got != ImportJobRunning {
		t.Fatalf("expected running job to stay running, got %s", got)
	}
	select {
	case <-job.Done():
		t.Fatal("running job should not be marked done")
	default:
	}
}

func TestImportStatusRequiresMatchingJobID(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	archive := []byte(`[{"uuid":"c","name":"n","created_at":"2024-01-01T00:00:00Z","chat_messages":[{"sender":"human","text":"hi","created_at":"2024-01-01T00:00:00Z"}]}]`)

	resp, body := f.post("/v1/import/create", ImportCreateRequest{
		Source:        "tinfoil",
		TotalBytes:    int64(len(archive)),
		TotalChunks:   1,
		ArchiveSHA256: hashOf(archive),
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	resp, _ = f.post("/v1/import/status", ImportStatusRequest{JobID: "wrong"}, tok)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for wrong job id, got %d", resp.StatusCode)
	}
}

func stageArchive(t *testing.T, f *fixture, source string, archive []byte) *ImportJobState {
	t.Helper()
	coord := NewImportCoordinator()
	job, err := coord.Create(f.userSub, ImportCreateRequest{
		Source:        source,
		TotalBytes:    int64(len(archive)),
		TotalChunks:   1,
		ArchiveSHA256: hashOf(archive),
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	err = stageImportChunk(context.Background(), f.handler.deps, f.userSub, job, ImportUploadRequest{
		UploadID:    job.UploadID,
		ChunkIndex:  0,
		ChunkSHA256: hashOf(archive),
		Data:        base64.StdEncoding.EncodeToString(archive),
	})
	if err != nil {
		t.Fatalf("stage chunk: %v", err)
	}
	return job
}

func importSession(f *fixture) Session {
	return Session{Claims: auth.Claims{Subject: f.userSub}}
}

func writeZipEntry(t *testing.T, zw *zip.Writer, name string, data []byte) {
	t.Helper()
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
