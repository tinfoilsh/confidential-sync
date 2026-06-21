package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
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

func TestImportJobRetriesCompletionNotification(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID

	oldDelay := importNotifyRetryDelay
	importNotifyRetryDelay = 0
	t.Cleanup(func() { importNotifyRetryDelay = oldDelay })

	var attempts int32
	f.cp.mux.HandleFunc("POST /api/sync/notify-import-complete", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < importNotifyAttempts {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	archive := []byte(`[{"uuid":"conv-1","name":"Hello","created_at":"2024-01-01T00:00:00Z","chat_messages":[{"sender":"human","text":"hi there","created_at":"2024-01-01T00:00:00Z"}]}]`)

	job := stageArchive(t, f, "tinfoil", archive)
	job.cek = append([]byte(nil), f.userKey...)

	if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err != nil {
		t.Fatalf("runImportJob: %v", err)
	}
	if atomic.LoadInt32(&attempts) != importNotifyAttempts {
		t.Fatalf("expected %d notification attempts, got %d", importNotifyAttempts, attempts)
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
	if len(snap.Errors) == 0 {
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
	if len(snap.Errors) == 0 {
		t.Fatal("expected warning for skipped unresolved image")
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

	if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err == nil {
		t.Fatal("expected message-limit error")
	}
}

func TestImportJobRejectsHashMismatch(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID

	archive := []byte(`[{"uuid":"c","name":"n","created_at":"2024-01-01T00:00:00Z","chat_messages":[{"sender":"human","text":"hi","created_at":"2024-01-01T00:00:00Z"}]}]`)
	job := stageArchive(t, f, "tinfoil", archive)
	job.ArchiveSHA256 = hashOf([]byte("different"))
	job.cek = append([]byte(nil), f.userKey...)

	if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err == nil {
		t.Fatal("expected hash-mismatch error")
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
	f.handler.importCoordinator.stagingRetention = time.Millisecond
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

	token := importChunkToken(createResp.UploadID, 0)
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && f.handler.importCoordinator.Get(f.userSub) != nil {
		time.Sleep(5 * time.Millisecond)
	}
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
